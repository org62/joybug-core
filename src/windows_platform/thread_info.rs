//! Quiet, bounded thread-name handling and per-listing Windows metadata.
use super::{DebuggedProcess, HandleSafe, utils::NtQueryInformationThread};
use crate::interfaces::{Architecture, PlatformError};
use crate::protocol::ThreadInfo;
use windows_sys::Win32::Foundation::{HANDLE, LocalFree, FILETIME};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;

pub(super) const LEGACY_NAME_EXCEPTION: u32 = 0x406D1388;

/// Scalar reads deliberately bypass the allocating/logging general memory path.
fn read_exact(handle: HANDLE, address: u64, bytes: &mut [u8]) -> bool {
    let Ok(address) = usize::try_from(address) else { return false };
    let mut read = 0;
    unsafe { ReadProcessMemory(handle, address as *const _, bytes.as_mut_ptr().cast(), bytes.len(), &mut read) != 0 && read == bytes.len() }
}

fn legacy_fields(arch: Architecture, slots: &[usize]) -> Option<(u64, u32)> {
    let (kind, name, tid, flags) = match (arch, slots) {
        (Architecture::X86, [kind, name, tid, flags]) => (*kind as u32, *name as u32 as u64, *tid as u32, *flags as u32),
        (_, [kind, name, packed]) if arch != Architecture::X86 => (*kind as u32, *name as u64, *packed as u32, (*packed as u64 >> 32) as u32),
        (_, [kind, name, tid, flags]) => (*kind as u32, *name as u64, *tid as u32, *flags as u32),
        _ => return None,
    };
    (kind == 0x1000 && flags == 0 && name != 0).then_some((name, tid))
}

fn read_legacy_name(handle: HANDLE, address: u64) -> Option<String> {
    // Keep the binding local: the rest of Globalization is not needed here.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MultiByteToWideChar(code_page: u32, flags: u32, input: *const u8, input_len: i32, output: *mut u16, output_len: i32) -> i32;
    }
    const CP_ACP: u32 = 0;
    let mut bytes = Vec::new();
    let mut chunk = [0; 64];
    while bytes.len() < 4096 {
        let cursor = address.checked_add(bytes.len() as u64)?;
        let len = 64.min(4096 - bytes.len()).min(4096 - (cursor as usize & 4095));
        if !read_exact(handle, cursor, &mut chunk[..len]) { return None; }
        if let Some(end) = chunk[..len].iter().position(|&b| b == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            let bytes = match String::from_utf8(bytes) {
                Ok(text) => return Some(text),
                Err(error) => error.into_bytes(),
            };
            let count = unsafe { MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), bytes.len() as i32, std::ptr::null_mut(), 0) };
            if count <= 0 { return None; }
            let mut wide = vec![0; count as usize];
            if unsafe { MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), bytes.len() as i32, wide.as_mut_ptr(), count) } != count { return None; }
            return Some(String::from_utf16_lossy(&wide));
        }
        bytes.extend_from_slice(&chunk[..len]);
    }
    None
}

/// False leaves *all* ordinary exception handling intact. A recognized notification
/// for an absent thread is consumed without touching its untrusted pointer.
pub(super) fn legacy_notification(process: &mut DebuggedProcess, event_tid: u32, slots: &[usize]) -> bool {
    let Some((address, tid)) = legacy_fields(process.architecture(), slots) else { return false };
    let tid = if tid == u32::MAX { event_tid } else { tid };
    if process.thread_manager().live_info(tid).is_none() { return true; }
    let Some(name) = read_legacy_name(process.handle(), address) else { return false };
    process.thread_manager_mut().set_name(tid, (!name.is_empty()).then_some(name));
    true
}

fn query<T: Copy>(handle: HANDLE, class: u32) -> Option<T> {
    let mut value: T = unsafe { std::mem::zeroed() };
    let mut returned = 0;
    let status = unsafe { NtQueryInformationThread(handle, class, (&mut value as *mut T).cast(), std::mem::size_of::<T>() as u32, &mut returned) };
    (status >= 0 && returned as usize == std::mem::size_of::<T>()).then_some(value)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ThreadBasicInformation {
    exit_status: i32,
    teb: usize,
    client_id: [usize; 2],
    affinity: usize,
    priority: i32,
    base_priority: i32,
}

#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: Architecture = Architecture::X64;
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: Architecture = Architecture::Arm64;

fn scalar<const N: usize>(process: HANDLE, address: u64) -> Option<[u8; N]> {
    let mut bytes = [0; N];
    read_exact(process, address, &mut bytes).then_some(bytes)
}

fn teb_layout(process: HANDLE, thread: HANDLE, arch: Architecture, entry: u64) -> Option<(u64, Architecture)> {
    let native = query::<ThreadBasicInformation>(thread, 0)?.teb as u64;
    if native == 0 { return None; }
    if arch != Architecture::X86 || entry > u32::MAX as u64 {
        return Some((native, NATIVE_ARCH));
    }
    let offset = i32::from_le_bytes(scalar(process, native.checked_add(0x180C)?)?);
    if offset == 0 { return None; }
    let guest = native.checked_add_signed(offset as i64)?;
    if guest == 0 || guest > u32::MAX as u64 { return None; }
    let self_address = u32::from_le_bytes(scalar(process, guest.checked_add(0x18)?)?) as u64;
    (self_address == guest).then_some((guest, Architecture::X86))
}

fn modern_name(thread: HANDLE) -> Option<String> {
    use windows_sys::Win32::System::Threading::GetThreadDescription;
    struct Description(*mut u16);
    impl Drop for Description {
        fn drop(&mut self) {
            if !self.0.is_null() { unsafe { LocalFree(self.0.cast()); } }
        }
    }
    let mut value = Description(std::ptr::null_mut());
    let status = unsafe { GetThreadDescription(thread, &mut value.0) };
    if status < 0 || value.0.is_null() { return None; }
    let mut len = 0;
    unsafe {
        while *value.0.add(len) != 0 { len += 1; }
        (len != 0).then(|| String::from_utf16_lossy(std::slice::from_raw_parts(value.0, len)))
    }
}

fn filetime(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

/// One bounded, aligned system snapshot; only scalar scheduling fields escape.
fn scheduling(pid: u32) -> Option<std::collections::HashMap<u32, (u32, Option<u32>)>> {
    use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
    use windows_sys::Win32::System::WindowsProgramming::{SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION};
    const CAP: usize = 64 * 1024 * 1024;
    let mut size = 64 * 1024usize;
    let (buffer, returned) = loop {
        let mut buffer = vec![0u64; size / 8];
        let mut returned = 0;
        let status = unsafe { NtQuerySystemInformation(5, buffer.as_mut_ptr().cast(), size as u32, &mut returned) };
        if status >= 0 {
            if returned as usize > size || (returned as usize) < std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>() { return None; }
            break (buffer, returned as usize);
        }
        if !matches!(status as u32, 0xC0000004 | 0xC0000023 | 0x80000005) { return None; }
        // Allocate a fresh buffer: failed contents have no value.
        size = size.checked_mul(2)?.max(returned as usize).checked_add(7)? & !7;
        if size > CAP { return None; }
    };
    let header_size = std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>();
    let thread_size = std::mem::size_of::<SYSTEM_THREAD_INFORMATION>();
    let mut offset = 0usize;
    let mut result = std::collections::HashMap::new();
    loop {
        if offset.checked_add(header_size)? > returned || offset % 8 != 0 { return None; }
        let header = unsafe { buffer.as_ptr().cast::<u8>().add(offset).cast::<SYSTEM_PROCESS_INFORMATION>() };
        // Bounds and alignment above establish the header, but only the needed
        // scalar fields are read; embedded strings/pointers are never copied.
        let next = unsafe { std::ptr::addr_of!((*header).NextEntryOffset).read() } as usize;
        let thread_count = unsafe { std::ptr::addr_of!((*header).NumberOfThreads).read() } as usize;
        let process_id = unsafe { std::ptr::addr_of!((*header).UniqueProcessId).read() } as usize;
        let end = if next == 0 { returned } else {
            if next < header_size || next % 8 != 0 { return None; }
            let end = offset.checked_add(next)?;
            if end.checked_add(header_size)? > returned { return None; }
            end
        };
        let start = offset.checked_add(header_size)?;
        let bytes = thread_count.checked_mul(thread_size)?;
        if start.checked_add(bytes)? > end || start % std::mem::align_of::<SYSTEM_THREAD_INFORMATION>() != 0 { return None; }
        if process_id == pid as usize {
            result.reserve(thread_count);
            for index in 0..thread_count {
                let thread = unsafe { buffer.as_ptr().cast::<u8>().add(start + index * thread_size).cast::<SYSTEM_THREAD_INFORMATION>() };
                let tid = u32::try_from(unsafe { std::ptr::addr_of!((*thread).ClientId.UniqueThread).read() } as usize).ok()?;
                let state = unsafe { std::ptr::addr_of!((*thread).ThreadState).read() };
                let reason = unsafe { std::ptr::addr_of!((*thread).WaitReason).read() };
                result.insert(tid, (state, (state == 5).then_some(reason)));
            }
            return Some(result);
        }
        if next == 0 { return Some(result); }
        offset = end;
    }
}

fn open_thread(pid: u32, tid: u32) -> Option<HandleSafe> {
    use windows_sys::Win32::System::Threading::{OpenThread, GetProcessIdOfThread, THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION, THREAD_GET_CONTEXT};
    for access in [THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION] {
        let handle = HandleSafe(unsafe { OpenThread(access, 0, tid) });
        if !handle.0.is_null() && unsafe { GetProcessIdOfThread(handle.0) } == pid { return Some(handle); }
    }
    None
}

fn enrich(info: &ThreadInfo, thread: HANDLE, process: HANDLE, arch: Option<Architecture>, schedule: Option<&(u32, Option<u32>)>) -> ThreadInfo {
    use windows_sys::Win32::System::Threading::{GetThreadPriority, GetThreadTimes};
    use windows_sys::Win32::System::WindowsProgramming::{QueryThreadCycleTime, THREAD_PRIORITY_ERROR_RETURN};
    let mut row = ThreadInfo { tid: info.tid, start_address: info.start_address, ..Default::default() };
    if row.start_address == 0 { row.start_address = query::<usize>(thread, 9).unwrap_or(0) as u64; }
    row.name = modern_name(thread).or_else(|| info.name.clone());
    row.suspend_count = super::thread_control::queried_suspend_count_handle(thread);
    let layout = arch.and_then(|arch| teb_layout(process, thread, arch, row.start_address));
    if let Some((teb, architecture)) = layout {
        row.teb_address = Some(teb);
        row.teb_architecture = Some(architecture);
        row.last_error = teb.checked_add(if architecture == Architecture::X86 { 0x34 } else { 0x68 })
            .and_then(|address| scalar(process, address)).map(u32::from_le_bytes);
    }
    let context_arch = arch.map(|arch| {
        if arch == Architecture::X86 && row.start_address > u32::MAX as u64 { NATIVE_ARCH } else { arch }
    });
    if row.suspend_count.is_some_and(|count| count > 0) {
        if let Some(architecture) = context_arch {
            row.instruction_pointer = super::thread_context::sample_instruction_pointer(thread, architecture);
            row.instruction_pointer_architecture = row.instruction_pointer.map(|_| architecture);
        }
    }
    let priority = unsafe { GetThreadPriority(thread) };
    row.priority = (priority != THREAD_PRIORITY_ERROR_RETURN as i32).then_some(priority);
    let mut creation = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    if unsafe { GetThreadTimes(thread, &mut creation, &mut exit, &mut kernel, &mut user) } != 0 {
        row.creation_time_filetime_100ns = Some(filetime(creation));
        row.kernel_time_100ns = Some(filetime(kernel));
        row.user_time_100ns = Some(filetime(user));
    }
    let mut cycles = 0;
    if unsafe { QueryThreadCycleTime(thread, &mut cycles) } != 0 { row.cpu_cycles = Some(cycles); }
    if let Some(&(state, reason)) = schedule { row.thread_state = Some(state); row.wait_reason = reason; }
    row
}

pub(super) fn list_threads(platform: &super::WindowsPlatform, pid: u32) -> Result<Vec<ThreadInfo>, PlatformError> {
    let schedule = scheduling(pid);
    let schedule_of = |tid: u32| schedule.as_ref().and_then(|values| values.get(&tid));
    if let Ok(process) = platform.get_process(pid) {
        return Ok(process.thread_manager().iter_live_info().map(|(info, handle)| {
            enrich(info, handle.0, process.handle(), Some(process.architecture()), schedule_of(info.tid))
        }).collect());
    }
    use windows_sys::Win32::System::Threading::{OpenProcess, IsWow64Process2, PROCESS_VM_READ, PROCESS_QUERY_LIMITED_INFORMATION};
    let process = HandleSafe(unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
    let process = if process.0.is_null() {
        HandleSafe(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })
    } else { process };
    let mut machine = 0;
    let mut native = 0;
    let arch = if !process.0.is_null() && unsafe { IsWow64Process2(process.0, &mut machine, &mut native) } != 0 {
        match machine {
            0x14c => Some(Architecture::X86),
            0 => match native { 0x8664 => Some(Architecture::X64), 0xaa64 => Some(Architecture::Arm64), _ => None },
            _ => None,
        }
    } else { None };
    Ok(super::utils::list_threads_toolhelp(pid)?.into_iter().map(|info| {
        if let Some(handle) = open_thread(pid, info.tid) {
            enrich(&info, handle.0, process.0, arch, schedule_of(info.tid))
        } else {
            let mut row = ThreadInfo { tid: info.tid, start_address: info.start_address, ..Default::default() };
            if let Some(&(state, reason)) = schedule_of(info.tid) { row.thread_state = Some(state); row.wait_reason = reason; }
            row
        }
    }).collect())
}
