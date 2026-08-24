//! The Handles window: kernel handles, windows, TCP connections and token
//! privileges of a debuggee, plus the three mutations the window offers
//! (close handle, toggle privilege, enable/disable window).
//!
//! Handle enumeration uses `NtQueryInformationProcess(ProcessHandleInformation)`
//! — only the target's table, not the system-wide `SystemHandleInformation`
//! walk x64dbg does, which also truncates pids/handles to 16 bits. Names come
//! from `NtQueryObject(ObjectNameInformation)` on a duplicate of the handle.
//! That call blocks forever on a synchronous named pipe with a pending read
//! (the classic `0x0012019F` pipe), so every name query runs on a worker
//! thread with a deadline; on timeout the worker (and the duplicated handle it
//! owns) is abandoned and a fresh one takes over for the remaining handles.

use std::ffi::c_void;
use std::collections::HashMap;
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::Duration;

use tracing::{debug, warn};
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS,
    ERROR_INSUFFICIENT_BUFFER, HANDLE, HWND, LUID, RECT,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetTcp6Table2, GetTcpTable2, MIB_TCP6TABLE2, MIB_TCPTABLE2, MIB_TCP_STATE_CLOSED,
    MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSING, MIB_TCP_STATE_DELETE_TCB,
    MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1, MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK,
    MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_RCVD, MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeNameW, LookupPrivilegeValueW,
    TokenPrivileges, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, GetProcessIdOfThread, GetThreadId, OpenProcess,
    OpenProcessToken, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, IsWindowEnabled};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, EnumWindows, GetClassLongPtrA, GetClassLongPtrW, GetClassNameW,
    GetDesktopWindow, GetParent, GetWindowLongW, GetWindowRect, GetWindowTextW,
    GetWindowThreadProcessId, IsWindowUnicode, GCLP_WNDPROC, GWL_EXSTYLE,
    GWL_STYLE,
};

use crate::interfaces::PlatformError;
use crate::protocol::{
    HandleInfo, PrivilegeInfo, PrivilegeState, ProcessObjects, TcpConnectionInfo, WindowInfo,
};

use super::utils::{error_message, NtQueryInformationProcess, NtQueryObject};
use super::HandleSafe;

// ---------------------------------------------------------------------------
// ntdll
// ---------------------------------------------------------------------------

const STATUS_SUCCESS: i32 = 0;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;

/// `PROCESS_INFORMATION_CLASS::ProcessHandleInformation` (Windows 8+).
const PROCESS_HANDLE_INFORMATION: u32 = 51;
const OBJECT_NAME_INFORMATION: u32 = 1;
const OBJECT_TYPE_INFORMATION: u32 = 2;
const OBJECT_TYPES_INFORMATION: u32 = 3;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct ProcessHandleTableEntryInfo {
    handle_value: HANDLE,
    handle_count: usize,
    pointer_count: usize,
    granted_access: u32,
    object_type_index: u32,
    handle_attributes: u32,
    reserved: u32,
}

#[repr(C)]
struct ProcessHandleSnapshotInformation {
    number_of_handles: usize,
    reserved: usize,
    handles: [ProcessHandleTableEntryInfo; 1],
}

#[repr(C)]
struct GenericMapping {
    generic_read: u32,
    generic_write: u32,
    generic_execute: u32,
    generic_all: u32,
}

/// `OBJECT_TYPE_INFORMATION` as returned by `ObjectTypeInformation` /
/// `ObjectTypesInformation`. The name buffer follows the fixed part; in the
/// `ObjectTypesInformation` array each entry is followed by its name padded to
/// pointer alignment.
#[repr(C)]
struct ObjectTypeInformation {
    type_name: UnicodeString,
    total_number_of_objects: u32,
    total_number_of_handles: u32,
    total_paged_pool_usage: u32,
    total_non_paged_pool_usage: u32,
    total_name_pool_usage: u32,
    total_handle_table_usage: u32,
    high_water_number_of_objects: u32,
    high_water_number_of_handles: u32,
    high_water_paged_pool_usage: u32,
    high_water_non_paged_pool_usage: u32,
    high_water_name_pool_usage: u32,
    high_water_handle_table_usage: u32,
    invalid_attributes: u32,
    generic_mapping: GenericMapping,
    valid_access_mask: u32,
    security_required: u8,
    maintain_handle_count: u8,
    type_index: u8,
    reserved_byte: i8,
    pool_type: u32,
    default_paged_pool_charge: u32,
    default_non_paged_pool_charge: u32,
}

#[repr(C)]
struct ObjectTypesInformation {
    number_of_types: u32,
    // padded to pointer alignment, then ObjectTypeInformation entries
}

fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

unsafe fn unicode_to_string(s: &UnicodeString) -> String { unsafe {
        if s.buffer.is_null() || s.length == 0 {
            return String::new();
        }
        let slice = std::slice::from_raw_parts(s.buffer, (s.length / 2) as usize);
        String::from_utf16_lossy(slice)
    }
}

/// Call an `Nt*` query that reports the needed size via `STATUS_INFO_LENGTH_MISMATCH`,
/// growing the buffer until it fits. Returns the raw bytes.
fn query_growing(mut call: impl FnMut(*mut c_void, u32, &mut u32) -> i32) -> Result<Vec<u8>, i32> {
    // Starts small: this runs once per handle for the name query, and the
    // answer is almost always well under a page. The grow loop covers the rest.
    let mut buf: Vec<u8> = vec![0; 4096];
    loop {
        let mut needed = 0u32;
        let status = call(buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut needed);
        match status {
            STATUS_SUCCESS => return Ok(buf),
            STATUS_INFO_LENGTH_MISMATCH | STATUS_BUFFER_OVERFLOW | STATUS_BUFFER_TOO_SMALL => {
                let next = if needed as usize > buf.len() { needed as usize + 4096 } else { buf.len() * 2 };
                if next > 64 * 1024 * 1024 {
                    return Err(status);
                }
                // Fresh buffer rather than `resize`: the old contents are garbage,
                // so copying them forward is pure waste.
                buf = vec![0; next];
            }
            other => return Err(other),
        }
    }
}

/// Object type index → type name, from the global `ObjectTypesInformation`
/// table. Lets handles that cannot be duplicated still show a type.
///
/// The table is a per-boot constant (~70 entries), so it is queried and parsed
/// once for the life of the server rather than on every snapshot.
fn object_type_table() -> &'static HashMap<u32, String> {
    static TABLE: OnceLock<HashMap<u32, String>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let buf = match query_growing(|p, len, ret| unsafe {
            NtQueryObject(std::ptr::null_mut(), OBJECT_TYPES_INFORMATION, p, len, ret)
        }) {
            Ok(b) => b,
            Err(status) => {
                debug!(status = format!("{:#x}", status), "ObjectTypesInformation query failed");
                return HashMap::new();
            }
        };
        let mut out = HashMap::new();
        unsafe {
            let base = buf.as_ptr();
            let count = (*(base as *const ObjectTypesInformation)).number_of_types as usize;
            let mut offset = align_up(std::mem::size_of::<ObjectTypesInformation>(), std::mem::size_of::<usize>());
            for _ in 0..count {
                if offset + std::mem::size_of::<ObjectTypeInformation>() > buf.len() {
                    break;
                }
                let entry = &*(base.add(offset) as *const ObjectTypeInformation);
                out.insert(entry.type_index as u32, unicode_to_string(&entry.type_name));
                offset += std::mem::size_of::<ObjectTypeInformation>()
                    + align_up(entry.type_name.maximum_length as usize, std::mem::size_of::<usize>());
            }
        }
        out
    })
}

/// `NtQueryObject(ObjectTypeInformation)` on a local handle.
fn query_type_name(handle: HANDLE) -> Option<String> {
    let buf = query_growing(|p, len, ret| unsafe { NtQueryObject(handle, OBJECT_TYPE_INFORMATION, p, len, ret) }).ok()?;
    let info = unsafe { &*(buf.as_ptr() as *const ObjectTypeInformation) };
    let name = unsafe { unicode_to_string(&info.type_name) };
    (!name.is_empty()).then_some(name)
}

/// `NtQueryObject(ObjectNameInformation)` on a local handle. May block forever
/// for a synchronous pipe — only call from [`NameWorker`].
fn query_object_name(handle: HANDLE) -> Option<String> {
    let buf = query_growing(|p, len, ret| unsafe { NtQueryObject(handle, OBJECT_NAME_INFORMATION, p, len, ret) }).ok()?;
    let name = unsafe { unicode_to_string(&*(buf.as_ptr() as *const UnicodeString)) };
    (!name.is_empty()).then_some(name)
}

/// Runs `query_object_name` on a dedicated thread with a deadline. A query that
/// misses the deadline leaves the worker (and its handle) hung; `dead` is set
/// and the caller replaces the worker. Hung threads block in the kernel and
/// cost nothing until the pipe is released or the server exits.
///
/// Handles travel the channel as `usize` — to us they are just integers, which
/// spares the newtype and its `unsafe impl Send`.
struct NameWorker {
    tx: mpsc::Sender<usize>,
    rx: mpsc::Receiver<Option<String>>,
    dead: bool,
}

impl NameWorker {
    const DEADLINE: Duration = Duration::from_millis(200);

    fn spawn() -> Self {
        let (tx, job_rx) = mpsc::channel::<usize>();
        let (res_tx, rx) = mpsc::channel::<Option<String>>();
        std::thread::Builder::new()
            .name("handle-name-query".into())
            .spawn(move || {
                while let Ok(h) = job_rx.recv() {
                    let h = h as HANDLE;
                    let name = query_object_name(h);
                    unsafe { CloseHandle(h) };
                    if res_tx.send(name).is_err() {
                        break;
                    }
                }
            })
            .expect("spawn handle-name worker");
        Self { tx, rx, dead: false }
    }

    /// Takes ownership of `local` (closes it when done, or leaks it on timeout).
    fn query(&mut self, local: HANDLE) -> Option<String> {
        if self.dead || self.tx.send(local as usize).is_err() {
            self.dead = true;
            unsafe { CloseHandle(local) };
            return None;
        }
        match self.rx.recv_timeout(Self::DEADLINE) {
            Ok(name) => name,
            Err(_) => {
                warn!("NtQueryObject(ObjectNameInformation) timed out; abandoning worker thread");
                self.dead = true;
                None
            }
        }
    }
}

/// Leaf image name of `pid`, or `None` if it can't be opened.
fn process_image_name(pid: u32) -> Option<String> {
    let h = HandleSafe(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
    if h.0.is_null() {
        return None;
    }
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    if unsafe { QueryFullProcessImageNameW(h.0, 0, buf.as_mut_ptr(), &mut len) } == 0 {
        return None;
    }
    let full = String::from_utf16_lossy(&buf[..len as usize]);
    Some(full.rsplit(['\\', '/']).next().unwrap_or(&full).to_string())
}

/// Memoises `process_image_name` across one handle walk: a target commonly
/// holds many `Process`/`Thread` handles into the same few processes, and each
/// lookup is an `OpenProcess` + `QueryFullProcessImageNameW` round trip.
struct ProcessNames {
    debuggee_pid: u32,
    cache: HashMap<u32, Option<String>>,
}

impl ProcessNames {
    fn new(debuggee_pid: u32) -> Self {
        Self { debuggee_pid, cache: HashMap::new() }
    }

    /// `"PID 1234 (foo.exe)"`, or `"PID 1234"` when the name is unavailable.
    fn describe_pid(&mut self, pid: u32) -> String {
        let debuggee_pid = self.debuggee_pid;
        let name = self
            .cache
            .entry(pid)
            .or_insert_with(|| {
                if pid == debuggee_pid { Some("debuggee".to_string()) } else { process_image_name(pid) }
            })
            .as_deref();
        match name {
            Some(n) => format!("PID {pid} ({n})"),
            None => format!("PID {pid}"),
        }
    }

    fn describe_process(&mut self, local: HANDLE) -> String {
        match unsafe { GetProcessId(local) } {
            0 => String::new(),
            pid => self.describe_pid(pid),
        }
    }

    fn describe_thread(&mut self, local: HANDLE) -> String {
        let tid = unsafe { GetThreadId(local) };
        if tid == 0 {
            return String::new();
        }
        match unsafe { GetProcessIdOfThread(local) } {
            0 => format!("TID {tid}"),
            pid => format!("TID {tid}, {}", self.describe_pid(pid)),
        }
    }
}

/// Every handle in `process`'s handle table, with type and (where cheaply
/// obtainable) name.
pub fn list_handles(process: HANDLE, pid: u32) -> Result<Vec<HandleInfo>, PlatformError> {
    let buf = query_growing(|p, len, ret| unsafe {
        NtQueryInformationProcess(process, PROCESS_HANDLE_INFORMATION, p, len, ret)
    })
    .map_err(|status| PlatformError::OsError(format!("NtQueryInformationProcess(ProcessHandleInformation) failed: {:#x}", status)))?;

    let type_table = object_type_table();
    let mut out: Vec<HandleInfo> = unsafe {
        let snap = &*(buf.as_ptr() as *const ProcessHandleSnapshotInformation);
        let first = snap.handles.as_ptr();
        (0..snap.number_of_handles)
            .map(|i| {
                let e = &*first.add(i);
                HandleInfo {
                    handle: e.handle_value as usize as u64,
                    type_index: e.object_type_index,
                    type_name: type_table.get(&e.object_type_index).cloned().unwrap_or_default(),
                    granted_access: e.granted_access,
                    attributes: e.handle_attributes,
                    name: String::new(),
                }
            })
            .collect()
    };

    let mut worker = NameWorker::spawn();
    let mut names = ProcessNames::new(pid);
    let this = unsafe { GetCurrentProcess() };
    for info in &mut out {
        let mut local: HANDLE = std::ptr::null_mut();
        let dup_ok = unsafe {
            DuplicateHandle(process, info.handle as usize as HANDLE, this, &mut local, 0, 0, DUPLICATE_SAME_ACCESS)
        } != 0;
        if !dup_ok {
            continue;
        }
        if info.type_name.is_empty() {
            if let Some(t) = query_type_name(local) {
                info.type_name = t;
            }
        }

        // Who owns `local` from here: the worker closes what it is handed, we
        // close what we keep. Splitting on that up front keeps the ownership
        // out of a flag read further down.
        //
        // `Process`/`Thread` are described from the handle itself. A synchronous
        // named pipe end opened with this exact access mask blocks forever in
        // `NtQueryObject`, so it is skipped outright rather than burning the
        // worker's deadline (TitanEngine's rule). Everything else goes to the
        // worker: only `File` handles can actually hang, but the worker answers
        // the rest just as fast and needs no per-type allow-list to stay safe.
        let named_by_worker = !matches!(info.type_name.as_str(), "Process" | "Thread")
            && !(info.type_name == "File" && info.granted_access == 0x0012_019F);

        if named_by_worker {
            if worker.dead {
                worker = NameWorker::spawn();
            }
            info.name = worker.query(local).unwrap_or_default();
        } else {
            info.name = match info.type_name.as_str() {
                "Process" => names.describe_process(local),
                "Thread" => names.describe_thread(local),
                _ => String::new(),
            };
            unsafe { CloseHandle(local) };
        }
    }
    Ok(out)
}

/// Close `handle` inside `process` without touching anything else.
pub fn close_remote_handle(process: HANDLE, handle: u64) -> Result<(), PlatformError> {
    let ok = unsafe {
        DuplicateHandle(
            process,
            handle as usize as HANDLE,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            0,
            DUPLICATE_CLOSE_SOURCE,
        )
    };
    if ok == 0 {
        let e = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!("DuplicateHandle(DUPLICATE_CLOSE_SOURCE) failed: {} ({})", e, error_message(e))));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

struct EnumCtx {
    pid: u32,
    out: Vec<WindowInfo>,
}

unsafe extern "system" fn enum_windows_cb(hwnd: HWND, lparam: isize) -> i32 { unsafe {
        let ctx = &mut *(lparam as *mut EnumCtx);
        let mut pid = 0u32;
        let tid = GetWindowThreadProcessId(hwnd, &mut pid);
        if pid == ctx.pid {
            ctx.out.push(window_info(hwnd, tid));
        }
        1
    }
}

/// Read a cross-process window string; these come from the caption cache so
/// they cannot hang on a suspended debuggee.
unsafe fn window_string(f: unsafe extern "system" fn(HWND, *mut u16, i32) -> i32, hwnd: HWND) -> String { unsafe {
        let mut buf = [0u16; 512];
        let n = f(hwnd, buf.as_mut_ptr(), buf.len() as i32);
        if n <= 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..n as usize])
    }
}

unsafe fn window_info(hwnd: HWND, tid: u32) -> WindowInfo { unsafe {
        let mut rect = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        GetWindowRect(hwnd, &mut rect);
        let unicode = IsWindowUnicode(hwnd) != 0;
        let proc_w = GetClassLongPtrW(hwnd, GCLP_WNDPROC) as u64;
        let proc_a = GetClassLongPtrA(hwnd, GCLP_WNDPROC) as u64;
        // Prefer the window's own charset, fall back to the other.
        let (preferred, fallback) = if unicode { (proc_w, proc_a) } else { (proc_a, proc_w) };
        let wnd_proc = if preferred != 0 { preferred } else { fallback };
        WindowInfo {
            handle: hwnd as usize as u64,
            parent: GetParent(hwnd) as usize as u64,
            thread_id: tid,
            style: GetWindowLongW(hwnd, GWL_STYLE) as u32,
            style_ex: GetWindowLongW(hwnd, GWL_EXSTYLE) as u32,
            wnd_proc,
            enabled: IsWindowEnabled(hwnd) != 0,
            left: rect.left,
            top: rect.top,
            width: rect.right - rect.left,
            height: rect.bottom - rect.top,
            title: window_string(GetWindowTextW, hwnd),
            class_name: window_string(GetClassNameW, hwnd),
        }
    }
}

/// Top-level windows of `pid`, followed by all their descendants.
pub fn list_windows(pid: u32) -> Vec<WindowInfo> {
    let mut ctx = EnumCtx { pid, out: Vec::new() };
    unsafe { EnumWindows(Some(enum_windows_cb), &mut ctx as *mut EnumCtx as isize) };
    let top: Vec<u64> = ctx.out.iter().map(|w| w.handle).collect();
    let mut children = EnumCtx { pid, out: Vec::new() };
    for h in top {
        unsafe { EnumChildWindows(h as usize as HWND, Some(enum_windows_cb), &mut children as *mut EnumCtx as isize) };
    }
    ctx.out.extend(children.out);
    ctx.out
}

/// The desktop window handle, so the UI can annotate parents that are it.
pub fn desktop_window() -> u64 {
    unsafe { GetDesktopWindow() as usize as u64 }
}

pub fn set_window_enabled(pid: u32, hwnd: u64, enabled: bool) -> Result<(), PlatformError> {
    let hwnd = hwnd as usize as HWND;
    let mut owner = 0u32;
    unsafe { GetWindowThreadProcessId(hwnd, &mut owner) };
    if owner != pid {
        return Err(PlatformError::Other(format!("window {:#x} is not owned by pid {}", hwnd as usize, pid)));
    }
    unsafe { EnableWindow(hwnd, if enabled { 1 } else { 0 }) };
    Ok(())
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

fn tcp_state_name(state: i32) -> String {
    match state {
        MIB_TCP_STATE_CLOSED => "CLOSED",
        MIB_TCP_STATE_LISTEN => "LISTEN",
        MIB_TCP_STATE_SYN_SENT => "SYN-SENT",
        MIB_TCP_STATE_SYN_RCVD => "SYN-RECEIVED",
        MIB_TCP_STATE_ESTAB => "ESTABLISHED",
        MIB_TCP_STATE_FIN_WAIT1 => "FIN-WAIT-1",
        MIB_TCP_STATE_FIN_WAIT2 => "FIN-WAIT-2",
        MIB_TCP_STATE_CLOSE_WAIT => "CLOSE-WAIT",
        MIB_TCP_STATE_CLOSING => "CLOSING",
        MIB_TCP_STATE_LAST_ACK => "LAST-ACK",
        MIB_TCP_STATE_TIME_WAIT => "TIME-WAIT",
        MIB_TCP_STATE_DELETE_TCB => "DELETE-TCB",
        _ => "UNKNOWN",
    }
    .to_string()
}

/// `dwLocalPort`/`dwRemotePort` hold the port in network byte order in the low
/// 16 bits.
fn tcp_port(raw: u32) -> u16 {
    u16::from_be((raw & 0xFFFF) as u16)
}

fn ipv4(raw: u32) -> String {
    std::net::Ipv4Addr::from(raw.to_ne_bytes()).to_string()
}

/// Probe for the table size, allocate, then fetch. Shared by the v4 and v6
/// walks, which differ only in the API they call and the row type they yield.
fn tcp_table(mut get: impl FnMut(*mut c_void, *mut u32) -> u32) -> Option<Vec<u8>> {
    let mut size = 0u32;
    if get(std::ptr::null_mut(), &mut size) != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    (get(buf.as_mut_ptr() as *mut c_void, &mut size) == 0).then_some(buf)
}

/// IPv4 + IPv6 TCP endpoints owned by `pid`.
pub fn list_tcp_connections(pid: u32) -> Vec<TcpConnectionInfo> {
    let mut out = Vec::new();

    if let Some(buf) = tcp_table(|p, size| unsafe { GetTcpTable2(p as *mut MIB_TCPTABLE2, size, 1) }) {
        let rows = unsafe {
            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE2);
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
        };
        out.extend(rows.iter().filter(|r| r.dwOwningPid == pid).map(|r| TcpConnectionInfo {
            local_address: ipv4(r.dwLocalAddr),
            local_port: tcp_port(r.dwLocalPort),
            remote_address: ipv4(r.dwRemoteAddr),
            remote_port: tcp_port(r.dwRemotePort),
            state: tcp_state_name(r.dwState as i32),
        }));
    }

    if let Some(buf) = tcp_table(|p, size| unsafe { GetTcp6Table2(p as *mut MIB_TCP6TABLE2, size, 1) }) {
        let rows = unsafe {
            let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE2);
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
        };
        let v6 = |a: &windows_sys::Win32::Networking::WinSock::IN6_ADDR| {
            format!("[{}]", std::net::Ipv6Addr::from(unsafe { a.u.Byte }))
        };
        out.extend(rows.iter().filter(|r| r.dwOwningPid == pid).map(|r| TcpConnectionInfo {
            local_address: v6(&r.LocalAddr),
            local_port: tcp_port(r.dwLocalPort),
            remote_address: v6(&r.RemoteAddr),
            remote_port: tcp_port(r.dwRemotePort),
            state: tcp_state_name(r.State),
        }));
    }

    out
}

// ---------------------------------------------------------------------------
// Privileges
// ---------------------------------------------------------------------------

fn open_token(process: HANDLE, access: u32) -> Result<HandleSafe, PlatformError> {
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, access, &mut token) } == 0 {
        let e = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!("OpenProcessToken failed: {} ({})", e, error_message(e))));
    }
    Ok(HandleSafe(token))
}

/// LUID → privilege name. The mapping is a per-boot constant, so the ~35 LSA
/// lookups a token walk needs are done once rather than on every snapshot.
fn privilege_name(luid: &LUID) -> Option<String> {
    static NAMES: OnceLock<Mutex<HashMap<(u32, i32), Option<String>>>> = OnceLock::new();
    let cache = NAMES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap();
    cache
        .entry((luid.LowPart, luid.HighPart))
        .or_insert_with(|| {
            let mut buf = [0u16; 256];
            let mut len = buf.len() as u32;
            let ok = unsafe {
                LookupPrivilegeNameW(std::ptr::null(), luid as *const LUID as *mut LUID, buf.as_mut_ptr(), &mut len)
            };
            (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
        })
        .clone()
}

/// Every privilege in the process's primary token with its current state.
pub fn list_privileges(process: HANDLE) -> Result<Vec<PrivilegeInfo>, PlatformError> {
    let token = open_token(process, TOKEN_QUERY)?;
    let mut size = 0u32;
    unsafe { GetTokenInformation(token.0, TokenPrivileges, std::ptr::null_mut(), 0, &mut size) };
    if size == 0 {
        let e = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!("GetTokenInformation failed: {} ({})", e, error_message(e))));
    }
    let mut buf = vec![0u8; size as usize];
    if unsafe { GetTokenInformation(token.0, TokenPrivileges, buf.as_mut_ptr() as *mut c_void, size, &mut size) } == 0 {
        let e = unsafe { GetLastError() };
        return Err(PlatformError::OsError(format!("GetTokenInformation failed: {} ({})", e, error_message(e))));
    }
    let mut out = Vec::new();
    unsafe {
        let tp = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let entries: &[LUID_AND_ATTRIBUTES] = std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize);
        for e in entries {
            let Some(name) = privilege_name(&e.Luid) else { continue };
            let state = if e.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT != 0 && e.Attributes & SE_PRIVILEGE_ENABLED != 0 {
                PrivilegeState::EnabledByDefault
            } else if e.Attributes & SE_PRIVILEGE_ENABLED != 0 {
                PrivilegeState::Enabled
            } else {
                PrivilegeState::Disabled
            };
            out.push(PrivilegeInfo { name, state });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

pub fn set_privilege(process: HANDLE, name: &str, enable: bool) -> Result<(), PlatformError> {
    let token = open_token(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;
    let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid = LUID { LowPart: 0, HighPart: 0 };
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), wname.as_ptr(), &mut luid) } == 0 {
        return Err(PlatformError::Other(format!("unknown privilege: {name}")));
    }
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: if enable { SE_PRIVILEGE_ENABLED } else { 0 } }],
    };
    let ok = unsafe { AdjustTokenPrivileges(token.0, 0, &tp, std::mem::size_of::<TOKEN_PRIVILEGES>() as u32, std::ptr::null_mut(), std::ptr::null_mut()) };
    // AdjustTokenPrivileges succeeds with ERROR_NOT_ALL_ASSIGNED when the
    // privilege isn't held by the token.
    let e = unsafe { GetLastError() };
    if ok == 0 || e != 0 {
        return Err(PlatformError::OsError(format!("AdjustTokenPrivileges failed: {} ({})", e, error_message(e))));
    }
    Ok(())
}

// ---------------------------------------------------------------------------

/// The whole Handles window in one go. Each section degrades independently:
/// a failing section is reported in `warnings` and left empty.
pub fn list_process_objects(process: HANDLE, pid: u32) -> ProcessObjects {
    let mut objects = ProcessObjects::default();
    match list_handles(process, pid) {
        Ok(h) => objects.handles = h,
        Err(e) => objects.warnings.push(format!("handles: {e}")),
    }
    objects.windows = list_windows(pid);
    objects.desktop_window = desktop_window();
    objects.tcp_connections = list_tcp_connections(pid);
    match list_privileges(process) {
        Ok(p) => objects.privileges = p,
        Err(e) => objects.warnings.push(format!("privileges: {e}")),
    }
    objects
}
