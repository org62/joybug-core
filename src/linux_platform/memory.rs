//! Tracee memory through `/proc/pid/mem`: works from any thread (the server's
//! out-of-band readers, the scanners' rayon pools) while the target runs or
//! is stopped, once we are its tracer. Writes go through `FOLL_FORCE`, so
//! read-only text pages take breakpoint bytes (copy-on-write).

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;

use crate::interfaces::PlatformError;

const PAGE: u64 = 4096;

/// A process's memory file, opened once per process (and again after an exec,
/// which replaces the address space the open file descriptor refers to).
#[derive(Debug)]
pub struct ProcessMemory {
    file: File,
}

impl ProcessMemory {
    pub fn open(pid: u32) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(format!("/proc/{pid}/mem"))?;
        Ok(Self { file })
    }

    /// Read `len` bytes, returning the readable prefix when the range runs
    /// into unmapped memory (page by page after the first short read), like
    /// the Windows probed read. An unreadable first page is an error.
    pub fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, PlatformError> {
        let mut buf = vec![0u8; len];
        match self.file.read_at(&mut buf, address) {
            Ok(n) if n == len => return Ok(buf),
            Ok(n) => {
                // Short read: the kernel stops at an unmapped page; probe the rest page-wise.
                let mut done = n;
                while done < len {
                    let page_end = ((address + done as u64) / PAGE + 1) * PAGE;
                    let chunk = ((page_end - (address + done as u64)) as usize).min(len - done);
                    match self.file.read_at(&mut buf[done..done + chunk], address + done as u64) {
                        Ok(m) if m > 0 => done += m,
                        _ => break,
                    }
                }
                buf.truncate(done);
                return Ok(buf);
            }
            Err(_) if len == 0 => return Ok(buf),
            Err(e) => {
                return Err(PlatformError::OsError(format!("read {} bytes at {:#x}: {}", len, address, e)));
            }
        }
    }

    pub fn write(&self, address: u64, data: &[u8]) -> Result<(), PlatformError> {
        let mut done = 0;
        while done < data.len() {
            match self.file.write_at(&data[done..], address + done as u64) {
                Ok(0) => return Err(PlatformError::OsError(format!("write at {:#x}: no progress", address))),
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(PlatformError::OsError(format!("write {} bytes at {:#x}: {}", data.len(), address, e))),
            }
        }
        Ok(())
    }

    /// A pointer-sized speculative read: no probing, no logging.
    pub fn try_read_pointer(&self, address: u64) -> Option<u64> {
        let mut buf = [0u8; 8];
        match self.file.read_at(&mut buf, address) {
            Ok(8) => Some(u64::from_le_bytes(buf)),
            _ => None,
        }
    }
}

/// Fast path for bulk reads while the target runs: one syscall, no file.
/// Returns the readable prefix (a short count at the first unmapped page).
pub fn process_vm_read(pid: u32, address: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: len };
    let remote = libc::iovec { iov_base: address as usize as *mut libc::c_void, iov_len: len };
    // SAFETY: both iovecs describe valid buffers for the duration of the call.
    let n = unsafe { libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}
