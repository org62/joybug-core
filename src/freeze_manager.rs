//! Server-side value freeze.
//!
//! A "freeze" (Cheat-Engine style value lock) is a per-connection background
//! thread that continuously writes a stored value to a target address. This lets
//! a client lock a value by sending a single register/unregister command instead
//! of streaming repeated `WriteMemory` requests over the protocol channel.
//!
//! The manager is owned per connection in [`crate::server`] and is dropped (which
//! stops every thread) when the client disconnects.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

use tracing::{debug, warn};

use crate::interfaces::PlatformAPI;

/// Default write interval when the client doesn't specify one.
const DEFAULT_INTERVAL_MS: u64 = 30;

/// Resolve a freeze target. With no offsets it is just `base`. Otherwise follow
/// the pointer chain (`addr = base; for off { addr = read_u64(addr) + off }`),
/// returning `None` if any hop can't be read (chain temporarily broken).
fn resolve_target<P: PlatformAPI + ?Sized>(
    platform: &P,
    pid: u32,
    base: u64,
    offsets: &[u64],
    pointer_size: usize,
) -> Option<u64> {
    if offsets.is_empty() {
        return Some(base);
    }
    let mut addr = base;
    for off in offsets {
        let buf = platform.read_memory(pid, addr, pointer_size).ok()?;
        if buf.len() < pointer_size {
            return None;
        }
        let ptr = if pointer_size == 4 {
            u32::from_le_bytes(buf[..4].try_into().unwrap()) as u64
        } else {
            u64::from_le_bytes(buf[..8].try_into().unwrap())
        };
        // A null hop means the object isn't there (e.g. mid-reload); treat the chain
        // as unresolvable this tick rather than writing to a near-null address.
        if ptr == 0 {
            return None;
        }
        addr = ptr.wrapping_add(*off);
    }
    Some(addr)
}

struct FreezeHandle {
    stop: Arc<AtomicBool>,
    /// Value the thread writes each tick; swappable via [`FreezeManager::update`].
    data: Arc<Mutex<Vec<u8>>>,
    thread: Option<JoinHandle<()>>,
}

/// Tracks active freezes for a single client connection.
pub struct FreezeManager {
    freezes: HashMap<u64, FreezeHandle>,
    next_id: u64,
}

impl FreezeManager {
    pub fn new() -> Self {
        Self {
            freezes: HashMap::new(),
            next_id: 1,
        }
    }

    /// Spawn a freeze thread that writes `data` every `interval_ms` (default
    /// ~30ms). When `offsets` is empty the target is the fixed `address`; otherwise
    /// `address` is a static base and the thread re-resolves the pointer chain each
    /// tick (`addr = base; for off in offsets { addr = read_u64(addr) + off }`) so
    /// the lock follows the value when the chain repoints (e.g. a level reload).
    /// Returns the freeze id used to update/stop it.
    pub fn start<P>(
        &mut self,
        platform: Arc<RwLock<P>>,
        pid: u32,
        address: u64,
        data: Vec<u8>,
        interval_ms: Option<u64>,
        offsets: Vec<u64>,
    ) -> u64
    where
        P: PlatformAPI + Send + Sync + 'static,
    {
        let id = self.next_id;
        self.next_id += 1;

        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Mutex::new(data));
        let interval = Duration::from_millis(
            interval_ms.filter(|&n| n > 0).unwrap_or(DEFAULT_INTERVAL_MS),
        );

        // Pointer width for the chain follow: 4 for a WOW64 target, else 8.
        let pointer_size = {
            let plat = platform.read().unwrap();
            plat.process_architecture(pid).map(|a| a.pointer_size()).unwrap_or(8)
        };
        let thread = {
            let stop = stop.clone();
            let shared = shared.clone();
            std::thread::Builder::new()
                .name(format!("freeze-{}", id))
                .spawn(move || {
                    debug!("freeze {} started: pid={} base=0x{:X} offsets={:?}", id, pid, address, offsets);
                    while !stop.load(Ordering::Relaxed) {
                        let bytes = shared.lock().unwrap().clone();
                        // Brief read lock per tick; PlatformAPI read/write take &self.
                        let plat = platform.read().unwrap();
                        // Re-resolve the (possibly moving) target each tick.
                        match resolve_target(&*plat, pid, address, &offsets, pointer_size) {
                            Some(addr) => {
                                if let Err(e) = plat.write_memory(pid, addr, &bytes) {
                                    warn!("freeze {} write to 0x{:X} failed: {}", id, addr, e);
                                }
                            }
                            // Chain not currently resolvable (e.g. null mid-reload);
                            // skip this tick and retry — don't write to a stale addr.
                            None => {}
                        }
                        drop(plat);
                        std::thread::sleep(interval);
                    }
                    debug!("freeze {} thread exiting", id);
                })
                .expect("failed to spawn freeze thread")
        };

        self.freezes.insert(
            id,
            FreezeHandle {
                stop,
                data: shared,
                thread: Some(thread),
            },
        );
        id
    }

    /// Replace the value an active freeze writes.
    pub fn update(&mut self, freeze_id: u64, data: Vec<u8>) -> Result<(), String> {
        match self.freezes.get(&freeze_id) {
            Some(h) => {
                *h.data.lock().unwrap() = data;
                Ok(())
            }
            None => Err(format!("No active freeze with id {}", freeze_id)),
        }
    }

    /// Stop and join a single freeze thread.
    pub fn stop(&mut self, freeze_id: u64) -> Result<(), String> {
        match self.freezes.remove(&freeze_id) {
            Some(mut h) => {
                h.stop.store(true, Ordering::Relaxed);
                if let Some(t) = h.thread.take() {
                    let _ = t.join();
                }
                Ok(())
            }
            None => Err(format!("No active freeze with id {}", freeze_id)),
        }
    }

    /// Stop and join every freeze thread.
    pub fn stop_all(&mut self) {
        for (_, mut h) in self.freezes.drain() {
            h.stop.store(true, Ordering::Relaxed);
            if let Some(t) = h.thread.take() {
                let _ = t.join();
            }
        }
    }
}

impl Default for FreezeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FreezeManager {
    fn drop(&mut self) {
        self.stop_all();
    }
}
