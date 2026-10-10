//! In-process performance recorder: where the time of a request goes.
//!
//! Off by default and then free: every entry point is one relaxed atomic load.
//! A host that wants the data (the Joybug UI's opt-in telemetry) installs a
//! sink with [`set_sink`]; from then on every [`span`] on any thread of this
//! process — the client side of a request, the embedded server's handler, the
//! symbol workers — lands in that channel as a [`PerfRecord`]. The channel is
//! bounded and never blocks the recording thread: a full channel drops the
//! record and counts it ([`take_dropped`]).
//!
//! Records carry numbers only (durations, counts, sizes). Nothing here knows a
//! module's name, an address or a symbol — what a record may say about the
//! target is the host's decision, not this module's.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::RwLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// One finished span.
#[derive(Debug, Clone)]
pub struct PerfRecord {
    /// What was measured, e.g. `"disasm.decode_listing"`.
    pub name: &'static str,
    /// The protocol request being served or sent when the span ran
    /// (`"DisassembleFunction"`), empty outside a request.
    pub request: &'static str,
    /// Wall-clock start, microseconds since the Unix epoch.
    pub start_us: u64,
    pub dur_us: u64,
    /// A small per-process thread number (not the OS id).
    pub thread: u64,
    pub attrs: Vec<(&'static str, u64)>,
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static SINK: RwLock<Option<SyncSender<PerfRecord>>> = RwLock::new(None);
static NEXT_THREAD: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static THREAD_NO: u64 = NEXT_THREAD.fetch_add(1, Ordering::Relaxed);
    static REQUEST: Cell<&'static str> = const { Cell::new("") };
}

/// Whether anything is recording. Callers building attributes that cost
/// something to compute check this first.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Install (or with `None`, remove) the channel records are sent to.
pub fn set_sink(sink: Option<SyncSender<PerfRecord>>) {
    let mut slot = SINK.write().unwrap();
    ENABLED.store(sink.is_some(), Ordering::Relaxed);
    *slot = sink;
}

/// Records dropped because the sink was full, since the last call.
pub fn take_dropped() -> u64 {
    DROPPED.swap(0, Ordering::Relaxed)
}

/// Wall clock in microseconds since the Unix epoch.
pub fn now_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

/// A stable number for a module path (FNV-1a of the lowercased path). Core
/// records say which module a span was about only through this key, as the
/// `module_key` attribute; the host matches it against its own module list
/// and decides what, if anything, to say about that module.
pub fn path_key(path: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path.bytes() {
        hash ^= b.to_ascii_lowercase() as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// This thread's number, as records carry it.
pub fn thread_no() -> u64 {
    THREAD_NO.with(|t| *t)
}

/// The request tag spans on this thread currently carry.
fn current_request() -> &'static str {
    REQUEST.with(|r| r.get())
}

/// Tags every span on this thread with `request` until the guard drops, then
/// restores the previous tag.
pub fn request_scope(request: &'static str) -> RequestScope {
    RequestScope { previous: REQUEST.with(|r| r.replace(request)) }
}

pub struct RequestScope {
    previous: &'static str,
}

impl Drop for RequestScope {
    fn drop(&mut self) {
        REQUEST.with(|r| r.set(self.previous));
    }
}

/// The variant name of a `Debug`-formatted enum value (`Foo { .. }` → `"Foo"`)
/// as a `'static` string, without formatting the payload. Names are interned;
/// the set is bounded by the number of variants.
pub fn variant_name<T: std::fmt::Debug>(value: &T) -> &'static str {
    use std::fmt::Write;

    /// Collects identifier characters and aborts the format at the first other one.
    struct Head {
        buf: [u8; 48],
        len: usize,
    }
    impl Write for Head {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            for b in s.bytes() {
                if !(b.is_ascii_alphanumeric() || b == b'_') || self.len == self.buf.len() {
                    return Err(std::fmt::Error);
                }
                self.buf[self.len] = b;
                self.len += 1;
            }
            Ok(())
        }
    }

    let mut head = Head { buf: [0; 48], len: 0 };
    let _ = write!(head, "{:?}", value);
    let name = std::str::from_utf8(&head.buf[..head.len]).unwrap_or("");

    static NAMES: RwLock<Vec<&'static str>> = RwLock::new(Vec::new());
    if let Some(found) = NAMES.read().unwrap().iter().find(|n| **n == name) {
        return found;
    }
    let mut names = NAMES.write().unwrap();
    if let Some(found) = names.iter().find(|n| **n == name) {
        return found;
    }
    let leaked: &'static str = Box::leak(name.to_string().into_boxed_str());
    names.push(leaked);
    leaked
}

/// Start a span; it is recorded when the guard drops. A no-op guard when
/// nothing is recording.
#[inline]
pub fn span(name: &'static str) -> Span {
    if !enabled() {
        return Span(None);
    }
    Span(Some(Live { name, start_us: now_us(), started: Instant::now(), attrs: Vec::new() }))
}

/// Record a span whose duration was measured elsewhere (accumulated over many
/// small calls, or reported by another component).
pub fn record(name: &'static str, start_us: u64, dur_us: u64, attrs: &[(&'static str, u64)]) {
    if enabled() {
        emit(PerfRecord { name, request: current_request(), start_us, dur_us, thread: THREAD_NO.with(|t| *t), attrs: attrs.to_vec() });
    }
}

struct Live {
    name: &'static str,
    start_us: u64,
    started: Instant,
    attrs: Vec<(&'static str, u64)>,
}

pub struct Span(Option<Live>);

impl Span {
    /// A span that records nothing (for a path that turned out not to be
    /// worth a record).
    pub fn off() -> Span {
        Span(None)
    }

    /// Attach a number to the span. Free when nothing is recording.
    #[inline]
    pub fn attr(&mut self, key: &'static str, value: u64) {
        if let Some(live) = &mut self.0 {
            live.attrs.push((key, value));
        }
    }

    /// Attach the time elapsed since `since`, in microseconds. Free when
    /// nothing is recording.
    #[inline]
    pub fn attr_elapsed(&mut self, key: &'static str, since: Instant) {
        if let Some(live) = &mut self.0 {
            live.attrs.push((key, since.elapsed().as_micros() as u64));
        }
    }

    /// Whether this span is being recorded (so a caller can skip computing an
    /// attribute that costs something).
    #[inline]
    pub fn is_live(&self) -> bool {
        self.0.is_some()
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        if let Some(live) = self.0.take() {
            emit(PerfRecord {
                name: live.name,
                request: current_request(),
                start_us: live.start_us,
                dur_us: live.started.elapsed().as_micros() as u64,
                thread: THREAD_NO.with(|t| *t),
                attrs: live.attrs,
            });
        }
    }
}

fn emit(record: PerfRecord) {
    let sink = SINK.read().unwrap();
    let Some(tx) = sink.as_ref() else { return };
    match tx.try_send(record) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
        // The receiver is gone; the host will remove the sink.
        Err(TrySendError::Disconnected(_)) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    #[allow(dead_code)]
    enum Sample {
        Unit,
        Tuple(u32),
        Struct { data: Vec<u8> },
    }

    #[test]
    fn variant_name_stops_at_the_payload() {
        assert_eq!(variant_name(&Sample::Unit), "Unit");
        assert_eq!(variant_name(&Sample::Tuple(7)), "Tuple");
        assert_eq!(variant_name(&Sample::Struct { data: vec![1, 2, 3] }), "Struct");
        // Interned: the same pointer comes back.
        assert!(std::ptr::eq(variant_name(&Sample::Unit), variant_name(&Sample::Unit)));
    }

    /// One test owns the global sink, so the steps cannot race each other.
    #[test]
    fn spans_reach_the_sink_only_while_installed() {
        drop(span("perf.test.off"));

        // Roomy: other tests' spans land here too while the sink is installed.
        let (tx, rx) = std::sync::mpsc::sync_channel(65536);
        set_sink(Some(tx));
        {
            let _scope = request_scope("TestRequest");
            let mut s = span("perf.test.on");
            s.attr("n", 3);
        }
        set_sink(None);
        drop(span("perf.test.off_again"));

        let ours: Vec<PerfRecord> = rx.try_iter().filter(|r| r.name.starts_with("perf.test.")).collect();
        assert_eq!(ours.len(), 1);
        assert_eq!(ours[0].name, "perf.test.on");
        assert_eq!(ours[0].request, "TestRequest");
        assert_eq!(ours[0].attrs, vec![("n", 3)]);
        assert_eq!(current_request(), "");
    }
}
