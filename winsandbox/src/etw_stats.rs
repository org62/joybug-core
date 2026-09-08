//! Loss accounting for a live ETW session.
//!
//! ETW drops events silently when its buffers overrun — a registry-heavy target
//! with every op enabled can lose most of its `process.start`s without a single
//! error (RETRO B8). The session keeps counters (`EventsLost`,
//! `RealTimeBuffersLost`, ...) that `ferrisetw` never reads; this module queries
//! them directly with `ControlTraceW(EVENT_TRACE_CONTROL_QUERY)` by session
//! name, so the tracer can write a `tracer.lost` record the moment truncation
//! starts and a `tracer.stats` summary at the end.

use windows::core::PCWSTR;
use windows::Win32::System::Diagnostics::Etw::{
    ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES,
};

/// Counters of a running session, as reported by the kernel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Events the session could not buffer (the truncation counter).
    pub events_lost: u32,
    /// Real-time buffers the consumer was too slow to take.
    pub rt_buffers_lost: u32,
    /// Buffers lost writing a log file (0 for a real-time session).
    pub log_buffers_lost: u32,
    pub buffers_written: u32,
    pub number_of_buffers: u32,
    pub buffer_size_kb: u32,
}

impl SessionStats {
    /// Total buffers lost, either way.
    pub fn buffers_lost(&self) -> u32 {
        self.rt_buffers_lost.saturating_add(self.log_buffers_lost)
    }
}

/// `EVENT_TRACE_PROPERTIES` followed by the room ETW needs for the logger and
/// log-file names it writes back.
#[repr(C)]
struct QueryProps {
    base: EVENT_TRACE_PROPERTIES,
    logger_name: [u16; 1024],
    log_file_name: [u16; 1024],
}

/// Query the session called `name`. `None` if there is no such session (or the
/// caller may not query it) — callers treat that as "no information".
pub fn query_session(name: &str) -> Option<SessionStats> {
    let mut props: QueryProps = unsafe { std::mem::zeroed() };
    props.base.Wnode.BufferSize = std::mem::size_of::<QueryProps>() as u32;
    props.base.LoggerNameOffset = std::mem::offset_of!(QueryProps, logger_name) as u32;
    props.base.LogFileNameOffset = std::mem::offset_of!(QueryProps, log_file_name) as u32;
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            PCWSTR(wide.as_ptr()),
            &mut props.base,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    if status.0 != 0 {
        return None;
    }
    Some(SessionStats {
        events_lost: props.base.EventsLost,
        rt_buffers_lost: props.base.RealTimeBuffersLost,
        log_buffers_lost: props.base.LogBuffersLost,
        buffers_written: props.base.BuffersWritten,
        number_of_buffers: props.base.NumberOfBuffers,
        buffer_size_kb: props.base.BufferSize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_session_is_none() {
        assert_eq!(query_session("joybug-no-such-etw-session-7f3a"), None);
    }
}
