//! Shared wire contract for a native interactive-console broker in the guest.
//! One broker owns its console attachment and process handle until explicitly closed.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConsoleConfig {
    pub start: ConsoleStart,
    /// None leaves terminal modes unchanged; a value explicitly requests ANSI handling.
    pub ansi: Option<bool>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConsoleStart {
    Launch {
        command: String,
        cwd: Option<String>,
        environment: Vec<(String, String)>,
    },
    Attach { pid: u32 },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ConsoleCommand {
    Read,
    Write { text: String },
    SendLine { text: String },
    SetAnsi { enabled: bool },
    WaitText { text: String, timeout_ms: u32 },
    WaitExit { timeout_ms: u32 },
    Close,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsoleSnapshot {
    pub pid: u32,
    pub hwnd: u64,
    /// The visible viewport, not a cumulative output transcript.
    pub text: String,
    pub running: bool,
    pub exit_code: Option<u32>,
    pub input_mode: u32,
    pub output_mode: u32,
    pub columns: u16,
    pub rows: u16,
    /// Absolute screen-buffer coordinates, before subtracting the viewport origin.
    pub cursor_x: i16,
    pub cursor_y: i16,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ConsoleReply {
    Snapshot(ConsoleSnapshot),
    Ok,
    Error(String),
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConsoleRequest {
    pub id: u64,
    pub command: ConsoleCommand,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConsoleResponse {
    pub id: u64,
    pub reply: ConsoleReply,
}

const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// A persistent reader over a pre-created append-only file. Never probe missing
/// per-request filenames: Windows Sandbox negatively caches those for seconds.
pub struct JsonInbox {
    reader: BufReader<File>,
    pending: Vec<u8>,
}

impl JsonInbox {
    pub fn new(file: File) -> Self {
        Self { reader: BufReader::new(file), pending: Vec::new() }
    }

    pub fn try_next<T: serde::de::DeserializeOwned>(&mut self) -> Result<Option<T>, String> {
        let remaining = MAX_MESSAGE_BYTES.saturating_sub(self.pending.len()) + 1;
        (&mut self.reader).take(remaining as u64).read_until(b'\n', &mut self.pending)
            .map_err(|e| format!("read console stream: {e}"))?;
        if self.pending.len() > MAX_MESSAGE_BYTES {
            return Err("console message exceeds 64 MiB".into());
        }
        if self.pending.last() != Some(&b'\n') {
            return Ok(None);
        }
        let result = serde_json::from_slice(&self.pending)
            .map_err(|e| format!("decode console stream: {e}"));
        self.pending.clear();
        result.map(Some)
    }
}

/// Exactly one writer owns each stream; a newline commits a complete compact
/// JSON message. Readers retain incomplete records, including split UTF-8.
pub fn append_json(file: &mut File, buffer: &mut Vec<u8>, value: &impl serde::Serialize) -> Result<(), String> {
    buffer.clear();
    serde_json::to_writer(&mut *buffer, value).map_err(|e| format!("encode console message: {e}"))?;
    buffer.push(b'\n');
    if buffer.len() > MAX_MESSAGE_BYTES {
        return Err("console message exceeds 64 MiB".into());
    }
    file.write_all(buffer).map_err(|e| format!("append console stream: {e}"))?;
    file.flush().map_err(|e| format!("flush console stream: {e}"))
}

/// Atomically publish initial config/readiness metadata without replacing an
/// existing publication. Commands use the persistent streams above instead.
pub fn publish_json(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    // Acquire ownership before cleanup is installed: a failed create_new must
    // never truncate or remove another publisher's in-flight file.
    let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&temporary)
        .map_err(|e| format!("create {}: {e}", temporary.display()))?;
    let result = (|| {
        let from: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut writer = std::io::BufWriter::new(file);
        serde_json::to_writer(&mut writer, value).map_err(|e| format!("encode console message: {e}"))?;
        writer.flush().map_err(|e| format!("flush {}: {e}", temporary.display()))?;
        drop(writer);
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } == 0 {
            Err(format!("publish {}: {}", path.display(), std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn racing_publications_cannot_replace_existing_metadata() {
        let directory = std::env::temp_dir().join(format!("joybug-console-publish-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("request-1.json");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let writers: Vec<_> = ["first", "second"].into_iter().map(|text| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                (text, publish_json(&path, &ConsoleCommand::SendLine { text: text.into() }))
            })
        }).collect();
        let results: Vec<_> = writers.into_iter().map(|writer| writer.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|(_, result)| result.is_ok()).count(), 1);
        let winner = results.iter().find(|(_, result)| result.is_ok()).unwrap().0;
        let command: ConsoleCommand = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(matches!(command, ConsoleCommand::SendLine { text } if text == winner));
        assert!(!path.with_extension("tmp").exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn stream_reader_retains_partial_utf8_and_resumes_after_eof() {
        let directory = std::env::temp_dir().join(format!("joybug-console-stream-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("requests.jsonl");
        let mut writer = std::fs::OpenOptions::new().create_new(true).append(true).open(&path).unwrap();
        let mut inbox = JsonInbox::new(File::open(&path).unwrap());
        let first = ConsoleRequest { id: 1, command: ConsoleCommand::SendLine { text: "é😀".into() } };
        let mut encoded = serde_json::to_vec(&first).unwrap();
        encoded.push(b'\n');
        let split = encoded.iter().position(|b| *b >= 128).unwrap() + 1;
        writer.write_all(&encoded[..split]).unwrap();
        assert!(inbox.try_next::<ConsoleRequest>().unwrap().is_none());
        writer.write_all(&encoded[split..]).unwrap();
        append_json(&mut writer, &mut Vec::new(), &ConsoleRequest { id: 2, command: ConsoleCommand::Close }).unwrap();
        let complete = inbox.try_next::<ConsoleRequest>().unwrap().unwrap();
        assert_eq!(complete.id, 1);
        assert!(matches!(complete.command, ConsoleCommand::SendLine { text } if text == "é😀"));
        let close = inbox.try_next::<ConsoleRequest>().unwrap().unwrap();
        assert_eq!(close.id, 2);
        assert!(matches!(close.command, ConsoleCommand::Close));
        assert!(inbox.try_next::<ConsoleRequest>().unwrap().is_none());
        drop(inbox);
        drop(writer);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
