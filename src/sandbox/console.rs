//! Host-side client for the native guest console broker's numbered JSON streams.
//! This owns no VM or target process: callers must keep the sandbox alive.

use std::fs::File;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::{exec_blocking, scratch_name, RunAs, SandboxHandle, GUEST_BIN_DIR, GUEST_IO_DIR};
use crate::console_protocol::{
    append_json, publish_json, ConsoleCommand, ConsoleConfig, ConsoleReply, ConsoleRequest,
    ConsoleResponse, ConsoleSnapshot, JsonInbox,
};
use crate::guest_roles::CONSOLE_ROLE_FLAG;

const START_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// A single native console attachment. Dropping it requests broker shutdown without
/// waiting; neither close nor drop terminates the target process.
///
/// Each session has an exclusively-created directory in the sandbox's I/O share.
/// A timed-out request keeps its number, so its eventual response cannot satisfy
/// a later request. Stream files remain available for diagnostics.
pub struct ConsoleSession {
    directory: PathBuf,
    next_request: u64,
    closed: bool,
    requests: File,
    responses: JsonInbox,
    outgoing: Vec<u8>,
}

impl ConsoleSession {
    /// Launch or attach in the interactive guest session, with bounded startup.
    pub fn start(handle: &SandboxHandle, config: ConsoleConfig) -> Result<Self, String> {
        if handle.io_dir.as_os_str().is_empty() {
            return Err("this sandbox handle has no io share (attach it with an `io_dir`)".into());
        }
        if handle.guest_exe.is_empty() {
            return Err("this sandbox handle does not know its guest exe (attach it with a `guest_exe`)".into());
        }
        let (name, directory) = loop {
            let name = scratch_name("console");
            let directory = handle.io_dir.join(&name);
            match std::fs::create_dir(&directory) {
                Ok(()) => break (name, directory),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("create console session {}: {e}", directory.display())),
            }
        };
        // Pre-create both streams before the guest can open them. Repeatedly
        // probing new filenames in a mapped folder triggers its negative cache.
        let requests = std::fs::OpenOptions::new().create_new(true).append(true)
            .open(directory.join("requests.jsonl")).map_err(|e| format!("create console requests: {e}"))?;
        let responses = std::fs::OpenOptions::new().create_new(true).read(true).write(true)
            .open(directory.join("responses.jsonl")).map_err(|e| format!("create console responses: {e}"))?;
        publish_json(&directory.join("config.json"), &config)?;
        let mut session = Self {
            directory, next_request: 1, closed: false, requests,
            responses: JsonInbox::new(responses), outgoing: Vec::new(),
        };
        let command = format!(
            r#""{GUEST_BIN_DIR}\{}" {CONSOLE_ROLE_FLAG} start --config "{GUEST_IO_DIR}\{name}\config.json""#,
            handle.guest_exe,
        );
        let sandbox_id = handle.id().to_owned();
        let (sender, receiver) = mpsc::channel();
        // Do not let a stuck wsb bootstrap defeat the mailbox startup deadline.
        // The native start role returns promptly after creating its broker.
        std::thread::spawn(move || {
            let result = exec_blocking(&sandbox_id, &command, RunAs::ExistingLogin);
            let _ = sender.send(result);
        });
        let started = Instant::now();
        let ready = session.directory.join("ready.json");
        let mut bootstrap_done = false;
        loop {
            if let Some(reply) = take_reply(&ready)? {
                match reply {
                    ConsoleReply::Snapshot(_) => return Ok(session),
                    ConsoleReply::Error(error) => return Err(error),
                    ConsoleReply::Ok => return Err("console startup returned no initial snapshot".into()),
                }
            }
            if !bootstrap_done {
                match receiver.try_recv() {
                    Ok(Ok(0)) => bootstrap_done = true,
                    Ok(Ok(code)) => return Err(format!("native console bootstrap exited with code {code}")),
                    Ok(Err(error)) => return Err(error),
                    Err(mpsc::TryRecvError::Disconnected) => return Err("native console bootstrap stopped without a result".into()),
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }
            if started.elapsed() >= START_TIMEOUT {
                // Drop leaves a numbered Close for a broker that becomes ready late.
                session.close_without_wait();
                return Err(format!("native console startup timed out after 30s ({})", session.directory.display()));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn read(&mut self) -> Result<ConsoleSnapshot, String> {
        self.snapshot(ConsoleCommand::Read, REQUEST_TIMEOUT)
    }

    /// Inject Unicode console key events without appending Enter.
    pub fn write(&mut self, text: String) -> Result<(), String> {
        self.ok(ConsoleCommand::Write { text }, REQUEST_TIMEOUT)
    }

    /// Inject text verbatim followed by Enter (CR).
    pub fn send_line(&mut self, text: String) -> Result<(), String> {
        self.ok(ConsoleCommand::SendLine { text }, REQUEST_TIMEOUT)
    }

    pub fn set_ansi(&mut self, enabled: bool) -> Result<(), String> {
        self.ok(ConsoleCommand::SetAnsi { enabled }, REQUEST_TIMEOUT)
    }

    pub fn wait_text(&mut self, text: String, timeout_ms: u32) -> Result<ConsoleSnapshot, String> {
        self.snapshot(ConsoleCommand::WaitText { text, timeout_ms }, wait_timeout(timeout_ms))
    }

    pub fn wait_exit(&mut self, timeout_ms: u32) -> Result<ConsoleSnapshot, String> {
        self.snapshot(ConsoleCommand::WaitExit { timeout_ms }, wait_timeout(timeout_ms))
    }

    /// Idempotent, bounded broker shutdown. The target is never terminated.
    pub fn close(&mut self) -> Result<(), String> {
        if self.closed {
            return Ok(());
        }
        let number = self.publish(ConsoleCommand::Close)?;
        self.closed = true;
        expect_ok(self.wait_reply(number, REQUEST_TIMEOUT)?)
    }

    /// Best-effort shutdown for Drop or an already-stopped parent VM.
    pub fn close_without_wait(&mut self) {
        if !self.closed {
            let _ = self.publish(ConsoleCommand::Close);
            self.closed = true;
        }
    }

    fn snapshot(&mut self, command: ConsoleCommand, timeout: Duration) -> Result<ConsoleSnapshot, String> {
        match self.request(command, timeout)? {
            ConsoleReply::Snapshot(snapshot) => Ok(snapshot),
            ConsoleReply::Error(error) => Err(error),
            ConsoleReply::Ok => Err("console broker returned no snapshot".into()),
        }
    }

    fn ok(&mut self, command: ConsoleCommand, timeout: Duration) -> Result<(), String> {
        expect_ok(self.request(command, timeout)?)
    }

    fn request(&mut self, command: ConsoleCommand, timeout: Duration) -> Result<ConsoleReply, String> {
        let number = self.publish(command)?;
        self.wait_reply(number, timeout)
    }

    fn publish(&mut self, command: ConsoleCommand) -> Result<u64, String> {
        if self.closed {
            return Err("console session already closed".into());
        }
        let number = self.next_request;
        let next = number.checked_add(1).ok_or("console request numbers exhausted")?;
        append_json(
            &mut self.requests, &mut self.outgoing,
            &ConsoleRequest { id: number, command },
        )?;
        self.next_request = next;
        Ok(number)
    }

    fn wait_reply(&mut self, number: u64, timeout: Duration) -> Result<ConsoleReply, String> {
        let started = Instant::now();
        loop {
            if let Some(response) = self.responses.try_next::<ConsoleResponse>()? {
                if response.id == number {
                    return Ok(response.reply);
                }
                if response.id > number {
                    return Err(format!("console response {} arrived before {number}", response.id));
                }
                // An earlier timed-out command may finish later. Consume its
                // response, but never mistake it for the current command.
                continue;
            }
            if started.elapsed() >= timeout {
                return Err(format!("console request {number} timed out after {}ms ({})", timeout.as_millis(), self.directory.display()));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for ConsoleSession {
    fn drop(&mut self) {
        self.close_without_wait();
    }
}

fn wait_timeout(timeout_ms: u32) -> Duration {
    Duration::from_millis(u64::from(timeout_ms)) + REQUEST_TIMEOUT
}

fn take_reply(path: &Path) -> Result<Option<ConsoleReply>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read console reply {}: {e}", path.display())),
    };
    let reply = serde_json::from_slice(&bytes)
        .map_err(|e| format!("decode console reply {}: {e}", path.display()))?;
    let _ = std::fs::remove_file(path);
    Ok(Some(reply))
}

fn expect_ok(reply: ConsoleReply) -> Result<(), String> {
    match reply {
        ConsoleReply::Ok => Ok(()),
        ConsoleReply::Error(error) => Err(error),
        ConsoleReply::Snapshot(_) => Err("console broker returned an unexpected snapshot".into()),
    }
}
