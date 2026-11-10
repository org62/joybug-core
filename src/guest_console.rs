//! A persistent, native guest console attachment, controlled through numbered JSON streams.
//! Console ownership stays in this process; closing a session never terminates its target.

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    BOOL, ERROR_INVALID_HANDLE, GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    AttachConsole, CONSOLE_SCREEN_BUFFER_INFO, CTRL_BREAK_EVENT, CTRL_C_EVENT,
    ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, FreeConsole, GetConsoleMode,
    GetConsoleScreenBufferInfo, GetConsoleWindow, INPUT_RECORD, INPUT_RECORD_0, KEY_EVENT,
    KEY_EVENT_RECORD, KEY_EVENT_RECORD_0, SetConsoleCtrlHandler,
    SetConsoleMode, WriteConsoleInputW,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_NO_WINDOW, CreateProcessW, GetExitCodeProcess, OpenProcess,
    PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, STARTUPINFOW,
    TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_BACK, VK_ESCAPE, VK_RETURN, VK_TAB};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Accessibility::{
    CUIAutomation8, IUIAutomation, IUIAutomationTextPattern,
    TreeScope_Subtree, UIA_IsTextPatternAvailablePropertyId, UIA_TextPatternId,
};

use crate::console_protocol::{
    append_json, ConsoleCommand, ConsoleConfig, ConsoleReply, ConsoleResponse, ConsoleRequest,
    ConsoleSnapshot, ConsoleStart, JsonInbox, publish_json,
};
use crate::env_block::EnvironmentBlock;
use crate::formatting::{loader_failure, process_exit_status};
use crate::windows_platform::HandleSafe;

const POLL_INTERVAL: Duration = Duration::from_millis(20);
// Leave time for cleanup and error publication inside the host's 30-second startup deadline.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const ROLE_FLAG: &str = crate::guest_roles::CONSOLE_ROLE_FLAG;

fn win_error(operation: &str, code: u32) -> String {
    format!("{operation}: {} (Win32 {code})", std::io::Error::from_raw_os_error(code as i32))
}

fn last_error(operation: &str) -> String {
    win_error(operation, unsafe { GetLastError() })
}

fn wide(value: &str, name: &str) -> Result<Vec<u16>, String> {
    if value.contains('\0') {
        return Err(format!("{name} contains a NUL character"));
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

// Quote one Windows argv argument, including backslashes immediately before quotes or the end.
fn quoted_argument(command: &mut Vec<u16>, value: impl Iterator<Item = u16>) -> Result<(), String> {
    command.push(u16::from(b'"'));
    let mut slashes = 0;
    for unit in value {
        match unit {
            0 => return Err("console broker argument contains a NUL character".into()),
            92 => slashes += 1,
            34 => {
                command.extend(std::iter::repeat_n(92, slashes * 2 + 1));
                command.push(unit);
                slashes = 0;
            }
            _ => {
                command.extend(std::iter::repeat_n(92, slashes));
                command.push(unit);
                slashes = 0;
            }
        }
    }
    command.extend(std::iter::repeat_n(92, slashes * 2));
    command.push(u16::from(b'"'));
    Ok(())
}

fn startup_info() -> STARTUPINFOW {
    let mut info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    // In particular, leave lpTitle and all window/stdio settings unset.
    info
}

fn start_broker(config: &Path) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|e| format!("locate console broker: {e}"))?;
    let application: Vec<u16> = executable.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut command = Vec::new();
    quoted_argument(&mut command, executable.as_os_str().encode_wide())?;
    command.push(u16::from(b' '));
    command.extend(ROLE_FLAG.encode_utf16());
    command.extend(" serve --config ".encode_utf16());
    quoted_argument(&mut command, config.as_os_str().encode_wide())?;
    command.push(0);
    let info = startup_info();
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(), command.as_mut_ptr(), ptr::null(), ptr::null(), 0,
            CREATE_NO_WINDOW, ptr::null(), ptr::null(), &info, &mut process,
        )
    };
    if created == 0 {
        return Err(last_error("start native console broker"));
    }
    // Bootstrap does not wait for the broker (or retain either of its handles).
    let _process = HandleSafe(process.hProcess);
    let _thread = HandleSafe(process.hThread);
    Ok(())
}

struct RootProcess {
    handle: HandleSafe,
    pid: u32,
    exit_code: Option<u32>,
    // Only a newly launched process whose initialization has not completed may be killed.
    abort_launch: bool,
}

impl RootProcess {
    fn start(start: ConsoleStart) -> Result<Self, String> {
        match start {
            ConsoleStart::Attach { pid } => {
                let handle = unsafe {
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid)
                };
                if handle.is_null() {
                    return Err(last_error(&format!("open console target PID {pid}")));
                }
                Ok(Self { handle: HandleSafe(handle), pid, exit_code: None, abort_launch: false })
            }
            ConsoleStart::Launch { command, cwd, environment } => {
                let mut command = wide(&command, "console command")?;
                let cwd = cwd.as_deref().map(|value| wide(value, "console cwd")).transpose()?;
                for (name, value) in &environment {
                    if name.is_empty() || name.contains(['\0', '=']) || value.contains('\0') {
                        return Err(format!("invalid console environment entry {name:?}"));
                    }
                }
                let environment = EnvironmentBlock::new(Some(&environment));
                let info = startup_info();
                let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
                let created = unsafe {
                    CreateProcessW(
                        ptr::null(), command.as_mut_ptr(), ptr::null(), ptr::null(), 0,
                        CREATE_NEW_CONSOLE | environment.create_flags(), environment.as_ptr(),
                        cwd.as_ref().map_or(ptr::null(), |value| value.as_ptr()), &info, &mut process,
                    )
                };
                if created == 0 {
                    return Err(last_error("launch console target"));
                }
                let _thread = HandleSafe(process.hThread);
                Ok(Self {
                    handle: HandleSafe(process.hProcess), pid: process.dwProcessId,
                    exit_code: None, abort_launch: true,
                })
            }
        }
    }

    fn wait(&mut self, timeout_ms: u32) -> Result<Option<u32>, String> {
        if self.exit_code.is_some() {
            return Ok(self.exit_code);
        }
        match unsafe { WaitForSingleObject(self.handle.0, timeout_ms) } {
            WAIT_OBJECT_0 => {
                let mut code = 0;
                if unsafe { GetExitCodeProcess(self.handle.0, &mut code) } == 0 {
                    return Err(last_error("get console target exit code"));
                }
                // A signaled process really exited, even if its chosen exit code is 259.
                self.exit_code = Some(code);
                Ok(Some(code))
            }
            WAIT_TIMEOUT => Ok(None),
            WAIT_FAILED => Err(last_error("wait for console target")),
            value => Err(format!("unexpected console target wait result {value}")),
        }
    }

    fn abort_initialization(&mut self, error: String) -> String {
        // The console or accessibility provider can disappear before the first
        // snapshot. Preserve the target's real exit before any cleanup can run.
        if let Ok(Some(code)) = self.wait(0) {
            self.abort_launch = false;
            return format!(
                "console target PID {} exited with code {} before console initialization completed; {error}",
                self.pid, process_exit_status(code),
            );
        }
        if !self.abort_launch {
            return error;
        }
        self.abort_launch = false;
        if unsafe { TerminateProcess(self.handle.0, 1) } == 0 {
            let cleanup_error = last_error("terminate uninitialized console target");
            // Termination can race a normal exit. Never identify it by reopening the PID.
            if matches!(self.wait(0), Ok(Some(_))) {
                return error;
            }
            return format!("{error}; cleanup failed: {cleanup_error}");
        }
        match self.wait(5_000) {
            Ok(Some(_)) => error,
            Ok(None) => format!("{error}; cleanup timed out terminating the uninitialized target"),
            Err(cleanup_error) => format!("{error}; cleanup failed: {cleanup_error}"),
        }
    }
}

impl Drop for RootProcess {
    fn drop(&mut self) {
        if self.abort_launch {
            // Last-resort cleanup on unwinding; ordinary failure paths report cleanup errors.
            if unsafe { TerminateProcess(self.handle.0, 1) } != 0 {
                unsafe { WaitForSingleObject(self.handle.0, 5_000) };
            }
        }
    }
}

struct Attachment;

impl Drop for Attachment {
    fn drop(&mut self) {
        unsafe { FreeConsole() };
    }
}

unsafe extern "system" fn broker_ctrl_handler(event: u32) -> BOOL {
    i32::from(event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT)
}

fn open_console(name: *const u16) -> Result<HandleSafe, u32> {
    let handle = unsafe {
        CreateFileW(
            name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(), OPEN_EXISTING, 0, ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(unsafe { GetLastError() })
    } else {
        Ok(HandleSafe(handle))
    }
}

struct ComApartment;

impl ComApartment {
    fn enter() -> windows::core::Result<Self> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()? };
        Ok(Self)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

/// Screen-reader text exposes full Unicode graphemes. ReadConsoleOutputCharacterW
/// deliberately projects non-BMP cells to U+FFFD on current conhost versions.
struct ConsoleText {
    pattern: IUIAutomationTextPattern,
    _automation: IUIAutomation,
    _apartment: ComApartment,
}

impl ConsoleText {
    fn new(hwnd: windows_sys::Win32::Foundation::HWND) -> windows::core::Result<Self> {
        let apartment = ComApartment::enter()?;
        let automation: IUIAutomation = unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER)? };
        let available = unsafe {
            automation.CreatePropertyCondition(UIA_IsTextPatternAvailablePropertyId, &VARIANT::from(true))?
        };
        let root = unsafe { automation.ElementFromHandle(windows::Win32::Foundation::HWND(hwnd))? };
        let element = unsafe { root.FindFirst(TreeScope_Subtree, &available)? };
        let pattern = unsafe { element.GetCurrentPatternAs(UIA_TextPatternId)? };
        // Retain the provider, not just its HWND: its window tree can change
        // when the original client exits while this broker still owns the buffer.
        Ok(Self { pattern, _automation: automation, _apartment: apartment })
    }

    fn read(&self, capacity: usize) -> windows::core::Result<String> {
        unsafe {
            let ranges = self.pattern.GetVisibleRanges()?;
            let mut text = String::with_capacity(capacity);
            let mut end = 0;
            let mut first = true;
            for index in 0..ranges.Length()? {
                let range = ranges.GetElement(index)?;
                let value = range.GetText(-1)?;
                for line in value.split(|unit| *unit == 10) {
                    let line = line.strip_suffix(&[13]).unwrap_or(line);
                    append_visible_row(&mut text, line, !first, &mut end);
                    first = false;
                }
            }
            text.truncate(end);
            Ok(text)
        }
    }
}

struct Console {
    // Field order closes both console handles before releasing the attachment.
    input: HandleSafe,
    output: HandleSafe,
    text: Option<ConsoleText>,
    _attachment: Attachment,
}

impl Console {
    fn attach(root: &mut RootProcess) -> Result<Self, String> {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let mut attachment = None;
        let mut handler_installed = false;
        loop {
            if root.wait(0)?.is_some() {
                return Err("target exited before its console was ready".to_string());
            }
            let attempt = (|| {
                if attachment.is_none() {
                    if unsafe { AttachConsole(root.pid) } == 0 {
                        return Err(("attach to target console", unsafe { GetLastError() }));
                    }
                    attachment = Some(Attachment);
                }
                if !handler_installed {
                    // A real handler is process-local, unlike SetConsoleCtrlHandler(NULL, TRUE),
                    // whose ignore-Ctrl+C attribute would be inherited by launched children.
                    // Install only after target creation and AttachConsole resets our handler table.
                    if unsafe { SetConsoleCtrlHandler(Some(broker_ctrl_handler), 1) } == 0 {
                        return Err(("install console broker control handler", unsafe { GetLastError() }));
                    }
                    handler_installed = true;
                }
                let input = open_console(windows_sys::w!("CONIN$")).map_err(|e| ("open CONIN$", e))?;
                let output = open_console(windows_sys::w!("CONOUT$")).map_err(|e| ("open CONOUT$", e))?;
                let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
                if unsafe { GetConsoleScreenBufferInfo(output.0, &mut info) } == 0 {
                    return Err(("initialize console screen buffer", unsafe { GetLastError() }));
                }
                Ok((input, output))
            })();
            match attempt {
                Ok((input, output)) => {
                    return Ok(Self {
                        input, output, text: None, _attachment: attachment.take().expect("attached console"),
                    });
                }
                Err((operation, code)) => {
                    if root.wait(0)?.is_some() {
                        return Err(win_error(operation, code));
                    }
                    // A just-created console may not exist yet. Never retry permanent failures.
                    if code != ERROR_INVALID_HANDLE {
                        return Err(win_error(operation, code));
                    }
                    if Instant::now() >= deadline {
                        return Err(format!("console readiness timed out: {}", win_error(operation, code)));
                    }
                    std::thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
                }
            }
        }
    }

    fn active_output(&mut self) -> Result<(), String> {
        // CONOUT$ resolves the currently active buffer. A target may switch buffers after attach.
        self.output = open_console(windows_sys::w!("CONOUT$")).map_err(|e| win_error("open active CONOUT$", e))?;
        Ok(())
    }

    fn set_ansi(&mut self, enabled: bool) -> Result<(), String> {
        self.active_output()?;
        let mode = console_mode(&self.output)?;
        let mode = if enabled {
            mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT
        } else {
            mode & !ENABLE_VIRTUAL_TERMINAL_PROCESSING
        };
        if unsafe { SetConsoleMode(self.output.0, mode) } == 0 {
            return Err(last_error("set console ANSI mode"));
        }
        Ok(())
    }

    fn snapshot(&mut self, root: &mut RootProcess) -> Result<ConsoleSnapshot, String> {
        self.active_output()?;
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        if unsafe { GetConsoleScreenBufferInfo(self.output.0, &mut info) } == 0 {
            return Err(last_error("read console screen-buffer information"));
        }
        let window = info.srWindow;
        if window.Left < 0 || window.Top < 0 || window.Right < window.Left
            || window.Bottom < window.Top || window.Right >= info.dwSize.X
            || window.Bottom >= info.dwSize.Y
        {
            return Err("console reported an invalid visible viewport".into());
        }
        let columns = (i32::from(window.Right) - i32::from(window.Left) + 1) as u16;
        let rows = (i32::from(window.Bottom) - i32::from(window.Top) + 1) as u16;
        if self.text.is_none() {
            self.text = Some(ConsoleText::new(unsafe { GetConsoleWindow() })
                .map_err(|e| if e.code().0 == 0 {
                    "initialize console text reader: UI Automation returned no usable text provider (HRESULT 0x00000000)".to_string()
                } else {
                    format!("initialize console text reader: {e}")
                })?);
        }
        let text = self.text.as_ref().expect("initialized text reader")
            .read(usize::from(columns) * usize::from(rows))
            .map_err(|e| format!("read console accessibility text: {e}"))?;
        let input_mode = console_mode(&self.input)?;
        let output_mode = console_mode(&self.output)?;
        let exit_code = root.wait(0)?;
        Ok(ConsoleSnapshot {
            pid: root.pid,
            hwnd: unsafe { GetConsoleWindow() } as usize as u64,
            text,
            running: exit_code.is_none(),
            exit_code,
            input_mode,
            output_mode,
            columns,
            rows,
            cursor_x: info.dwCursorPosition.X,
            cursor_y: info.dwCursorPosition.Y,
        })
    }

    fn write(&self, text: &str, send_line: bool) -> Result<(), String> {
        // Fixed-size batches avoid building a second, potentially large copy of the input.
        let mut records = [key_record(0, false); 128];
        let mut count = 0;
        for unit in text.encode_utf16().chain(send_line.then_some(u16::from(b'\r'))) {
            records[count] = key_record(unit, true);
            records[count + 1] = key_record(unit, false);
            count += 2;
            if count == records.len() {
                self.write_records(&records)?;
                count = 0;
            }
        }
        self.write_records(&records[..count])
    }

    fn write_records(&self, mut records: &[INPUT_RECORD]) -> Result<(), String> {
        while !records.is_empty() {
            let mut written = 0;
            if unsafe {
                WriteConsoleInputW(self.input.0, records.as_ptr(), records.len() as u32, &mut written)
            } == 0 {
                return Err(last_error("write Unicode console input"));
            }
            if written == 0 || written as usize > records.len() {
                return Err("WriteConsoleInputW made no valid forward progress".into());
            }
            records = &records[written as usize..];
        }
        Ok(())
    }

    fn wait_text(&mut self, root: &mut RootProcess, literal: &str, timeout_ms: u32)
        -> Result<ConsoleSnapshot, String>
    {
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        loop {
            let snapshot = self.snapshot(root)?;
            if snapshot.text.contains(literal) {
                return Ok(snapshot);
            }
            if let Some(code) = snapshot.exit_code {
                return Err(format!(
                    "console target exited with code {} without literal {literal:?}; last visible text:\n{}",
                    process_exit_status(code), snapshot.text,
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "timed out after {timeout_ms} ms waiting for literal {literal:?}; last visible text:\n{}",
                    snapshot.text,
                ));
            }
            std::thread::sleep(POLL_INTERVAL.min(remaining));
        }
    }

    fn wait_exit(&mut self, root: &mut RootProcess, timeout_ms: u32)
        -> Result<ConsoleSnapshot, String>
    {
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            // u32::MAX means INFINITE to Win32, but every protocol timeout is finite.
            let wait_ms = remaining.as_millis().min(u128::from(u32::MAX - 1)) as u32;
            if root.wait(wait_ms)?.is_some() {
                return self.snapshot(root);
            }
            if Instant::now() >= deadline {
                let snapshot = self.snapshot(root)?;
                if !snapshot.running {
                    return Ok(snapshot);
                }
                return Err(format!(
                    "timed out after {timeout_ms} ms waiting for console target PID {} to exit; last visible text:\n{}",
                    root.pid, snapshot.text,
                ));
            }
            // Round down only affects the final sub-millisecond portion of the deadline.
            if wait_ms == 0 {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            }
        }
    }
}

fn console_mode(handle: &HandleSafe) -> Result<u32, String> {
    let mut mode = 0;
    if unsafe { GetConsoleMode(handle.0, &mut mode) } == 0 {
        return Err(last_error("read console mode"));
    }
    Ok(mode)
}

fn append_visible_row(text: &mut String, row: &[u16], newline: bool, last_nonempty: &mut usize) {
    let end = row.iter().rposition(|unit| *unit != u16::from(b' ')).map_or(0, |i| i + 1);
    if newline {
        text.push('\n');
    }
    text.extend(char::decode_utf16(row[..end].iter().copied()).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)));
    if end != 0 {
        *last_nonempty = text.len();
    }
}

fn key_record(unit: u16, down: bool) -> INPUT_RECORD {
    let (virtual_key, scan) = match unit {
        13 => (VK_RETURN, 0x1c),
        9 => (VK_TAB, 0x0f),
        8 => (VK_BACK, 0x0e),
        27 => (VK_ESCAPE, 0x01),
        _ => (0, 0),
    };
    INPUT_RECORD {
        EventType: KEY_EVENT as u16,
        Event: INPUT_RECORD_0 {
            KeyEvent: KEY_EVENT_RECORD {
                bKeyDown: i32::from(down), wRepeatCount: 1,
                wVirtualKeyCode: virtual_key, wVirtualScanCode: scan,
                uChar: KEY_EVENT_RECORD_0 { UnicodeChar: unit }, dwControlKeyState: 0,
            },
        },
    }
}

struct Broker {
    console: Console,
    root: RootProcess,
}

impl Broker {
    fn initialize(config: ConsoleConfig, ready: &Path) -> Result<Self, String> {
        // The detached serve role must not accidentally read the launcher's console.
        if unsafe { FreeConsole() } == 0 {
            return Err(last_error("detach broker from its inherited console"));
        }
        let mut root = RootProcess::start(config.start)?;
        let mut console = match Console::attach(&mut root) {
            Ok(console) => console,
            Err(error) => return Err(root.abort_initialization(error)),
        };
        let initialization = (|| {
            if let Some(enabled) = config.ansi {
                console.set_ansi(enabled)?;
            }
            let snapshot = console.snapshot(&mut root)?;
            if snapshot.exit_code.is_some_and(|code| loader_failure(code).is_some()) {
                return Err(format!(
                    "target failed during Windows loading; last visible text:\n{}",
                    snapshot.text,
                ));
            }
            publish_json(ready, &ConsoleReply::Snapshot(snapshot))
        })();
        if let Err(error) = initialization {
            return Err(root.abort_initialization(error));
        }
        root.abort_launch = false;
        Ok(Self { console, root })
    }

    fn command(&mut self, command: ConsoleCommand) -> Result<ConsoleReply, String> {
        match command {
            ConsoleCommand::Read => self.console.snapshot(&mut self.root).map(ConsoleReply::Snapshot),
            ConsoleCommand::Write { text } => self.console.write(&text, false).map(|()| ConsoleReply::Ok),
            ConsoleCommand::SendLine { text } => self.console.write(&text, true).map(|()| ConsoleReply::Ok),
            ConsoleCommand::SetAnsi { enabled } => self.console.set_ansi(enabled).map(|()| ConsoleReply::Ok),
            ConsoleCommand::WaitText { text, timeout_ms } => self.console.wait_text(&mut self.root, &text, timeout_ms).map(ConsoleReply::Snapshot),
            ConsoleCommand::WaitExit { timeout_ms } => self.console.wait_exit(&mut self.root, timeout_ms).map(ConsoleReply::Snapshot),
            ConsoleCommand::Close => Ok(ConsoleReply::Ok),
        }
    }
}


fn serve(config_path: &Path) -> Result<(), String> {
    let directory = config_path.parent().ok_or("console config has no session directory")?;
    let ready = directory.join("ready.json");
    let initialization = (|| {
        let requests = std::fs::File::open(directory.join("requests.jsonl"))
            .map_err(|e| format!("open console request stream: {e}"))?;
        let responses = std::fs::OpenOptions::new().append(true).open(directory.join("responses.jsonl"))
            .map_err(|e| format!("open console response stream: {e}"))?;
        let file = std::fs::File::open(config_path)
            .map_err(|e| format!("open console config {}: {e}", config_path.display()))?;
        let config = serde_json::from_reader(std::io::BufReader::new(file))
            .map_err(|e| format!("read console config: {e}"))?;
        Broker::initialize(config, &ready).map(|broker| (broker, JsonInbox::new(requests), responses))
    })();
    let (mut broker, mut requests, mut responses) = match initialization {
        Ok(state) => state,
        Err(error) => {
            publish_json(&ready, &ConsoleReply::Error(error.clone()))
                .map_err(|publication| format!("{error}; {publication}"))?;
            return Err(error);
        }
    };
    let mut sequence = 1u64;
    let mut outgoing = Vec::new();
    loop {
        let request = loop {
            match requests.try_next::<ConsoleRequest>()? {
                Some(request) => break request,
                None => std::thread::sleep(POLL_INTERVAL),
            }
        };
        if request.id != sequence {
            return Err(format!("expected console request {sequence}, received {}", request.id));
        }
        let close = matches!(request.command, ConsoleCommand::Close);
        let reply = broker.command(request.command).unwrap_or_else(ConsoleReply::Error);
        append_json(&mut responses, &mut outgoing, &ConsoleResponse { id: sequence, reply })?;
        if close {
            return Ok(());
        }
        sequence = sequence.checked_add(1).ok_or("console request sequence exhausted")?;
    }
}

#[derive(Clone, Copy)]
enum Mode { Start, Serve }

fn parse_cli(mut argv: impl Iterator<Item = String>) -> Result<(Mode, PathBuf), String> {
    let mut mode = None;
    let mut config = None;
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            ROLE_FLAG if mode.is_none() => {
                mode = Some(match argv.next().as_deref() {
                    Some("start") => Mode::Start,
                    Some("serve") => Mode::Serve,
                    other => return Err(format!("{ROLE_FLAG} needs start or serve, got {other:?}")),
                });
            }
            "--config" if config.is_none() => {
                config = Some(PathBuf::from(argv.next().ok_or("--config needs a path")?));
            }
            other => return Err(format!("unknown or repeated console argument {other:?}")),
        }
    }
    let config = std::path::absolute(config.ok_or("missing --config <path>")?)
        .map_err(|e| format!("resolve console config path: {e}"))?;
    Ok((mode.ok_or("missing --console start|serve")?, config))
}

/// `--console start --config <path>` bootstraps this executable's detached `serve` role.
/// Startup failures are published to ready.json; no diagnostics are printed into the target console.
pub fn run_cli(argv: impl Iterator<Item = String>) -> ! {
    let (mode, config) = match parse_cli(argv) {
        Ok(arguments) => arguments,
        Err(error) => {
            eprintln!("guest console: {error}");
            std::process::exit(1);
        }
    };
    let result = match mode {
        Mode::Serve => serve(&config),
        Mode::Start => start_broker(&config).inspect_err(|error| {
            if let Some(directory) = config.parent() {
                let _ = publish_json(&directory.join("ready.json"), &ConsoleReply::Error(error.clone()));
            }
        }),
    };
    std::process::exit(if result.is_ok() { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_quotes_spaces_quotes_and_trailing_backslashes() {
        let mut command = Vec::new();
        quoted_argument(&mut command, "C:\\a b\\".encode_utf16()).unwrap();
        assert_eq!(String::from_utf16(&command).unwrap(), "\"C:\\a b\\\\\"");
        command.clear();
        quoted_argument(&mut command, "a\\\"b".encode_utf16()).unwrap();
        assert_eq!(String::from_utf16(&command).unwrap(), "\"a\\\\\\\"b\"");
    }

    #[test]
    fn viewport_trimming_preserves_unicode_leading_and_interior_empty_rows() {
        let mut text = String::new();
        let mut end = 0;
        for (index, row) in ["    ", "  A😀  ", "    ", "Ω   ", "    "].iter().enumerate() {
            append_visible_row(&mut text, &row.encode_utf16().collect::<Vec<_>>(), index != 0, &mut end);
        }
        text.truncate(end);
        assert_eq!(text, "\n  A😀\n\nΩ");
    }

}
