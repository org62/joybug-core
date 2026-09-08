//! The guest side of "see the guest desktop from the host" (RETRO F4): the
//! window tree, one window's text, and a screenshot of the virtual screen,
//! read straight from Win32 by the process that runs *inside* the guest's
//! interactive session. `sandbox::guest_ui` is the host side: it launches the
//! staged guest exe in this role through `wsb exec` and reads the result file
//! back through the `C:\io` share.
//!
//! Role dispatch: an exe that can be a sandbox guest is launched as
//! `<exe> --ui <mode> --ui-out <path> [--hwnd <n>]` and runs [`run_cli`],
//! which never returns. `guest_roles::from_argv` is where that is decided,
//! next to the `--listen` (server) and `--out` (collector) roles.

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{HWND, LPARAM, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC, ReleaseDC,
    SelectObject, CAPTUREBLT, SRCCOPY,
};
use windows_sys::Win32::Graphics::GdiPlus::{
    GdipCreateBitmapFromHBITMAP, GdipDisposeImage, GdipSaveImageToFile, GdiplusShutdown,
    GdiplusStartup, GdiplusStartupInput,
};
use windows_sys::Win32::UI::HiDpi::{
    SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, EnumWindows, GetClassNameW, GetParent, GetSystemMetrics, GetWindowRect,
    GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible, SendMessageTimeoutW,
    SMTO_ABORTIFHUNG, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
    SM_YVIRTUALSCREEN, WM_GETTEXT, WM_GETTEXTLENGTH,
};

/// The argv flag that selects this role.
pub const ROLE_FLAG: &str = "--ui";

/// One window (top-level or child) in the interactive session. The wire shape
/// between guest and host (`--ui windows` writes a JSON array of these).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GuestWindow {
    pub hwnd: u64,
    pub parent: u64,
    pub pid: u32,
    pub tid: u32,
    pub class: String,
    pub title: String,
    pub visible: bool,
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// Every window in the session: each top-level window followed by its children.
pub fn list_windows() -> Vec<GuestWindow> {
    unsafe extern "system" fn push(hwnd: HWND, list: LPARAM) -> i32 {
        unsafe { (*(list as *mut Vec<HWND>)).push(hwnd) };
        1
    }
    unsafe extern "system" fn push_with_children(hwnd: HWND, list: LPARAM) -> i32 {
        unsafe {
            push(hwnd, list);
            EnumChildWindows(hwnd, Some(push), list);
        }
        1
    }
    let mut handles: Vec<HWND> = Vec::new();
    unsafe { EnumWindows(Some(push_with_children), &mut handles as *mut _ as LPARAM) };
    handles.into_iter().map(|h| describe(h)).collect()
}

fn describe(hwnd: HWND) -> GuestWindow {
    let mut rect = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    let mut pid = 0u32;
    let (parent, tid, visible) = unsafe {
        GetWindowRect(hwnd, &mut rect);
        (GetParent(hwnd), GetWindowThreadProcessId(hwnd, &mut pid), IsWindowVisible(hwnd) != 0)
    };
    GuestWindow {
        hwnd: hwnd as u64,
        parent: parent as u64,
        pid,
        tid,
        class: wide_call(256, |buf, cap| unsafe { GetClassNameW(hwnd, buf, cap) }),
        title: wide_call(1024, |buf, cap| unsafe { GetWindowTextW(hwnd, buf, cap) }),
        visible,
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

/// Call a `(buffer, capacity) -> chars written` Win32 text getter into a fresh
/// buffer of `cap` characters and decode what it wrote.
fn wide_call(cap: usize, f: impl FnOnce(*mut u16, i32) -> i32) -> String {
    let mut buf = vec![0u16; cap];
    let n = f(buf.as_mut_ptr(), cap as i32).max(0) as usize;
    String::from_utf16_lossy(&buf[..n.min(cap)])
}

/// `WM_GETTEXT` of one window or control (an edit box's contents, not only a
/// caption). Sent with a timeout so a hung window cannot block the probe.
pub fn window_text(hwnd: u64) -> String {
    const TIMEOUT_MS: u32 = 1000;
    let hwnd = hwnd as HWND;
    let mut len: usize = 0;
    unsafe {
        SendMessageTimeoutW(hwnd, WM_GETTEXTLENGTH, 0, 0, SMTO_ABORTIFHUNG, TIMEOUT_MS, &mut len)
    };
    wide_call(len + 1, |buf, cap| {
        let mut written: usize = 0;
        unsafe {
            SendMessageTimeoutW(
                hwnd,
                WM_GETTEXT,
                cap as usize,
                buf as LPARAM,
                SMTO_ABORTIFHUNG,
                TIMEOUT_MS,
                &mut written,
            )
        };
        written as i32
    })
}

/// PNG of the whole virtual screen, written to `path`. The capture is a plain
/// GDI `BitBlt` from the screen DC; encoding goes through GDI+ so no image crate
/// is needed in the guest.
pub fn screenshot_png(path: &Path) -> Result<(), String> {
    // Without this the capture is the DPI-virtualised (scaled, blurry) screen.
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    let (x, y, w, h) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    };
    if w <= 0 || h <= 0 {
        return Err("no display: the virtual screen is empty (not an interactive session?)".into());
    }
    unsafe {
        let screen = GetDC(std::ptr::null_mut());
        let mem = CreateCompatibleDC(screen);
        let bitmap = CreateCompatibleBitmap(screen, w, h);
        let previous = SelectObject(mem, bitmap);
        let copied = BitBlt(mem, 0, 0, w, h, screen, x, y, SRCCOPY | CAPTUREBLT) != 0;
        SelectObject(mem, previous);
        DeleteDC(mem);
        ReleaseDC(std::ptr::null_mut(), screen);
        let result = if copied { save_png(bitmap, path) } else { Err("BitBlt from the screen failed".into()) };
        DeleteObject(bitmap);
        result
    }
}

/// Encode a GDI bitmap as PNG with GDI+'s built-in encoder.
unsafe fn save_png(bitmap: windows_sys::Win32::Graphics::Gdi::HBITMAP, path: &Path) -> Result<(), String> {
    // CLSID of GDI+'s PNG encoder: {557CF406-1A04-11D3-9A73-0000F81EF32E}.
    const PNG_ENCODER: windows_sys::core::GUID = windows_sys::core::GUID {
        data1: 0x557c_f406,
        data2: 0x1a04,
        data3: 0x11d3,
        data4: [0x9a, 0x73, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e],
    };
    let input = GdiplusStartupInput {
        GdiplusVersion: 1,
        DebugEventCallback: 0,
        SuppressBackgroundThread: 0,
        SuppressExternalCodecs: 0,
    };
    let mut token = 0usize;
    let status = unsafe { GdiplusStartup(&mut token, &input, std::ptr::null_mut()) };
    if status != 0 {
        return Err(format!("GdiplusStartup failed (status {status})"));
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut image = std::ptr::null_mut();
    let result = unsafe {
        let status = GdipCreateBitmapFromHBITMAP(bitmap, std::ptr::null_mut(), &mut image);
        if status != 0 {
            Err(format!("GdipCreateBitmapFromHBITMAP failed (status {status})"))
        } else {
            let status = GdipSaveImageToFile(image.cast(), wide.as_ptr(), &PNG_ENCODER, std::ptr::null());
            GdipDisposeImage(image.cast());
            if status != 0 { Err(format!("GdipSaveImageToFile({}) failed (status {status})", path.display())) } else { Ok(()) }
        }
    };
    unsafe { GdiplusShutdown(token) };
    result
}

/// A `--ui` invocation. The host side (`sandbox::guest_ui`) builds the command
/// line with [`UiMode::cli_args`] and this side parses it back with
/// [`UiMode::parse`], so the mode names, result-file extensions and the
/// `--hwnd` argument are spelled in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiMode {
    /// The whole virtual screen as PNG.
    Screenshot,
    /// Every window in the session, as JSON (`Vec<GuestWindow>`).
    Windows,
    /// `WM_GETTEXT` of one window, as UTF-8 text.
    Text { hwnd: u64 },
}

impl UiMode {
    /// The mode token after `--ui`.
    pub fn name(self) -> &'static str {
        match self {
            UiMode::Screenshot => "screenshot",
            UiMode::Windows => "windows",
            UiMode::Text { .. } => "text",
        }
    }

    /// Extension of the result file.
    pub fn ext(self) -> &'static str {
        match self {
            UiMode::Screenshot => "png",
            UiMode::Windows => "json",
            UiMode::Text { .. } => "txt",
        }
    }

    /// The arguments after the exe: `--ui <mode> --ui-out <out> [--hwnd <n>]`.
    pub fn cli_args(self, out: &str) -> String {
        let mut args = format!("{ROLE_FLAG} {} --ui-out {out}", self.name());
        if let UiMode::Text { hwnd } = self {
            args.push_str(&format!(" --hwnd {hwnd}"));
        }
        args
    }

    /// Parse the arguments [`Self::cli_args`] produces (without argv[0]).
    pub fn parse(argv: impl Iterator<Item = String>) -> Result<(UiMode, PathBuf), String> {
        let (mut mode, mut out, mut hwnd) = (None, None, 0u64);
        let mut it = argv;
        while let Some(arg) = it.next() {
            let mut value = |flag: &str| it.next().ok_or_else(|| format!("{flag} needs a value"));
            match arg.as_str() {
                ROLE_FLAG => mode = Some(value(ROLE_FLAG)?),
                "--ui-out" => out = Some(value("--ui-out")?),
                "--hwnd" => hwnd = value("--hwnd")?.parse().map_err(|e| format!("--hwnd: {e}"))?,
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        let mode = mode.ok_or("missing --ui <mode>")?;
        let out = PathBuf::from(out.ok_or("missing --ui-out <path>")?);
        let mode = match mode.as_str() {
            "screenshot" => UiMode::Screenshot,
            "windows" => UiMode::Windows,
            "text" if hwnd == 0 => return Err("--ui text needs --hwnd <n>".into()),
            "text" => UiMode::Text { hwnd },
            other => return Err(format!("unknown --ui mode {other:?} (screenshot|windows|text)")),
        };
        Ok((mode, out))
    }
}

/// The `--ui` role: `--ui <screenshot|windows|text> --ui-out <path> [--hwnd <n>]`.
/// Writes the result to the output path and exits 0, or prints the error to
/// stderr and exits 1 (the host redirects both streams to a log it tails).
pub fn run_cli(argv: impl Iterator<Item = String>) -> ! {
    let code = match run_cli_inner(argv) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("guest ui: {e}");
            1
        }
    };
    std::process::exit(code)
}

fn run_cli_inner(argv: impl Iterator<Item = String>) -> Result<(), String> {
    let (mode, out) = UiMode::parse(argv)?;
    let write = |bytes: Vec<u8>| std::fs::write(&out, bytes).map_err(|e| format!("write {}: {e}", out.display()));
    match mode {
        UiMode::Screenshot => screenshot_png(&out),
        UiMode::Windows => write(serde_json::to_vec(&list_windows()).map_err(|e| e.to_string())?),
        UiMode::Text { hwnd } => write(window_text(hwnd).into_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_list_is_well_formed_json() {
        // Runs on any session (an empty list in session 0 is fine): the point
        // is that the struct round-trips through the wire format.
        let wins = list_windows();
        let json = serde_json::to_string(&wins).unwrap();
        let back: Vec<GuestWindow> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), wins.len());
        for w in &wins {
            assert!(w.hwnd != 0);
        }
    }

    #[test]
    fn cli_rejects_missing_arguments() {
        let args = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>().into_iter();
        assert!(run_cli_inner(args("--ui windows")).unwrap_err().contains("--ui-out"));
        assert!(run_cli_inner(args("--ui-out x.json")).unwrap_err().contains("--ui"));
        assert!(run_cli_inner(args("--ui text --ui-out x.txt")).unwrap_err().contains("--hwnd"));
        assert!(run_cli_inner(args("--ui bogus --ui-out x")).unwrap_err().contains("bogus"));
    }

    #[test]
    fn cli_args_round_trip_through_parse() {
        for mode in [UiMode::Screenshot, UiMode::Windows, UiMode::Text { hwnd: 0x1234 }] {
            let line = mode.cli_args(r"C:\io\out.bin");
            let argv = line.split_whitespace().map(String::from);
            let (back, out) = UiMode::parse(argv).unwrap();
            assert_eq!(back, mode);
            assert_eq!(out, PathBuf::from(r"C:\io\out.bin"));
        }
    }
}
