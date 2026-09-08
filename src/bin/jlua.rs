//! jlua — joybug-core Lua scripting debugger CLI.
//!
//! Usage:
//!   jlua                              # Interactive REPL
//!   jlua script.lua                   # Run a script file
//!   jlua --command "test.exe"         # Launch target, REPL at initial breakpoint
//!   jlua --command "test.exe" -s script.lua  # Launch + run script
//!   jlua --sandbox --command "C:\path\t.exe" --mount C:\path
//!                                     # Provision a Windows Sandbox, connect a
//!                                     # dbg client to the in-guest server, and
//!                                     # drop into the REPL (or run -s script).
//!
//! jlua.exe is also a valid sandbox GUEST: launched with `--listen <addr>` it is
//! the debug server, with `--out <file>` the ETW collector. `--sandbox`
//! provisions a VM whose guest exe defaults to *this* jlua.exe, so a single
//! binary drives and serves the sandbox.

use std::path::PathBuf;
use std::process::exit;

use clap::Parser;

use joybug_core::local_server::LocalServer;
use joybug_core::scripting::bindings::LuaDebugClient;
use joybug_core::scripting::debug_client::DebugClient;
use joybug_core::scripting::repl::Repl;
use joybug_core::scripting;

#[derive(Parser, Debug)]
#[command(name = "jlua", about = "joybug-core Lua scripting debugger")]
struct Args {
    /// Lua script file to execute
    #[arg(short = 's', long)]
    script: Option<PathBuf>,

    /// Server address (default: start local server)
    #[arg(long)]
    server: Option<String>,

    /// Command to debug (shortcut for dbg:launch("..."))
    #[arg(short, long)]
    command: Option<String>,

    /// Drop into REPL on any breakpoint (even without handler)
    #[arg(long)]
    repl_on_break: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    // ---- Windows Sandbox mode (see `sandbox_mode`) ----
    /// Provision a Windows Sandbox and connect `dbg` to the in-guest server.
    #[arg(long)]
    sandbox: bool,

    /// Guest-binary folder to stage into the sandbox. Default: the folder of the
    /// running jlua.exe (jlua is a valid guest).
    #[arg(long)]
    guest_bin_dir: Option<PathBuf>,

    /// Guest exe name inside `--guest-bin-dir`. Default: this jlua.exe's name.
    #[arg(long)]
    guest_exe: Option<String>,

    /// Host I/O folder shared read-write as the guest's C:\io. Default: a
    /// timestamped folder under %TEMP%.
    #[arg(long)]
    io_dir: Option<PathBuf>,

    /// Host folder to map into the guest (repeatable). Append `:rw` for a
    /// writable mount (default read-only), e.g. `--mount C:\proj:rw`.
    #[arg(long = "mount")]
    mounts: Vec<String>,

    /// Guest memory in MB (sandbox mode).
    #[arg(long)]
    memory_mb: Option<u32>,

    /// ETW capture ops for sandbox mode, comma-separated (e.g. `file.*,process.start`).
    #[arg(long)]
    etw_ops: Option<String>,

    /// Capture callstacks in the sandbox ETW trace.
    #[arg(long)]
    stacks: bool,

    /// Leave the sandbox VM running on exit (reconnect later with sbx.attach(id)).
    #[arg(long)]
    keep_sandbox: bool,

    /// Positional: script file (alternative to --script)
    #[arg()]
    script_pos: Option<PathBuf>,
}

fn main() {
    // Guest roles (ETW collector, desktop probe, debug server) are decided on
    // the raw argv before clap and never return, so jlua.exe is a complete
    // sandbox guest.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if let Some(role) = joybug_core::guest_roles::from_argv(&argv) {
        joybug_core::guest_roles::run(role, argv);
    }

    joybug_core::init_tracing();

    let args = Args::parse();
    let script = args.script.clone().or(args.script_pos.clone());

    if args.sandbox {
        sandbox_mode(&args, script.as_deref());
        return;
    }

    // Start local server or connect to remote
    let _server;
    let server_addr = if let Some(addr) = &args.server {
        addr.clone()
    } else {
        let srv = LocalServer::spawn();
        let addr = srv.address().to_string();
        _server = srv;
        addr
    };

    let lua = session_lua(&args, &server_addr);

    // If --command provided, launch it via Lua
    if let Some(cmd) = &args.command {
        let launch_code = format!(r#"dbg:launch({:?})"#, cmd);
        if let Err(e) = lua.load(&launch_code).exec() {
            eprintln!("Failed to launch '{}': {}", cmd, e);
            exit(1);
        }
    }

    // Run script if provided
    if let Some(script_path) = &script {
        let code = std::fs::read_to_string(script_path).unwrap_or_else(|e| {
            eprintln!("Failed to read script '{}': {}", script_path.display(), e);
            exit(1);
        });
        if let Err(e) = lua.load(&code).set_name(script_path.to_string_lossy()).exec() {
            eprintln!("Script error: {}", e);
            exit(1);
        }
    } else if args.command.is_some() {
        // Command provided without script: run the event loop directly
        // (repl_on_break will cause breakpoints to drop into REPL)
        if let Err(e) = lua.load("dbg:run()").exec() {
            eprintln!("Error: {}", e);
            exit(1);
        }
    } else {
        // Interactive REPL mode (no command, no script)
        let mut repl = Repl::new();
        repl.run_top_level(&lua);
    }
}

/// A Lua state with a `dbg` client connected to `server_addr` and the colour
/// flag set — the bootstrap shared by the local and `--sandbox` sessions.
fn session_lua(args: &Args, server_addr: &str) -> mlua::Lua {
    let lua = scripting::create_lua().unwrap_or_else(|e| {
        eprintln!("Failed to create Lua state: {}", e);
        exit(1);
    });
    // Colour mode (also checked by the NO_COLOR env var).
    let use_color = !args.no_color && std::env::var("NO_COLOR").is_err();
    lua.globals().set("_jlua_color", use_color).unwrap();

    let client = DebugClient::connect(server_addr).unwrap_or_else(|e| {
        eprintln!("Failed to connect to server at {}: {}", server_addr, e);
        exit(1);
    });
    let lua_client = LuaDebugClient::new(client);
    if args.repl_on_break {
        lua_client.inner.borrow_mut().handlers.repl_on_break = true;
    }
    lua.globals()
        .set("dbg", lua.create_userdata(lua_client).unwrap())
        .unwrap();
    lua
}

/// `--sandbox`: provision a Windows Sandbox in debug mode, connect a `dbg`
/// client to the in-guest server, expose the handle as the `h`/`sbx_info`
/// globals, and drop into the REPL (or run `-s script`). Provision once, iterate
/// against the live guest as long as you like — the boot cost is paid a single
/// time (RETRO F3). On exit the VM is stopped unless `--keep-sandbox`.
#[cfg(windows)]
fn sandbox_mode(args: &Args, script: Option<&std::path::Path>) {
    use joybug_core::sandbox;

    // Ctrl+C / console close stops any VM we provisioned, so a hard kill does
    // not leave the one-per-user sandbox occupied (RETRO B5).
    sandbox::install_ctrl_handler();

    let status = sandbox::status();
    if !(status.supported && status.wsb_present) {
        eprintln!("Windows Sandbox is not available: {}", status.reason.unwrap_or_default());
        exit(1);
    }

    let self_exe = std::env::current_exe().unwrap_or_else(|e| {
        eprintln!("cannot locate the running jlua.exe: {e}");
        exit(1);
    });
    let guest_bin_dir = args
        .guest_bin_dir
        .clone()
        .unwrap_or_else(|| self_exe.parent().map(|p| p.to_path_buf()).unwrap_or_default());
    let guest_exe = args.guest_exe.clone().unwrap_or_else(|| {
        self_exe.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "jlua.exe".to_string())
    });
    let io_dir = args.io_dir.clone().unwrap_or_else(|| {
        std::env::temp_dir()
            .join("joybug-sbx")
            .join(format!("{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)))
            .join("io")
    });
    let symbols_dir = sandbox::default_symbols_dir(&io_dir);

    let mounts = args
        .mounts
        .iter()
        .map(|m| {
            // `<path>` or `<path>:rw` / `<path>:ro`. A drive-letter colon is not
            // a suffix, so only a trailing `:rw`/`:ro` counts.
            let (path, read_only) = if let Some(p) = m.strip_suffix(":rw") {
                (p.to_string(), false)
            } else if let Some(p) = m.strip_suffix(":ro") {
                (p.to_string(), true)
            } else {
                (m.clone(), true)
            };
            sandbox::MountSpec { host_path: path, read_only }
        })
        .collect();

    let etw = sandbox::EtwCaptureSpec {
        ops: args
            .etw_ops
            .as_deref()
            .map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect())
            .unwrap_or_default(),
        callstacks: args.stacks,
        ..Default::default()
    };
    if let Err(e) = etw.validate() {
        eprintln!("bad --etw-ops: {e}");
        exit(1);
    }

    let cfg = sandbox::ProvisionConfig {
        guest_bin_dir,
        guest_exe,
        io_dir,
        symbols_dir,
        etw_out_file: sandbox::DEFAULT_ETW_OUT_FILE.to_string(),
        server_port: sandbox::DEFAULT_SERVER_PORT,
        mounts,
        memory_mb: args.memory_mb.unwrap_or(sandbox::DEFAULT_MEMORY_MB),
        debug: true,
        collect_etw: !etw.ops.is_empty() || args.stacks,
        etw,
        symbol_offline: false,
        // A debug-mode session may leave this empty and drive dbg:launch itself;
        // --command fills it in (rewritten to a guest path via the mounts).
        launch_command: args.command.clone().unwrap_or_default(),
        working_directory: None,
    };

    eprintln!("provisioning Windows Sandbox (this takes ~a minute) ...");
    let handle = sandbox::provision(&cfg).unwrap_or_else(|e| {
        eprintln!("sandbox provision failed: {e}");
        exit(1);
    });
    let id = handle.id().to_string();
    let server_url = handle.server_url.clone();
    let guest_cmd = handle.guest_launch_command.clone();
    eprintln!("sandbox {id} ready; in-guest server at {server_url}");

    // A `dbg` client bound to the in-guest server, plus the handle as `h` and
    // its info as `sbx_info` (built exactly as `sbx.provision` builds them, so
    // `h` behaves identically).
    let lua = session_lua(args, &server_url);
    let (handle_ud, info_tbl) =
        joybug_core::scripting::sbx::wrap_handle(&lua, handle).expect("wrap sandbox handle");
    lua.globals().set("h", handle_ud).unwrap();
    lua.globals().set("sbx_info", info_tbl).unwrap();

    // --command launches the guest target under the debugger.
    if !guest_cmd.is_empty() {
        let code = format!("dbg:launch({:?})", guest_cmd);
        if let Err(e) = lua.load(&code).exec() {
            eprintln!("failed to launch the guest target: {e}");
        }
    }

    if let Some(script_path) = script {
        match std::fs::read_to_string(script_path) {
            Ok(code) => {
                if let Err(e) = lua.load(&code).set_name(script_path.to_string_lossy()).exec() {
                    eprintln!("Script error: {}", e);
                }
            }
            Err(e) => eprintln!("Failed to read script '{}': {}", script_path.display(), e),
        }
    } else {
        eprintln!("Sandbox REPL. `dbg` talks to the guest; `h` is the sandbox, `sbx_info` its details.");
        if !guest_cmd.is_empty() {
            eprintln!("Target staged: run `dbg:run()` to start it, or relaunch with `dbg:launch(sbx_info.guest_launch_command)`.");
        }
        let mut repl = Repl::new();
        repl.run_top_level(&lua);
    }

    // Teardown: stop the VM unless asked to keep it.
    if args.keep_sandbox {
        eprintln!("leaving sandbox {id} running (reconnect with sbx.attach({id:?})).");
    } else {
        eprintln!("stopping sandbox {id} ...");
        if let Err(e) = sandbox::stop(&id) {
            eprintln!("warning: {e}");
        }
    }
}

#[cfg(not(windows))]
fn sandbox_mode(_args: &Args, _script: Option<&std::path::Path>) {
    eprintln!("--sandbox is only available on Windows");
    std::process::exit(1);
}
