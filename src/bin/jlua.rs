//! jlua — joybug-core Lua scripting debugger CLI.
//!
//! Usage:
//!   jlua                              # Interactive REPL
//!   jlua script.lua                   # Run a script file
//!   jlua --command "test.exe"         # Launch target, REPL at initial breakpoint
//!   jlua --command "test.exe" -s script.lua  # Launch + run script

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

    /// Positional: script file (alternative to --script)
    #[arg()]
    script_pos: Option<PathBuf>,
}

fn main() {
    joybug_core::init_tracing();

    let args = Args::parse();
    let script = args.script.or(args.script_pos);

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

    // Create Lua state
    let lua = scripting::create_lua().unwrap_or_else(|e| {
        eprintln!("Failed to create Lua state: {}", e);
        exit(1);
    });

    // Connect debug client
    let client = DebugClient::connect(&server_addr).unwrap_or_else(|e| {
        eprintln!("Failed to connect to server at {}: {}", server_addr, e);
        exit(1);
    });

    let lua_client = LuaDebugClient::new(client);

    // Set repl_on_break if requested
    if args.repl_on_break {
        lua_client.inner.borrow_mut().handlers.repl_on_break = true;
    }

    // Set color mode (also checked by NO_COLOR env var)
    let use_color = !args.no_color && std::env::var("NO_COLOR").is_err();
    lua.globals().set("_jlua_color", use_color).unwrap();

    // Register as global "dbg"
    lua.globals()
        .set("dbg", lua.create_userdata(lua_client).unwrap())
        .unwrap();

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
