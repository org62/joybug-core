# joybug-core

A Windows debugging engine written in Rust — usable as a library, or as a TCP server speaking a framed-JSON protocol.

This is the engine behind **[Joybug](https://github.com/org62/joybug-tauri)**, a desktop debugger UI. Joybug is just a client: it connects over a socket, so it can drive an engine running locally or on another machine. Everything the UI does, it does by asking this crate.

It covers the ground you'd expect from a debugging backend — process launch and attach, breakpoints, stepping, memory read/write, disassembly, symbols, call stacks — plus a handful of less common capabilities that the UI surfaces as first-class features.

## Supported targets

Windows, x64 and ARM64. Breakpoints and single-stepping are written natively, so **the host architecture must match the target's** — an ARM64 build won't correctly debug an emulated x64 process, or vice versa. 32-bit/WOW64 targets aren't supported.

## Usage

As a library:

```toml
[dependencies]
joybug-core = { git = "https://github.com/org62/joybug-core" }
```

As a server — `cargo run --bin joybug-core` listens on `127.0.0.1:9000`. Clients speak the protocol in `src/protocol.rs`; `src/protocol_io.rs` has a ready-made client. Embedding the server in-process instead is a one-liner via `local_server::LocalServer`, which is what Joybug does for local sessions.

Two other binaries come along: `trace` and `jlua`, a Lua REPL exposing the debugger API.

## Building

```bash
cargo build
```

The engine links Capstone, Keystone, Unicorn and Lua natively, so the build needs a bit more than a Rust toolchain:

- Visual Studio with **both** the MSVC and **LLVM/Clang** components, and `LIBCLANG_PATH` pointing at the libclang matching your host architecture — `build.rs` panics without it.
- An MSVC developer shell (`vcvars64.bat`, or `Launch-VsDevShell.ps1 -Arch arm64`), since `build.rs` also compiles C test programs with `cl.exe`.
- On ARM64, Keystone's bundled CMakeLists needs CMake < 4: `pip install cmake==3.31.6`, put it first on `PATH`, and set `CMAKE_GENERATOR=Ninja`.
- Two dependencies are pulled from GitHub forks rather than crates.io, so the build needs network access.

Integration tests under `tests/` need Windows with debugging privileges.

## Documentation

Notes on specific subsystems live in [`docs/`](docs/) — the Lua scripting API, the VEH-based debugging mode, and the trace format.

## License

**TBD.** No license has been chosen yet; all rights reserved for now.
