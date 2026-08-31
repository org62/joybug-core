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

## Sandbox & ETW

Both are always compiled — no feature flags — and both are Windows-only, as the rest of the crate already is.

**Windows Sandbox** (`src/sandbox/`) provisions a disposable VM through the `wsb.exe` CLI (Windows 11 24H2 / build 26100+), shares folders in, starts a debug server inside it and hands back a `server_url` an ordinary `DebugSession` connects to. The mechanism is caller-agnostic: core owns no data-directory layout and never embeds guest binaries — [`ProvisionConfig`](src/sandbox/config.rs) takes the paths, so Joybug supplies its own exe as the in-guest server.

**ETW** (`src/etw.rs`, collector in [`winsandbox::tracer`](winsandbox/src/tracer.rs)) is a *mode of the hosting executable*, not a separate binary: a caller re-launches itself with the collector's flags, so there is nothing to build, ship or keep in version step. Tracing is rooted at a process and follows the whole tree transitively — it outlives its root, so a process that spawns a successor and exits is followed to the end of the chain rather than truncated. Events are JSON lines with an incremental reader, optional symbolizable callstacks, and per-operation capture selection. Kernel providers need admin on the host; inside the sandbox they do not.

One caveat worth stating plainly: **cross-process memory reads and writes are not observable.** `NtReadVirtualMemory` and friends are only emitted by Microsoft-Windows-Threat-Intelligence, which requires the consumer to be a Protected Process Light with an anti-malware ELAM signature. What the tracer reports is the `OpenProcess`/`OpenThread` that must precede them, with the decoded access mask.

The live sandbox tests are gated behind `JOYBUG_SANDBOX_LIVE` so a normal `cargo test` never boots a VM. See [`docs/jlua-guide.md`](docs/jlua-guide.md) for the `sbx` and `etw` scripting APIs.

## Building

```bash
cargo build
```

The engine links Capstone, Keystone, Unicorn and Lua natively, so the build needs a bit more than a Rust toolchain:

- Visual Studio with **both** the MSVC and **LLVM/Clang** components, and `LIBCLANG_PATH` pointing at the libclang matching your host architecture — `build.rs` panics without it.
- An MSVC developer shell (`vcvars64.bat`, or `Launch-VsDevShell.ps1 -Arch arm64`), since `build.rs` also compiles C test programs with `cl.exe`.
- On ARM64, Keystone's bundled CMakeLists needs CMake < 4: `pip install cmake==3.31.6`, put it first on `PATH`, and set `CMAKE_GENERATOR=Ninja`.
- Two dependencies are pulled from GitHub forks rather than crates.io, so the build needs network access.

Integration tests under `tests/` need Windows with debugging privileges. The live Windows Sandbox tests need more: set `JOYBUG_SANDBOX_LIVE=1`, and point `JOYBUG_SANDBOX_TEST_BINDIR` at a folder holding the guest exe. They self-skip when Windows Sandbox isn't available, and are serialized against each other because Windows allows only one sandbox per user.

## Documentation

Notes on specific subsystems live in [`docs/`](docs/) — the Lua scripting API, the VEH-based debugging mode, and the trace format.

## License

**TBD.** No license has been chosen yet; all rights reserved for now.
