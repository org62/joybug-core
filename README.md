# joybug-core

A Windows debugging engine written in Rust — usable as a library, or as a TCP server speaking a framed-JSON protocol.

This is the engine behind **[Joybug](https://github.com/org62/joybug-tauri)**, a desktop debugger UI. Joybug is just a client: it connects over a socket, so it can drive an engine running locally or on another machine. Everything the UI does, it does by asking this crate.

It covers the ground you'd expect from a debugging backend — process launch and attach, breakpoints, stepping, memory read/write, disassembly, symbols, call stacks — plus a handful of less common capabilities that the UI surfaces as first-class features.

The whole engine is also a single command-line tool, **`jlua`**: one portable exe that runs Lua scripts against a live process (`dbg`), analyses and emulates PE files with no process at all (`pe`), detonates a target inside a disposable Windows Sandbox with ETW capture (`sbx`), and traces a process tree on the host (`etw`). It doubles as the headless debug server (`jlua --listen`) and as the sandbox guest.

## Using it with an AI agent

Point the model at this repository and it has what it needs: [`llms.txt`](llms.txt) is the index, and [`docs/agent-guide.md`](docs/agent-guide.md) is the start page — download permalink, how to run jlua non-interactively (a script in, stdout out, no REPL), which surface to pick for a question, and tested recipes for static triage, API tracing, breakpoints, coverage, offline emulation and sandbox detonation. The complete API is [`docs/jlua-guide.md`](docs/jlua-guide.md).

## Download

Grab the latest build from the [Releases page](https://github.com/org62/joybug-core/releases), or use the permalinks:

| Host | Download |
| --- | --- |
| x64 | [`jlua-x64.exe`](https://github.com/org62/joybug-core/releases/latest/download/jlua-x64.exe) |
| ARM64 | [`jlua-aarch64.exe`](https://github.com/org62/joybug-core/releases/latest/download/jlua-aarch64.exe) |

Each has a `.sha256` sidecar next to it. It's a single portable `.exe` — no installer, no runtime, nothing to configure. `jlua --version` prints the release it came from (a local build says `0.0.0`). Download the build that matches **your machine's** architecture — see [Supported targets](#supported-targets).

## Supported targets

Windows, x64 and ARM64. Breakpoints and single-stepping are written natively, so for a **native 64-bit** target **the host architecture must match** — an ARM64 build won't correctly debug an emulated x64 process, or vice versa. **32-bit x86 (WOW64)** targets are supported on either host, driven through the 32-bit (`WOW64_CONTEXT`) register file.

Pause / `BreakInto` works with PEB normalization enabled, including when
`BeingDebugged` is cleared. Windows starts a native break-in thread directly at
the target's `ntdll!DbgBreakPoint`, without changing PEB flags or patching target
code. The same path supports WOW64 targets and does not need downloaded symbols.

## Usage

As a command-line tool — `jlua` is the only binary this crate builds:

```bash
jlua                                   # interactive Lua REPL
jlua -s script.lua                     # run a script (see docs/agent-guide.md for the contract)
jlua --command "target.exe" -s x.lua   # launch a target, then run the script
jlua --listen 127.0.0.1:9000           # headless debug server for remote clients
jlua --sandbox --command "C:\mounts\d\target.exe" --mount C:\d   # debug inside Windows Sandbox
```

`--offline` and `--symbol-path` control symbol resolution for the embedded server and for `--listen` alike. The Lua API is documented in [`docs/jlua-guide.md`](docs/jlua-guide.md).

As a library:

```toml
[dependencies]
joybug-core = { git = "https://github.com/org62/joybug-core" }
```

As a server — `jlua --listen 127.0.0.1:9000`. Clients speak the protocol in `src/protocol.rs`; `src/protocol_io.rs` has a ready-made client. Embedding the server in-process instead is a one-liner via `local_server::LocalServer`, which is what Joybug and jlua itself do for local sessions.

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
- Some dependencies are pulled from GitHub rather than crates.io (two forks, and the Kuna decompiler, pinned by revision), so the build needs network access.

Integration tests under `tests/` need Windows with debugging privileges. The live Windows Sandbox tests need more: set `JOYBUG_SANDBOX_LIVE=1`; the freshly built `jlua.exe` is staged as the guest (override with `JOYBUG_SANDBOX_TEST_GUEST_EXE`). They self-skip when Windows Sandbox isn't available, and are serialized against each other because Windows allows only one sandbox per user.

CI uses self-hosted Windows ARM64/X64 and Linux X64 runners. The Linux job requires Ubuntu/Debian with passwordless `sudo apt-get`; offline runners leave jobs queued, with no GitHub-hosted fallback.

### Releases

Trunk-based: one branch, `main`, and tags. A release is a tag on `main` — nothing else is committed:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

`release.yml` runs the same build and tests as CI in `--release`, stamps the tag into `Cargo.toml` (the repo keeps a `0.0.0` placeholder; `jlua --version` on a local build prints that), and publishes `jlua-x64.exe` / `jlua-aarch64.exe` with `.sha256` sidecars. A tag containing `-` (`v0.2.0-rc.1`) is a prerelease, which the `releases/latest/download/...` permalinks skip.

## Documentation

- [`docs/agent-guide.md`](docs/agent-guide.md) — start here: getting jlua, running it non-interactively, recipes.
- [`docs/jlua-guide.md`](docs/jlua-guide.md) — the complete Lua API (`dbg`, `pe`, `sbx`, `etw`).
- [`docs/TENET_TRACE_FORMAT.md`](docs/TENET_TRACE_FORMAT.md) — the instruction-trace format.
- [`llms.txt`](llms.txt) — the same links as an index for language models.

## License

**TBD.** No license has been chosen yet; all rights reserved for now.
