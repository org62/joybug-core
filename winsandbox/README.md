# winsandbox

Control **Windows Sandbox** from Rust: start it, copy files in/out, run processes, read the IP, stop it.

## How it works (and why there's no "real" API)

Windows Sandbox has **no public Win32 or COM API**. The supported, documented
programmatic control surface is the **`wsb.exe` CLI**, which ships with
**Windows 11, version 24H2 (build 26100)** and later. This crate is a typed
wrapper over that CLI — it runs `wsb.exe` with `--raw` (JSON output) and parses
the results.

The alternatives, and why this crate uses the CLI:

| Approach | Supported? | Notes |
|---|---|---|
| `wsb.exe` CLI | ✅ Yes (24H2+) | Documented. `start`/`exec`/`share`/`ip`/`list`/`stop`. Used here. |
| `WindowsSandbox.exe <config.wsb>` | ✅ Yes | Declarative XML: `<MappedFolders>`, `<LogonCommand>`. Fire-and-forget. |
| Undocumented COM interface | ❌ No | `wsb.exe` is a thin client over it; reverse-engineered, unstable. |
| Host Compute System (HCS) API | ⚠️ Partial | Real Win32 (`computecore.dll`), but no public *Sandbox* schema. |

The one genuine Windows API call in this crate is `RtlGetVersion` (in
`src/version.rs`), used to verify the OS build is new enough — not to control the
sandbox itself.

## Requirements

- Windows 11 24H2+ (build ≥ 26100) with the **Windows Sandbox** optional feature enabled.
- Only one sandbox runs at a time per user.

## Usage

```rust
use winsandbox::{RunAs, Sandbox};

let work = std::env::temp_dir().join("wsb-simple");
std::fs::create_dir_all(&work)?;
std::fs::write(work.join("input.txt"), "hello\r\n")?;

// start() -> into_guard() stops the sandbox automatically on scope exit.
let sandbox = Sandbox::start()?.into_guard();

// (wait for the guest to boot — see examples/simple.rs)

// mount `work`, run cmd.exe against it, capture stdout+stderr:
let (code, output) = sandbox.run_and_capture(
    r"cmd.exe /c type C:\winsandbox-io\input.txt & whoami",
    RunAs::System,
    &work,
)?;
println!("[{code}] {output}");

sandbox.stop()?;
```

### Key points about `exec`

- **No stdout capture.** `wsb exec` cannot return a process's output. To read
  output, redirect it into a *writable shared folder* and read the file on the
  host. `run_and_capture` does this for you.
- **`RunAs::System`** runs headlessly (best for automation). **`RunAs::ExistingLogin`**
  needs an interactive session — establish one first with `wsb connect`.
- Mapped folders with `allow_write = true` are how you copy files *out* of the guest.

## Run the demos

```
cargo run                    # full demo: start, map, exec, capture, IP, stop
cargo run --example simple   # minimal mount -> run -> read -> kill loop
```

## ETW behavior tracing (`tracer`)

To see **what a process actually does** — real-time, attributed to its process
tree, with no snapshot-diff noise — the project includes a native-Rust ETW
tracer (`src/bin/tracer.rs`, using `ferrisetw`) that runs inside the sandbox as
SYSTEM and captures four kernel providers:

| Signal | Provider | Reported |
|---|---|---|
| Process creation | `Microsoft-Windows-Kernel-Process` | start (pid, ppid, image), stop (exit) |
| File modifications | `Microsoft-Windows-Kernel-File` | create (new file), write (+bytes), delete, rename |
| Registry modifications | `Microsoft-Windows-Kernel-Registry` | create_key, set_value, delete_key, delete_value (full paths) |
| Network connections | `Microsoft-Windows-Kernel-Network` | outbound TCP connect (ip:port, pid) |

Run the whole flow (start sandbox → trace a workload → summarize → stop):

```
cargo build
cargo run --example trace
```

Example output:

```
== processes ==
  + pid 4536   (parent 4464  ) \Windows\System32\curl.exe
== files created ==
  [share]\made\note.txt
== files written ==
  [share]\made\note.txt  (7 bytes)
== registry ==
  create_key   \REGISTRY\USER\.DEFAULT\Software\SbxDemo
  set_value    \REGISTRY\USER\.DEFAULT\Software\SbxDemo\Marker
  delete_key   \REGISTRY\USER\.DEFAULT\Software\SbxDemo
== network ==
  connect  104.20.23.154:80 (pid 4536)
```

From Rust it's one call once the sandbox is booted:

```rust
let events: Vec<TraceEvent> =
    sandbox.run_traced(&tracer_exe, r"C:\io\target.cmd", &work_dir)?;
```

### How it works / gotchas learned the hard way

- **Dispatch is name-based, not id-based.** Event semantics key off the
  manifest *names* from TDH (`schema.task_name()` for File — "Create", "Write",
  "CreateNewFile"; `schema.opcode_name()` for Registry — "SetValueKey",
  "DeleteKey"), which are far more stable across Windows builds than numeric
  event ids. Numeric ids are kept only as a fallback. This is the antidote to
  hardcoded magic numbers.
- **Built-in drift detector.** Run with `--discover` and any event type from the
  traced tree that we *don't* handle is emitted once as an `unhandled` probe
  carrying its task/opcode/id. If a future Windows build renames or renumbers a
  modification event, it shows up here loudly instead of silently disappearing.
- **The tracer launches the target itself** so it knows the root PID, then
  follows the process tree via `ProcessStart` events (a child of a tracked pid
  becomes tracked). Everything is filtered to that tree.
- **The base sandbox image has no VC++ runtime.** The collector is a mode of a
  joybug executable, which links the CRT dynamically, so the sandbox driver
  (`joybug_core::sandbox`) stages `vcruntime140*.dll` / `msvcp140.dll` next to
  the guest exe; without them a pushed `.exe` dies with `STATUS_DLL_NOT_FOUND`
  (`0xC0000135`).
- **Network events lie about the PID.** They're logged in a deferred (DPC)
  context, so the event's process id is System — the real pid is the `PID`
  event property. Filtering on the wrong one silently drops every connection.
- **Loss is accounted, not silent.** ETW drops events when its buffers overrun.
  The tracer sizes the session's buffers generously (overridable with
  `--buffer-kb` / `--buffers`) and polls `EventsLost` / `RealTimeBuffersLost`
  (`etw_stats::query_session`, via `ControlTraceW(EVENT_TRACE_CONTROL_QUERY)`):
  when they grow it writes a `tracer/lost` record and a stderr warning, and a
  `tracer/stats` summary at the end. A `tracer/start` record marks the session
  coming up, so a host can tell "collector never ran" from "target was quiet".
- **Symbolized stacks.** With `--stacks`, each event's raw return addresses are
  kept in `stack` and resolved in a parallel `frames` array
  (`module+0xrva` / `kernel` / bare address) from a per-pid module map fed by
  image-load events and a toolhelp snapshot when a process joins the tree.
- **File name resolution.** Write events carry only a file-object pointer, so
  the tracer keeps an object→name map built from Create events. "New file" is
  the `CreateNewFile` event; `NameCreate` is a name-cache access, not a creation.
- **Registry path resolution.** Full paths are reconstructed from a
  KeyObject→path map built from Create/Open events. Values written through a
  handle that was opened *before* tracing started show as `<unresolved>`.

### Deletion detection (an honest limitation)

Detecting file **deletion** via the Kernel-File manifest provider does not work
cleanly on build 26200:

- There is **no `SetInformation`/`FileDispositionInformation` event** — even with
  all keywords enabled, `del` produces none. So the "watch the disposition flag"
  approach is not available here.
- `NameDelete` fires on real deletion **and** on final handle close, with no
  field distinguishing them, so it yields false positives (a created-then-closed
  file looks deleted). The tracer therefore does **not** treat it as a delete.

Instead, deletion is detected reliably **host-side by existence check**: a file
the tree *created* under the shared folder that no longer exists on the host was
deleted in the sandbox (`detect_shared_deletions`). This is accurate for files
under the mapped folder; deletions elsewhere on the guest disk aren't observable
this way. For disk-wide, fully-attributed deletion you'd move to Sysmon
(`FileDelete`) or a filesystem minifilter.

### Portability

Event ids/property names were established empirically on Windows 11 build 26200.
Because dispatch is name-based with a drift detector, the tracer should tolerate
minor build differences; if something does move, `--discover` shows exactly what.

## API surface

- `Sandbox::start()` / `start_with(&SandboxConfig)` / `from_id(..)` / `list()`
- `Sandbox::share(host, guest, allow_write)`
- `Sandbox::exec(cmd, RunAs, working_dir)` → inner exit code
- `Sandbox::run_and_capture(cmd, RunAs, work_dir)` → `(exit_code, output)`
- `Sandbox::ip()` / `is_running()` / `stop()` / `into_guard()`
- `Sandbox::wait_until_ready(timeout)` / `run_traced(tracer_exe, target, work_dir)` → `Vec<TraceEvent>`
- `SandboxConfig` builder → `.wsb`-style `<Configuration>` XML for `start_with`
