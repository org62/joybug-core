//! REPL (Read-Eval-Print Loop) for interactive Lua debugging.

use std::borrow::Cow;
use std::cell::RefCell;
use mlua::prelude::*;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{Editor, Helper, Context};

use crate::protocol::DebuggerRequest;
use super::colors;
use super::debug_client::{DebugClient, context_to_lua_table};

// ---- Function signature database ----
// Each entry: (name, signature, description)
// name: lookup key (e.g. "disasm", "dbg:read_memory")
// signature: parameter hint shown after "("
// description: help text

struct FnSig {
    name: &'static str,
    sig: &'static str,
    desc: &'static str,
}

const FN_SIGS: &[FnSig] = &[
    // Shortcuts
    FnSig { name: "disasm", sig: "[addr], [count=10]", desc: "Disassemble instructions. No args = at rip. Also accepts instruction table." },
    FnSig { name: "regs", sig: "[ctx]", desc: "Print registers. No args = current context." },
    FnSig { name: "hexdump", sig: "[addr], [size=64]", desc: "Hex dump memory. No args = 64 bytes at rsp. Also accepts binary string." },
    FnSig { name: "callstack", sig: "[frames]", desc: "Print call stack. No args = current." },
    FnSig { name: "modules", sig: "[mods]", desc: "Print module list. No args = current pid." },
    FnSig { name: "deref", sig: "[addr=rsp], [count=8]", desc: "Dereference pointer chains." },
    FnSig { name: "sym", sig: "name, [max=10]", desc: "Find symbol by name, print matches, return first VA." },
    FnSig { name: "str", sig: "addr, [maxlen]", desc: "Read wide (UTF-16) string from memory." },
    FnSig { name: "bp", sig: "addr_or_name, [handler]", desc: "Set breakpoint. No handler = drop to REPL on hit." },
    FnSig { name: "hex", sig: "n", desc: "Format number as hex string (e.g. \"0xFF\")." },
    FnSig { name: "asm", sig: "code, [address=0]", desc: "Assemble instructions, print hex bytes. Returns {bytes, hex, count, size}." },
    FnSig { name: "patch", sig: "addr_or_symbol, code", desc: "Assemble and write to process memory. Accepts symbol name or address." },
    FnSig { name: "regions", sig: "", desc: "Print all memory regions with protection, state, and type." },
    FnSig { name: "u8", sig: "data, [offset=1]", desc: "Read little-endian u8 from binary string." },
    FnSig { name: "u16", sig: "data, [offset=1]", desc: "Read little-endian u16 from binary string." },
    FnSig { name: "u32", sig: "data, [offset=1]", desc: "Read little-endian u32 from binary string." },
    FnSig { name: "u64", sig: "data, [offset=1]", desc: "Read little-endian u64 from binary string." },
    // dbg methods - process
    FnSig { name: "dbg:launch", sig: "command, [debug_children=false]", desc: "Launch process for debugging. Call dbg:run() after to enter event loop." },
    FnSig { name: "dbg:attach", sig: "pid", desc: "Attach to a running process." },
    FnSig { name: "dbg:run", sig: "", desc: "Enter the debug event loop. Processes events until the root process exits." },
    FnSig { name: "dbg:terminate", sig: "pid", desc: "Terminate the debugged process." },
    FnSig { name: "dbg:detach", sig: "pid", desc: "Detach from process without terminating." },
    FnSig { name: "dbg:break_into", sig: "pid", desc: "Interrupt a running process (async break)." },
    FnSig { name: "dbg:repl", sig: "", desc: "Drop into interactive REPL from a breakpoint handler." },
    FnSig { name: "dbg:pid", sig: "", desc: "Return current stopped process ID." },
    FnSig { name: "dbg:tid", sig: "", desc: "Return current stopped thread ID." },
    FnSig { name: "dbg:address", sig: "", desc: "Return current stopped address." },
    // dbg methods - breakpoints
    FnSig { name: "dbg:set_breakpoint", sig: "pid, addr_or_symbol, [handler(pid,tid,addr)]", desc: "Set software breakpoint. addr can be number or symbol name string. Handler returns \"remove\" to auto-remove." },
    FnSig { name: "dbg:remove_breakpoint", sig: "pid, addr", desc: "Remove a software breakpoint." },
    FnSig { name: "dbg:set_single_shot_breakpoint", sig: "pid, addr_or_symbol, [handler(pid,tid,addr)]", desc: "Set one-shot breakpoint, auto-removed after first hit." },
    FnSig { name: "dbg:set_hw_breakpoint", sig: "pid, addr, type, [size=\"1\"], [handler]", desc: "Set hardware breakpoint. type: \"execute\"/\"x\", \"write\"/\"w\", \"readwrite\"/\"rw\". size: \"1\"/\"2\"/\"4\"/\"8\"." },
    FnSig { name: "dbg:remove_hw_breakpoint", sig: "pid, addr", desc: "Remove a hardware breakpoint." },
    // dbg methods - stepping
    FnSig { name: "dbg:step_into", sig: "[pid], [tid]", desc: "Single step into calls. Uses current pid/tid if omitted." },
    FnSig { name: "dbg:step_over", sig: "[pid], [tid]", desc: "Single step over calls. Uses current pid/tid if omitted." },
    FnSig { name: "dbg:step_out", sig: "[pid], [tid]", desc: "Step out of current function. Uses current pid/tid if omitted." },
    // dbg methods - memory
    FnSig { name: "dbg:read_memory", sig: "pid, addr, size", desc: "Read raw bytes from process memory. Returns binary Lua string." },
    FnSig { name: "dbg:write_memory", sig: "pid, addr, data", desc: "Write bytes to process memory. data is a Lua string." },
    FnSig { name: "dbg:read_u8", sig: "pid, addr", desc: "Read unsigned 8-bit integer from memory." },
    FnSig { name: "dbg:read_u16", sig: "pid, addr", desc: "Read little-endian unsigned 16-bit integer." },
    FnSig { name: "dbg:read_u32", sig: "pid, addr", desc: "Read little-endian unsigned 32-bit integer." },
    FnSig { name: "dbg:read_u64", sig: "pid, addr", desc: "Read little-endian unsigned 64-bit integer." },
    FnSig { name: "dbg:read_string", sig: "pid, addr, [max_len]", desc: "Read wide (UTF-16) string from memory." },
    FnSig { name: "dbg:search_memory", sig: "pid, pattern, [max_results=100]", desc: "Search for byte pattern in process memory. Returns (addresses_table, capped_bool)." },
    // dbg methods - registers
    FnSig { name: "dbg:get_context", sig: "[pid], [tid]", desc: "Read thread registers. Returns table with rax, rbx, ..., rip, rflags." },
    FnSig { name: "dbg:set_context", sig: "pid, tid, ctx_table", desc: "Modify registers. Only fields present in table are changed." },
    FnSig { name: "dbg:get_arguments", sig: "pid, tid, count", desc: "Read first N calling-convention arguments (rcx, rdx, r8, r9, stack...)." },
    // dbg methods - symbols
    FnSig { name: "dbg:find_symbol", sig: "name, [max_results=10]", desc: "Find symbols by name across all modules. Returns table of {name, module, va, rva, is_function}." },
    FnSig { name: "dbg:resolve_address", sig: "pid, addr", desc: "Resolve address to symbol. Returns {name, module, rva, offset, is_function}." },
    FnSig { name: "dbg:list_symbols", sig: "module_path", desc: "List all symbols in a module. Returns table of {name, rva, is_function}." },
    FnSig { name: "dbg:resolve_rva", sig: "module_path, rva", desc: "Resolve module-relative address to symbol." },
    FnSig { name: "dbg:symbol_status", sig: "[pid]", desc: "Per-module symbol load status. Returns table of {module, base, state, symbol_count, error, pdb_path}." },
    FnSig { name: "dbg:load_pdb", sig: "pid, module_base, pdb_path, [force=false]", desc: "Load symbols from a PDB file. Returns {loaded, symbol_count} or {loaded=false, mismatch={pe_guid, pe_age, pdb_guid, pdb_age}}." },
    FnSig { name: "dbg:retry_symbols", sig: "pid, module_base", desc: "Retry a failed symbol download for a module." },
    // dbg methods - disassembly
    FnSig { name: "dbg:disassemble", sig: "pid, addr, [count=10]", desc: "Disassemble N instructions. Returns table of {address, mnemonic, operands, symbol, size, bytes, is_call, is_jump, is_ret}." },
    FnSig { name: "dbg:disassemble_function", sig: "pid, addr, [max=1000]", desc: "Disassemble entire function. Returns {instructions, start, end, name}." },
    // dbg methods - call stack
    FnSig { name: "dbg:get_call_stack", sig: "[pid], [tid]", desc: "Get call stack frames. Returns table of {address, sp, fp, symbol, module}." },
    // dbg methods - listing
    FnSig { name: "dbg:list_modules", sig: "pid", desc: "List loaded modules. Returns table of {name, base, size}." },
    FnSig { name: "dbg:list_threads", sig: "pid", desc: "List threads. Returns table of {tid, start_address}." },
    FnSig { name: "dbg:list_processes", sig: "", desc: "List all running processes. Returns table of {pid, name}." },
    // dbg methods - memory regions
    FnSig { name: "dbg:get_module_info", sig: "pid, module_base", desc: "Get PE info: entry_point, image_base, size_of_image, sections." },
    FnSig { name: "dbg:query_memory", sig: "pid, addr", desc: "Query memory region at address. Returns {base_address, region_size, protect, state, region_type}." },
    FnSig { name: "dbg:enumerate_regions", sig: "pid", desc: "Enumerate all committed memory regions." },
    FnSig { name: "dbg:dereference", sig: "pid, addr, [count=1], [ref_base]", desc: "Follow pointer chains. Returns table of {address, offset, chain}." },
    // dbg methods - tracing
    FnSig { name: "dbg:emulate", sig: "pid, tid, [max=1000], [mode=\"basic\"], [exit_addr], [memory_reads]", desc: "Emulate instructions. Modes: basic, trace, block, module, syscall. memory_reads: {{addr,size}, ...}." },
    FnSig { name: "dbg:trace", sig: "pid, tid, [max=1000], [exit_addr]", desc: "Trace instructions using trap flag. Returns {trace, stop_reason, time_us}." },
    // dbg methods - scanning
    FnSig { name: "dbg:scan_start", sig: "pid, value_type, compare_type, [value]", desc: "Start memory scan. value_type: u8/u16/u32/u64/f32/f64. compare: exact/unknown/bigger/smaller/changed/unchanged." },
    FnSig { name: "dbg:scan_next", sig: "scan_id, compare_type, [value]", desc: "Refine memory scan results." },
    FnSig { name: "dbg:scan_results", sig: "scan_id, [offset=0], [count=100]", desc: "Get scan results. Returns {addresses, total_count}." },
    FnSig { name: "dbg:scan_reset", sig: "scan_id", desc: "Reset scan to initial state." },
    // dbg methods - events
    FnSig { name: "dbg:on_initial_breakpoint", sig: "handler(pid, tid, addr)", desc: "Register handler for the initial loader breakpoint." },
    FnSig { name: "dbg:on_dll_loaded", sig: "handler(pid, tid, name, base)", desc: "Register handler for DLL load events." },
    FnSig { name: "dbg:on_dll_unloaded", sig: "handler(pid, tid, base)", desc: "Register handler for DLL unload events." },
    FnSig { name: "dbg:on_exception", sig: "handler(pid, tid, code, addr, first_chance)", desc: "Register exception handler. Return \"stop\"/\"pass\"/nil." },
    FnSig { name: "dbg:on_process_exited", sig: "handler(pid, exit_code)", desc: "Register handler for process exit." },
    FnSig { name: "dbg:on_process_created", sig: "handler(pid, tid, name, base)", desc: "Register handler for child process creation." },
    FnSig { name: "dbg:on_thread_created", sig: "handler(pid, tid, start_addr)", desc: "Register handler for thread creation." },
    FnSig { name: "dbg:on_thread_exited", sig: "handler(pid, tid, exit_code)", desc: "Register handler for thread exit." },
    FnSig { name: "dbg:set_repl_on_break", sig: "bool", desc: "If true, auto-enter REPL on any unhandled breakpoint/exception." },
    // dbg methods - assembler
    FnSig { name: "dbg:assemble", sig: "code, [address=0]", desc: "Assemble x64 instructions. Returns {bytes, hex, count, size}. Handles RIP-relative addressing." },
    FnSig { name: "dbg:assemble_to", sig: "pid, address, code", desc: "Assemble and write directly to process memory. Returns {bytes, count, size}." },
    // Global helpers - memory formatting
    FnSig { name: "mem_state", sig: "state", desc: "Convert memory state flag to string (MEM_COMMIT, MEM_RESERVE, MEM_FREE)." },
    FnSig { name: "mem_type", sig: "region_type", desc: "Convert memory type flag to string (MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE)." },
    FnSig { name: "mem_protect", sig: "protect", desc: "Convert memory protection flag to string (PAGE_READWRITE, PAGE_EXECUTE_READ, etc.)." },
];

/// Look up a function signature by name. Matches "disasm", "dbg:read_memory", etc.
fn find_sig(name: &str) -> Option<&'static FnSig> {
    FN_SIGS.iter().find(|s| s.name == name)
}

/// Extract the function name being called at the cursor position.
/// Returns (function_name, chars_after_open_paren) if cursor is inside a call.
fn extract_call_context(line: &str, pos: usize) -> Option<(&str, usize)> {
    let text = &line[..pos];
    // Find the last unmatched '('
    let mut depth = 0i32;
    let mut paren_pos = None;
    for (i, c) in text.char_indices().rev() {
        match c {
            ')' => depth += 1,
            '(' => {
                if depth == 0 {
                    paren_pos = Some(i);
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    let paren_pos = paren_pos?;
    let after_paren = pos - paren_pos - 1;

    // Extract function name before the '('
    let before = &text[..paren_pos];
    let name_start = before.rfind(|c: char| !c.is_alphanumeric() && c != '_' && c != ':')
        .map(|i| i + 1)
        .unwrap_or(0);
    let name = &before[name_start..];
    if name.is_empty() { return None; }
    Some((name, after_paren))
}

/// Tab-completion and hint helper for the REPL.
struct LuaHelper {
    at_breakpoint: bool,
}

impl LuaHelper {
    fn new(at_breakpoint: bool) -> Self {
        Self { at_breakpoint }
    }
}

impl Helper for LuaHelper {}
impl Highlighter for LuaHelper {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(&'s self, prompt: &'p str, _default: bool) -> Cow<'b, str> {
        if !colors::enabled() {
            return Cow::Borrowed(prompt);
        }
        // Colorize "break sym> " or "jlua> " prompts
        if let Some(rest) = prompt.strip_prefix("break ") {
            if let Some(location) = rest.strip_suffix("> ") {
                return Cow::Owned(format!(
                    "\x1b[36mbreak\x1b[0m \x1b[33m{}\x1b[0m\x1b[36m>\x1b[0m ",
                    location
                ));
            }
        }
        if prompt == "jlua> " {
            return Cow::Owned("\x1b[36mjlua>\x1b[0m ".to_string());
        }
        Cow::Borrowed(prompt)
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        if colors::enabled() {
            Cow::Owned(format!("\x1b[90m{}\x1b[0m", hint))
        } else {
            Cow::Borrowed(hint)
        }
    }
}
impl Validator for LuaHelper {}

impl Hinter for LuaHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<String> {
        // Show parameter signature when cursor is inside a function call
        if let Some((name, chars_typed)) = extract_call_context(line, pos) {
            if let Some(sig) = find_sig(name) {
                if !sig.sig.is_empty() && chars_typed == 0 {
                    // Show full signature hint right after "("
                    return Some(format!("{}) -- {}", sig.sig, sig.desc));
                } else if !sig.sig.is_empty() {
                    // Show just the signature as reminder
                    return Some(format!("  -- {}({})", name.rsplit(':').next().unwrap_or(name), sig.sig));
                }
            }
        }
        None
    }
}

impl Completer for LuaHelper {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        let text = &line[..pos];

        // Find the start of the current word
        let word_start = text.rfind(|c: char| !c.is_alphanumeric() && c != '_' && c != ':' && c != '.')
            .map(|i| i + 1)
            .unwrap_or(0);
        let prefix = &text[word_start..];

        let mut candidates = Vec::new();

        if prefix.starts_with("dbg:") {
            let method_prefix = &prefix[4..];
            for sig in FN_SIGS.iter().filter(|s| s.name.starts_with("dbg:")) {
                let method = &sig.name[4..]; // strip "dbg:"
                if method.starts_with(method_prefix) {
                    let display = if sig.sig.is_empty() {
                        format!("dbg:{}() -- {}", method, sig.desc)
                    } else {
                        format!("dbg:{}({}) -- {}", method, sig.sig, sig.desc)
                    };
                    let replacement = if sig.sig.is_empty() {
                        format!("dbg:{}()", method)
                    } else {
                        format!("dbg:{}(", method)
                    };
                    candidates.push(Pair { display, replacement });
                }
            }
        } else {
            // Helper functions and commands
            let extras: &[&str] = if self.at_breakpoint {
                &["go", "continue", "si", "step_into", "so", "step_over", "sout", "step_out",
                  "help", "quit", "exit",
                  "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                  "rip", "rflags", "ctx", "pid", "tid",
                  "print(", "type(", "tostring(", "tonumber("]
            } else {
                &["help", "quit", "exit", "print(", "type(", "tostring(", "tonumber("]
            };

            // Add signature-based completions for shortcuts
            for sig in FN_SIGS.iter().filter(|s| !s.name.starts_with("dbg:")) {
                if sig.name.starts_with(prefix) {
                    let display = if sig.sig.is_empty() {
                        format!("{}() -- {}", sig.name, sig.desc)
                    } else {
                        format!("{}({}) -- {}", sig.name, sig.sig, sig.desc)
                    };
                    let replacement = if sig.sig.is_empty() {
                        format!("{}()", sig.name)
                    } else {
                        format!("{}(", sig.name)
                    };
                    candidates.push(Pair { display, replacement });
                }
            }

            // Add non-function completions
            for name in extras {
                if name.starts_with(prefix) {
                    candidates.push(Pair {
                        display: name.to_string(),
                        replacement: name.to_string(),
                    });
                }
            }

            if "dbg:".starts_with(prefix) && !prefix.is_empty() {
                candidates.push(Pair {
                    display: "dbg:".to_string(),
                    replacement: "dbg:".to_string(),
                });
            }
        }

        Ok((word_start, candidates))
    }
}

/// Interactive REPL for Lua evaluation.
pub struct Repl {
    editor: Editor<LuaHelper, DefaultHistory>,
}

impl Repl {
    pub fn new() -> Self {
        Self::with_helper(false)
    }

    fn with_helper(at_breakpoint: bool) -> Self {
        let mut editor = Editor::new().expect("Failed to create line editor");
        editor.set_helper(Some(LuaHelper::new(at_breakpoint)));
        Self { editor }
    }

    /// Run the top-level REPL loop (no debug session required).
    pub fn run_top_level(&mut self, lua: &Lua) {
                sync_color(lua);
        eprintln!("joybug-core Lua REPL. Type 'help' for commands, 'quit' to exit.");
        loop {
            let prompt = &colors::prompt_top();
            match self.editor.readline(prompt) {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() { continue; }
                    if trimmed == "quit" || trimmed == "exit" { break; }
                    if trimmed == "help" || trimmed == "?" {
                        print_help(false);
                        continue;
                    }
                    if let Some(topic) = trimmed.strip_prefix("help ").or_else(|| trimmed.strip_prefix("? ")) {
                        print_function_help(topic.trim());
                        continue;
                    }
                    let _ = self.editor.add_history_entry(&line);
                    self.eval_and_print(lua, trimmed);
                }
                Err(ReadlineError::Eof | ReadlineError::Interrupted) => break,
                Err(e) => {
                    eprintln!("Readline error: {}", e);
                    break;
                }
            }
        }
    }

    /// Run a breakpoint sub-REPL. Returns when user types "go"/"continue" or Ctrl-D.
    /// Takes a RefCell<DebugClient> so Lua eval and stepping can borrow/release.
    pub fn run_break_repl(&mut self, lua: &Lua, client_cell: &RefCell<DebugClient>) -> mlua::Result<()> {
        let (pid, tid, _addr, sym) = {
            let mut client = client_cell.borrow_mut();
            let pid = client.current_pid.unwrap_or(0);
            let tid = client.current_tid.unwrap_or(0);
            let addr = client.current_address.unwrap_or(0);
            let sym = if pid > 0 {
                client.format_address(pid, addr)
            } else {
                format!("0x{:X}", addr)
            };
            (pid, tid, addr, sym)
        };
                sync_color(lua);
        // Populate register globals (rax, rip, rsp, ..., ctx, pid, tid)
        populate_register_globals(lua, client_cell);
        eprintln!("Paused at {}. Type {} for commands.",
            colors::sym(&sym), colors::dim("'help'"));

        // Use a break-specific editor with breakpoint completions
        let mut break_editor = Editor::new().expect("Failed to create break editor");
        break_editor.set_helper(Some(LuaHelper::new(true)));

        let mut prompt = colors::prompt_break(&sym);
        loop {
            match break_editor.readline(&prompt) {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() { continue; }
                    let _ = break_editor.add_history_entry(&line);

                    if let Some(topic) = trimmed.strip_prefix("help ").or_else(|| trimmed.strip_prefix("? ")) {
                        print_function_help(topic.trim());
                        continue;
                    }

                    match trimmed {
                        "go" | "continue" | "g" | "c" => break,
                        "help" | "?" => print_help(true),
                        "quit" | "exit" => {
                            let pid = client_cell.borrow().current_pid;
                            if let Some(pid) = pid {
                                let _ = client_cell.borrow_mut().send_and_receive(
                                    &crate::protocol::DebuggerRequest::TerminateProcess { pid },
                                );
                            }
                            std::process::exit(0);
                        }
                        "si" | "step_into" | "so" | "step_over" | "sout" | "step_out" => {
                            let kind = match trimmed {
                                "si" | "step_into" => crate::protocol::StepKind::Into,
                                "so" | "step_over" => crate::protocol::StepKind::Over,
                                _ => crate::protocol::StepKind::Out,
                            };
                            let result = client_cell.borrow_mut().step_and_wait(pid, tid, kind);
                            match result {
                                Ok(new_addr) => {
                                    let sym = client_cell.borrow_mut().format_address(pid, new_addr);
                                    populate_register_globals(lua, client_cell);
                                    prompt = colors::prompt_break(&sym);
                                    eprintln!("Stepped to {}", colors::sym(&sym));
                                }
                                Err(e) => eprintln!("{}", colors::red(&format!("Step error: {}", e))),
                            }
                        }
                        _ => {
                            self.eval_and_print(lua, trimmed);
                        }
                    }
                }
                Err(ReadlineError::Eof) => break,
                Err(ReadlineError::Interrupted) => continue,
                Err(e) => {
                    eprintln!("Readline error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Evaluate a Lua expression or statement and print the result.
    fn eval_and_print(&self, lua: &Lua, code: &str) {
        // Try as expression first (prepend "return "), then as statement
        let result = lua
            .load(&format!("return {}", code))
            .eval::<LuaMultiValue>()
            .or_else(|_| lua.load(code).eval::<LuaMultiValue>());

        match result {
            Ok(values) => {
                if !values.is_empty() {
                    let parts: Vec<String> = values
                        .iter()
                        .map(|v| format_lua_value(v))
                        .collect();
                    println!("{}", parts.join("\t"));
                }
            }
            Err(e) => {
                eprintln!("{}", colors::red(&format!("Error: {}", e)));
            }
        }
    }
}

/// Format a Lua value for display in the REPL.
fn format_lua_value(value: &LuaValue) -> String {
    match value {
        LuaValue::Nil => "nil".to_string(),
        LuaValue::Boolean(b) => b.to_string(),
        LuaValue::Integer(n) => {
            // Show integers as both decimal and hex if they look like addresses
            if *n > 0xFFFF {
                format!("{} (0x{:X})", n, n)
            } else {
                n.to_string()
            }
        }
        LuaValue::Number(f) => format!("{}", f),
        LuaValue::String(s) => {
            match s.to_str() {
                Ok(str_val) => format!("{:?}", str_val),
                Err(_) => format!("<binary string, {} bytes>", s.as_bytes().len()),
            }
        }
        LuaValue::Table(t) => format_lua_table(t),
        LuaValue::Function(_) => "<function>".to_string(),
        LuaValue::UserData(_) => "<userdata>".to_string(),
        _ => format!("{:?}", value),
    }
}

/// Format a Lua table for display, showing up to 20 entries.
fn format_lua_table(table: &LuaTable) -> String {
    let mut parts = Vec::new();
    let max_entries = 20;

    // Try sequential first
    let len = table.raw_len();
    if len > 0 {
        for i in 1..=len.min(max_entries) {
            if let Ok(v) = table.get::<LuaValue>(i) {
                parts.push(format_lua_value(&v));
            }
        }
        if len > max_entries {
            parts.push(format!("... ({} more)", len - max_entries));
        }
        return format!("{{ {} }}", parts.join(", "));
    }

    // Hash table
    if let Ok(pairs) = table.clone().pairs::<LuaValue, LuaValue>().collect::<Result<Vec<_>, _>>() {
        for (k, v) in pairs.iter().take(max_entries) {
            parts.push(format!("{} = {}", format_lua_value(k), format_lua_value(v)));
        }
        if pairs.len() > max_entries {
            parts.push(format!("... ({} more)", pairs.len() - max_entries));
        }
    }

    if parts.is_empty() {
        "{}".to_string()
    } else {
        format!("{{ {} }}", parts.join(", "))
    }
}

/// Sync color state from Lua global to the colors module.
fn sync_color(lua: &Lua) {
    let on = lua.globals().get::<bool>("_jlua_color").unwrap_or(false);
    colors::set_enabled(on);
}

/// Populate register globals (rax, rbx, ..., rip, rsp, pid, tid) from the current context.
/// This makes `disasm(dbg:pid(), rip, 10)` work without needing `dbg:get_context()` first.
fn populate_register_globals(lua: &Lua, client_cell: &RefCell<DebugClient>) {
    let (pid, tid) = {
        let client = client_cell.borrow();
        (client.current_pid.unwrap_or(0), client.current_tid.unwrap_or(0))
    };
    if pid == 0 { return; }

    // Get thread context
    let ctx = {
        let mut client = client_cell.borrow_mut();
        client.send_and_receive(&DebuggerRequest::GetThreadContext { pid, tid })
    };

    if let Ok(crate::protocol::DebuggerResponse::ThreadContext { context }) = ctx {
        if let Ok(table) = context_to_lua_table(lua, &context) {
            let globals = lua.globals();
            // Set each register as a global
            for key in table.clone().pairs::<String, i64>() {
                if let Ok((name, value)) = key {
                    let _ = globals.set(name, value);
                }
            }
            // Also set ctx as a global for convenience
            let _ = globals.set("ctx", table);
        }
    }
    // Set pid/tid globals
    let _ = lua.globals().set("pid", pid);
    let _ = lua.globals().set("tid", tid);
}

/// Print help for a specific function/method.
fn print_function_help(topic: &str) {
    // Normalize: strip trailing "(", allow "read_memory" to match "dbg:read_memory"
    let topic = topic.trim_end_matches('(');

    // Exact match first
    let mut matches: Vec<&FnSig> = FN_SIGS.iter()
        .filter(|s| s.name == topic)
        .collect();

    // If no exact match, try "dbg:topic"
    if matches.is_empty() {
        let dbg_topic = format!("dbg:{}", topic);
        matches = FN_SIGS.iter()
            .filter(|s| s.name == dbg_topic)
            .collect();
    }

    // If still no match, substring search
    if matches.is_empty() {
        matches = FN_SIGS.iter()
            .filter(|s| s.name.contains(topic))
            .collect();
    }

    if matches.is_empty() {
        eprintln!("No help found for '{}'. Type 'help' for overview.", topic);
        return;
    }

    for sig in &matches {
        if sig.sig.is_empty() {
            eprintln!("  {}()", colors::addr(sig.name));
        } else {
            eprintln!("  {}({})", colors::addr(sig.name), colors::sym(sig.sig));
        }
        eprintln!("    {}", colors::dim(sig.desc));
        eprintln!();
    }
}

fn print_help(at_breakpoint: bool) {
    eprintln!("{}", colors::bold("REPL Commands:"));
    if at_breakpoint {
        eprintln!("  {}   Resume execution", colors::addr("go, g, c, continue"));
        eprintln!("  {}        Step one instruction (into calls)", colors::addr("si, step_into"));
        eprintln!("  {}        Step one instruction (over calls)", colors::addr("so, step_over"));
        eprintln!("  {}       Step out of current function", colors::addr("sout, step_out"));
    }
    eprintln!("  {}              Show this help {}", colors::addr("help, ?"), colors::dim("(help <name> for details)"));
    eprintln!("  {}           Terminate debuggee and exit", colors::addr("quit, exit"));
    eprintln!();
    eprintln!("{}", colors::bold("Shortcuts (auto-use current pid/tid/rip/rsp):"));
    eprintln!("  {}             Disassemble 10 instructions at rip", colors::addr("disasm()"));
    eprintln!("  {}               Print current registers", colors::addr("regs()"));
    eprintln!("  {}            Hex dump 64 bytes at rsp", colors::addr("hexdump()"));
    eprintln!("  {}          Print current call stack", colors::addr("callstack()"));
    eprintln!("  {}            Print loaded modules", colors::addr("modules()"));
    eprintln!("  {}              Dereference 8 pointers at rsp", colors::addr("deref()"));
    eprintln!("  {}          Find symbol, return VA", colors::addr("sym(\"name\")"));
    eprintln!("  {}            Read wide string", colors::addr("str(addr)"));
    eprintln!("  {}     Set breakpoint (REPL on hit)", colors::addr("bp(addr_or_name)"));
    eprintln!("  {}               Format number as hex", colors::addr("hex(n)"));
    if at_breakpoint {
        eprintln!();
        eprintln!("{}", colors::bold("Register globals (auto-updated on break/step):"));
        eprintln!("  {}", colors::green("rax rbx rcx rdx rsi rdi rbp rsp r8-r15 rip rflags"));
        eprintln!("  {}   {}   {}", colors::green("ctx (full table)"), colors::green("pid"), colors::green("tid"));
    }
    eprintln!();
    eprintln!("Full API: dbg:method() — Tab after 'dbg:' for all methods");
}
