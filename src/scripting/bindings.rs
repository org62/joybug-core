//! Lua bindings: register all debugger methods on the `dbg` userdata.
//!
//! Each method on `DebugClient` maps to a `DebuggerRequest`, sends it over TCP,
//! and converts the `DebuggerResponse` into Lua values.

use std::cell::RefCell;

use mlua::prelude::*;

use crate::interfaces::{Architecture, ModuleSymbol};
use crate::protocol::*;

use super::colors;
use super::debug_client::*;
use super::repl::Repl;

/// Wrapper around DebugClient stored as Lua UserData.
/// Uses RefCell for interior mutability since mlua UserData methods get &self.
pub struct LuaDebugClient {
    pub inner: RefCell<DebugClient>,
}

impl LuaDebugClient {
    pub fn new(client: DebugClient) -> Self {
        Self {
            inner: RefCell::new(client),
        }
    }
}

impl LuaUserData for LuaDebugClient {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        // ---- Process lifecycle ----

        methods.add_method("launch", |_lua, this, (command, debug_children, working_directory, env): (String, Option<bool>, Option<String>, Option<LuaTable>)| {
            let mut client = this.inner.borrow_mut();
            // Optional `{NAME = "value"}` table of extra environment variables.
            let environment = match env {
                Some(t) => Some(t.pairs::<String, String>().collect::<mlua::Result<Vec<_>>>()?),
                None => None,
            };
            // Launch just sends the request. Events start flowing through the stream.
            // Call dbg:run() to enter the event loop.
            client.send_request_only(&DebuggerRequest::Launch {
                command,
                debug_children: debug_children.unwrap_or(false),
                working_directory,
                environment,
            }).map_err(|e| mlua::Error::external(e))?;
            Ok(())
        });

        methods.add_method("attach", |_lua, this, pid: u32| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::Attach { pid })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::Ack => Ok(()),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("Attach failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("detach", |_lua, this, pid: u32| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::Detach { pid })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::Ack => Ok(()),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("Detach failed: {}", message),
                )),
                _ => Ok(()),
            }
        });

        methods.add_method("terminate", |_lua, this, pid: u32| {
            let mut client = this.inner.borrow_mut();
            let _ = client.send_and_receive(&DebuggerRequest::TerminateProcess { pid });
            Ok(())
        });

        // ---- Thread control ----
        fn ack_method(name: &'static str, resp: anyhow::Result<DebuggerResponse>) -> mlua::Result<()> {
            crate::protocol_io::expect_ack(name, resp.map_err(mlua::Error::external)?)
                .map_err(mlua::Error::external)
        }

        methods.add_method("suspend_thread", |_lua, this, (pid, tid): (u32, u32)| {
            let mut client = this.inner.borrow_mut();
            ack_method("SuspendThread", client.send_and_receive(&DebuggerRequest::SuspendThread { pid, tid }))
        });

        methods.add_method("resume_thread", |_lua, this, (pid, tid): (u32, u32)| {
            let mut client = this.inner.borrow_mut();
            ack_method("ResumeThread", client.send_and_receive(&DebuggerRequest::ResumeThread { pid, tid }))
        });

        methods.add_method("terminate_thread", |_lua, this, (pid, tid, exit_code): (u32, u32, Option<u32>)| {
            let mut client = this.inner.borrow_mut();
            let req = DebuggerRequest::TerminateThread { pid, tid, exit_code: exit_code.unwrap_or(0) };
            ack_method("TerminateThread", client.send_and_receive(&req))
        });

        methods.add_method("break_into", |_lua, this, pid: u32| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::BreakInto { pid })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::Ack => Ok(()),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("BreakInto failed: {}", message),
                )),
                _ => Ok(()),
            }
        });

        // ---- Event loop ----
        // Three-phase event handling to avoid RefCell double-borrow:
        // 1. Borrow to receive event + determine action (releases borrow)
        // 2. Call Lua handlers (no borrow held — handlers can call dbg:get_context etc.)
        // 3. Re-borrow to send Continue

        methods.add_method("run", |lua, this, ()| {
            use super::debug_client::{EventAction, HandlerType};
            // Sync color state from Lua
            let color_on = lua.globals().get::<bool>("_jlua_color").unwrap_or(false);
            colors::set_enabled(color_on);
            let mut repl = Repl::new();
            loop {
                // Phase 1: receive event and determine action
                let (_event, action) = {
                    let mut client = this.inner.borrow_mut();
                    match client.receive_event() {
                        Ok(Some(event)) => {
                            let action = client.prepare_event(&event);
                            (Some(event), action)
                        }
                        Ok(None) => continue, // non-event, retry
                        Err(e) => return Err(mlua::Error::external(e)),
                    }
                };
                // Borrow is now released

                // Phase 2: execute action (call Lua handlers, enter REPL, etc.)
                let mut should_continue = true;
                let mut exited_root = false;
                let mut pass_exception = false;
                let (continue_pid, continue_tid) = match &action {
                    EventAction::InitialBreakpoint { pid, tid, address, has_handler, repl_on_break } => {
                        if *has_handler {
                            let key = this.inner.borrow().handlers.on_initial_breakpoint.as_ref()
                                .map(|k| lua.registry_value::<LuaFunction>(k)).transpose()?;
                            if let Some(func) = key {
                                func.call::<()>((*pid, *tid, *address))?;
                            }
                        }
                        let wants_repl = this.inner.borrow().wants_repl;
                        if wants_repl {
                            this.inner.borrow_mut().wants_repl = false;
                            let sym = this.inner.borrow_mut().format_address(*pid, *address);
                            eprintln!("Initial breakpoint at {} {}", colors::sym(&sym), colors::dim(&format!("(pid={}, tid={})", pid, tid)));
                            repl.run_break_repl(lua, &this.inner)?;
                        } else if !*has_handler && *repl_on_break {
                            let sym = this.inner.borrow_mut().format_address(*pid, *address);
                            eprintln!("Initial breakpoint at {} {}", colors::sym(&sym), colors::dim(&format!("(pid={}, tid={})", pid, tid)));
                            repl.run_break_repl(lua, &this.inner)?;
                        }
                        (*pid, *tid)
                    }
                    EventAction::Breakpoint { pid, tid, address, has_handler, repl_on_break } => {
                        let mut handled = false;
                        if *has_handler {
                            let key = this.inner.borrow().handlers.breakpoint_handlers.get(address)
                                .map(|k| lua.registry_value::<LuaFunction>(k)).transpose()?;
                            if let Some(func) = key {
                                let decision: Option<String> = func.call((*pid, *tid, *address))?;
                                handled = true;
                                if decision.as_deref() == Some("remove") {
                                    let mut client = this.inner.borrow_mut();
                                    client.handlers.breakpoint_handlers.remove(address);
                                    let _ = client.send_and_receive(&DebuggerRequest::RemoveBreakpoint {
                                        pid: *pid, addr: *address,
                                    });
                                }
                            }
                        }
                        let wants_repl = this.inner.borrow().wants_repl;
                        if wants_repl {
                            this.inner.borrow_mut().wants_repl = false;
                            if !handled {
                                let sym = this.inner.borrow_mut().format_address(*pid, *address);
                                eprintln!("Breakpoint at {} {}", colors::sym(&sym), colors::dim(&format!("(pid={}, tid={})", pid, tid)));
                            }
                            repl.run_break_repl(lua, &this.inner)?;
                        } else if !handled && *repl_on_break {
                            let sym = this.inner.borrow_mut().format_address(*pid, *address);
                            eprintln!("Breakpoint at {} {}", colors::sym(&sym), colors::dim(&format!("(pid={}, tid={})", pid, tid)));
                            repl.run_break_repl(lua, &this.inner)?;
                        }
                        (*pid, *tid)
                    }
                    EventAction::HwBreakpoint { pid, tid, address, has_handler, repl_on_break, dr_index, bp_type } => {
                        let mut handled = false;
                        if *has_handler {
                            let key = this.inner.borrow().handlers.hw_breakpoint_handlers.get(address)
                                .map(|k| lua.registry_value::<LuaFunction>(k)).transpose()?;
                            if let Some(func) = key {
                                let decision: Option<String> = func.call((*pid, *tid, *address))?;
                                handled = true;
                                if decision.as_deref() == Some("remove") {
                                    let mut client = this.inner.borrow_mut();
                                    client.handlers.hw_breakpoint_handlers.remove(address);
                                    let _ = client.send_and_receive(&DebuggerRequest::RemoveHardwareBreakpoint {
                                        pid: *pid, addr: *address,
                                    });
                                }
                            }
                        }
                        let wants_repl = this.inner.borrow().wants_repl;
                        if wants_repl {
                            this.inner.borrow_mut().wants_repl = false;
                            if !handled {
                                let sym = this.inner.borrow_mut().format_address(*pid, *address);
                                eprintln!("Hardware breakpoint at {} {}",
                                    colors::sym(&sym), colors::dim(&format!("(dr={}, type={:?}, pid={}, tid={})", dr_index, bp_type, pid, tid)));
                            }
                            repl.run_break_repl(lua, &this.inner)?;
                        } else if !handled && *repl_on_break {
                            let sym = this.inner.borrow_mut().format_address(*pid, *address);
                            eprintln!("Hardware breakpoint at {} {}",
                                colors::sym(&sym), colors::dim(&format!("(dr={}, type={:?}, pid={}, tid={})", dr_index, bp_type, pid, tid)));
                            repl.run_break_repl(lua, &this.inner)?;
                        }
                        (*pid, *tid)
                    }
                    EventAction::SingleShotBreakpoint { pid, tid, address, has_handler } => {
                        if *has_handler {
                            let key = this.inner.borrow_mut().handlers.single_shot_handlers.remove(address)
                                .map(|k| lua.registry_value::<LuaFunction>(&k)).transpose()?;
                            if let Some(func) = key {
                                func.call::<()>((*pid, *tid, *address))?;
                            }
                        }
                        let wants_repl = this.inner.borrow().wants_repl;
                        if wants_repl {
                            this.inner.borrow_mut().wants_repl = false;
                            repl.run_break_repl(lua, &this.inner)?;
                        }
                        (*pid, *tid)
                    }
                    EventAction::Exception { pid, tid, code, address, first_chance, has_handler, repl_on_break } => {
                        if *has_handler {
                            let key = this.inner.borrow().handlers.on_exception.as_ref()
                                .map(|k| lua.registry_value::<LuaFunction>(k)).transpose()?;
                            if let Some(func) = key {
                                let action: Option<String> = func.call((*pid, *tid, *code, *address, *first_chance))?;
                                match action.as_deref() {
                                    Some("stop") => {
                                        let sym = this.inner.borrow_mut().format_address(*pid, *address);
                                        eprintln!("Exception {} at {} {}",
                                            colors::red(&format!("0x{:08X}", code)), colors::sym(&sym),
                                            colors::dim(&format!("(first_chance={}, pid={}, tid={})", first_chance, pid, tid)));
                                        repl.run_break_repl(lua, &this.inner)?;
                                    }
                                    Some("pass") => pass_exception = true,
                                    _ => {}
                                }
                            }
                        } else if *repl_on_break {
                            let sym = this.inner.borrow_mut().format_address(*pid, *address);
                            eprintln!("Exception {} at {} {}",
                                colors::red(&format!("0x{:08X}", code)), colors::sym(&sym),
                                colors::dim(&format!("(first_chance={}, pid={}, tid={})", first_chance, pid, tid)));
                            repl.run_break_repl(lua, &this.inner)?;
                        }
                        (*pid, *tid)
                    }
                    EventAction::ProcessExited { pid, tid, exit_code, is_root, has_handler } => {
                        eprintln!("{}", colors::dim(&format!("Process {} exited with code {}", pid, exit_code)));
                        if *has_handler {
                            let key = this.inner.borrow().handlers.on_process_exited.as_ref()
                                .map(|k| lua.registry_value::<LuaFunction>(k)).transpose()?;
                            if let Some(func) = key {
                                func.call::<()>((*pid, *exit_code))?;
                            }
                        }
                        if *is_root {
                            should_continue = false;
                            exited_root = true;
                        }
                        (*pid, *tid)
                    }
                    EventAction::AutoContinue { pid, tid, handler_type } => {
                        if let Some(ht) = handler_type {
                            match ht {
                                HandlerType::DllLoaded { name, base } => {
                                    let key = this.inner.borrow().handlers.on_dll_loaded.as_ref()
                                        .map(|k| lua.registry_value::<LuaFunction>(k)).transpose()?;
                                    if let Some(func) = key {
                                        func.call::<()>((*pid, *tid, name.clone(), *base))?;
                                    }
                                }
                                HandlerType::DllUnloaded { base } => {
                                    let key = this.inner.borrow().handlers.on_dll_unloaded.as_ref()
                                        .map(|k| lua.registry_value::<LuaFunction>(k)).transpose()?;
                                    if let Some(func) = key {
                                        func.call::<()>((*pid, *tid, *base))?;
                                    }
                                }
                                HandlerType::ProcessCreated { name, base } => {
                                    let key = this.inner.borrow().handlers.on_process_created.as_ref()
                                        .map(|k| lua.registry_value::<LuaFunction>(k)).transpose()?;
                                    if let Some(func) = key {
                                        func.call::<()>((*pid, *tid, name.clone(), *base))?;
                                    }
                                }
                                HandlerType::ThreadCreated { start } => {
                                    let key = this.inner.borrow().handlers.on_thread_created.as_ref()
                                        .map(|k| lua.registry_value::<LuaFunction>(k)).transpose()?;
                                    if let Some(func) = key {
                                        func.call::<()>((*pid, *tid, *start))?;
                                    }
                                }
                                HandlerType::ThreadExited { exit_code } => {
                                    let key = this.inner.borrow().handlers.on_thread_exited.as_ref()
                                        .map(|k| lua.registry_value::<LuaFunction>(k)).transpose()?;
                                    if let Some(func) = key {
                                        func.call::<()>((*pid, *tid, *exit_code))?;
                                    }
                                }
                            }
                        }
                        (*pid, *tid)
                    }
                };

                if !should_continue {
                    // The root process's exit event is still outstanding; release it
                    // so the dead target isn't kept alive by the server's handles.
                    if exited_root {
                        this.inner.borrow_mut().finalize_exited_process(continue_pid, continue_tid);
                    }
                    break;
                }

                // Phase 3: continue the process
                this.inner.borrow_mut().do_continue(continue_pid, continue_tid, pass_exception)?;
            }
            Ok(())
        });

        // ---- REPL trigger (sets flag, checked by event loop after handler returns) ----

        methods.add_method("repl", |_lua, this, ()| {
            let mut client = this.inner.borrow_mut();
            client.wants_repl = true;
            Ok(())
        });

        // ---- Event handlers ----

        methods.add_method("on_initial_breakpoint", |lua, this, func: LuaFunction| {
            let key = lua.create_registry_value(func)?;
            let mut client = this.inner.borrow_mut();
            client.handlers.on_initial_breakpoint = Some(key);
            Ok(())
        });

        methods.add_method("on_dll_loaded", |lua, this, func: LuaFunction| {
            let key = lua.create_registry_value(func)?;
            let mut client = this.inner.borrow_mut();
            client.handlers.on_dll_loaded = Some(key);
            Ok(())
        });

        methods.add_method("on_dll_unloaded", |lua, this, func: LuaFunction| {
            let key = lua.create_registry_value(func)?;
            let mut client = this.inner.borrow_mut();
            client.handlers.on_dll_unloaded = Some(key);
            Ok(())
        });

        methods.add_method("on_exception", |lua, this, func: LuaFunction| {
            let key = lua.create_registry_value(func)?;
            let mut client = this.inner.borrow_mut();
            client.handlers.on_exception = Some(key);
            Ok(())
        });

        methods.add_method("on_process_exited", |lua, this, func: LuaFunction| {
            let key = lua.create_registry_value(func)?;
            let mut client = this.inner.borrow_mut();
            client.handlers.on_process_exited = Some(key);
            Ok(())
        });

        methods.add_method("on_process_created", |lua, this, func: LuaFunction| {
            let key = lua.create_registry_value(func)?;
            let mut client = this.inner.borrow_mut();
            client.handlers.on_process_created = Some(key);
            Ok(())
        });

        methods.add_method("on_thread_created", |lua, this, func: LuaFunction| {
            let key = lua.create_registry_value(func)?;
            let mut client = this.inner.borrow_mut();
            client.handlers.on_thread_created = Some(key);
            Ok(())
        });

        methods.add_method("on_thread_exited", |lua, this, func: LuaFunction| {
            let key = lua.create_registry_value(func)?;
            let mut client = this.inner.borrow_mut();
            client.handlers.on_thread_exited = Some(key);
            Ok(())
        });

        // ---- Breakpoints ----

        methods.add_method("set_breakpoint", |lua, this, (pid, addr_or_sym, handler): (u32, LuaValue, Option<LuaFunction>)| {
            let mut client = this.inner.borrow_mut();
            let addr = resolve_addr_or_sym(&mut client, addr_or_sym)?;

            let resp = client.send_and_receive(&DebuggerRequest::SetBreakpoint {
                pid, addr, tid: None,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::Ack => {}
                DebuggerResponse::Error { message } => {
                    return Err(mlua::Error::external(
                        anyhow::anyhow!("SetBreakpoint failed: {}", message),
                    ));
                }
                _ => {}
            }

            // Register Lua handler if provided
            if let Some(func) = handler {
                let key = lua.create_registry_value(func)?;
                client.handlers.breakpoint_handlers.insert(addr, key);
            }

            Ok(addr)
        });

        methods.add_method("remove_breakpoint", |_lua, this, (pid, addr): (u32, u64)| {
            let mut client = this.inner.borrow_mut();
            client.handlers.breakpoint_handlers.remove(&addr);
            let _ = client.send_and_receive(&DebuggerRequest::RemoveBreakpoint { pid, addr });
            Ok(())
        });

        methods.add_method("set_single_shot_breakpoint", |lua, this, (pid, addr_or_sym, handler): (u32, LuaValue, Option<LuaFunction>)| {
            let mut client = this.inner.borrow_mut();
            let addr = resolve_addr_or_sym(&mut client, addr_or_sym)?;

            let resp = client.send_and_receive(&DebuggerRequest::SetSingleShotBreakpoint {
                pid, addr,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::Ack => {}
                DebuggerResponse::Error { message } => {
                    return Err(mlua::Error::external(
                        anyhow::anyhow!("SetSingleShotBreakpoint failed: {}", message),
                    ));
                }
                _ => {}
            }

            if let Some(func) = handler {
                let key = lua.create_registry_value(func)?;
                client.handlers.single_shot_handlers.insert(addr, key);
            }

            Ok(addr)
        });

        methods.add_method("set_hw_breakpoint", |lua, this, (pid, addr, bp_type_str, size_str, handler): (u32, u64, String, Option<String>, Option<LuaFunction>)| {
            let mut client = this.inner.borrow_mut();

            let bp_type = parse_hw_type_str(&bp_type_str, true)?;
            let size = parse_hw_size_str(size_str.as_deref().unwrap_or("1"))?;

            let resp = client.send_and_receive(&DebuggerRequest::SetHardwareBreakpoint {
                pid, addr, bp_type, size,
            }).map_err(|e| mlua::Error::external(e))?;
            let dr_index = match resp {
                DebuggerResponse::HardwareBreakpointSet { dr_index } => dr_index,
                DebuggerResponse::Error { message } => {
                    return Err(mlua::Error::external(
                        anyhow::anyhow!("SetHardwareBreakpoint failed: {}", message),
                    ));
                }
                _ => 0,
            };

            if let Some(func) = handler {
                let key = lua.create_registry_value(func)?;
                client.handlers.hw_breakpoint_handlers.insert(addr, key);
            }

            Ok(dr_index)
        });

        methods.add_method("remove_hw_breakpoint", |_lua, this, (pid, addr): (u32, u64)| {
            let mut client = this.inner.borrow_mut();
            client.handlers.hw_breakpoint_handlers.remove(&addr);
            let _ = client.send_and_receive(&DebuggerRequest::RemoveHardwareBreakpoint { pid, addr });
            Ok(())
        });

        // ---- Stepping ----

        methods.add_method("step_into", |_lua, this, (pid, tid): (Option<u32>, Option<u32>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let tid = tid.or(client.current_tid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current tid")))?;
            client.step_and_wait(pid, tid, StepKind::Into)
        });

        methods.add_method("step_over", |_lua, this, (pid, tid): (Option<u32>, Option<u32>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let tid = tid.or(client.current_tid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current tid")))?;
            client.step_and_wait(pid, tid, StepKind::Over)
        });

        methods.add_method("step_out", |_lua, this, (pid, tid): (Option<u32>, Option<u32>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let tid = tid.or(client.current_tid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current tid")))?;
            client.step_and_wait(pid, tid, StepKind::Out)
        });

        // Step by one source line. `dir` is "into" (default) or "over".
        methods.add_method("step_line", |_lua, this, (dir, pid, tid): (Option<String>, Option<u32>, Option<u32>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let tid = tid.or(client.current_tid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current tid")))?;
            let kind = match dir.as_deref() {
                Some("over") => StepKind::Over,
                _ => StepKind::Into,
            };
            client.step_source_line_and_wait(pid, tid, kind)
        });

        // ---- Memory ----

        methods.add_method("read_memory", |lua, this, (pid, addr, size): (u32, u64, usize)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::ReadMemory {
                pid, address: addr, size,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::MemoryData { data } => Ok(lua.create_string(&data)?),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ReadMemory failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("write_memory", |_lua, this, (pid, addr, data): (u32, u64, LuaString)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::WriteMemory {
                pid, address: addr, data: data.as_bytes().to_vec(),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::WriteAck => Ok(()),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("WriteMemory failed: {}", message),
                )),
                _ => Ok(()),
            }
        });

        // ---- Value freeze (server-side continuous write) ----

        // dbg:freeze_value(pid, addr, data[, interval_ms][, offsets]) -> freeze_id
        // With `offsets` (a pointer chain), `addr` is the static base and the freeze
        // re-follows the chain each tick so it tracks a moving target.
        methods.add_method("freeze_value", |_lua, this, (pid, addr, data, interval_ms, offsets): (u32, u64, LuaString, Option<u64>, Option<Vec<u64>>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::FreezeValueStart {
                pid, address: addr, data: data.as_bytes().to_vec(), interval_ms,
                offsets: offsets.unwrap_or_default(),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::FreezeValueStarted { freeze_id } => Ok(freeze_id),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("FreezeValueStart failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // dbg:update_freeze_value(freeze_id, data)
        methods.add_method("update_freeze_value", |_lua, this, (freeze_id, data): (u64, LuaString)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::FreezeValueUpdate {
                freeze_id, data: data.as_bytes().to_vec(),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::Ack => Ok(()),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("FreezeValueUpdate failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // dbg:unfreeze_value(freeze_id)
        methods.add_method("unfreeze_value", |_lua, this, freeze_id: u64| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::FreezeValueStop {
                freeze_id,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::Ack => Ok(()),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("FreezeValueStop failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // dbg:sleep(ms) — pause the script (useful e.g. to let a freeze thread tick).
        methods.add_method("sleep", |_lua, _this, ms: u64| {
            std::thread::sleep(std::time::Duration::from_millis(ms));
            Ok(())
        });

        methods.add_method("read_string", |_lua, this, (pid, addr, max_len): (u32, u64, Option<usize>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::ReadWideString {
                pid, address: addr, max_len,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::WideStringData { data } => Ok(data),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ReadWideString failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("search_memory", |lua, this, (pid, pattern, max_results): (u32, LuaString, Option<usize>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::SearchMemory {
                pid,
                pattern: pattern.as_bytes().to_vec(),
                max_results: max_results.unwrap_or(100),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::MemorySearchResult { addresses, capped } => {
                    let table = lua.create_table()?;
                    for (i, addr) in addresses.iter().enumerate() {
                        table.set(i + 1, *addr)?;
                    }
                    Ok((table, capped))
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("SearchMemory failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // Convenience: read_u8, read_u16, read_u32, read_u64

        methods.add_method("read_u8", |_lua, this, (pid, addr): (u32, u64)| {
            read_memory_uint(&mut this.inner.borrow_mut(), pid, addr, 1)
        });

        methods.add_method("read_u16", |_lua, this, (pid, addr): (u32, u64)| {
            read_memory_uint(&mut this.inner.borrow_mut(), pid, addr, 2)
        });

        methods.add_method("read_u32", |_lua, this, (pid, addr): (u32, u64)| {
            read_memory_uint(&mut this.inner.borrow_mut(), pid, addr, 4)
        });

        methods.add_method("read_u64", |_lua, this, (pid, addr): (u32, u64)| {
            read_memory_uint(&mut this.inner.borrow_mut(), pid, addr, 8)
        });

        // ---- Registers ----

        methods.add_method("get_context", |lua, this, (pid, tid): (Option<u32>, Option<u32>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let tid = tid.or(client.current_tid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current tid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::GetThreadContext { pid, tid })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::ThreadContext { context } => {
                    context_to_lua_table(lua, &context)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("GetThreadContext failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("set_context", |_lua, this, (pid, tid, ctx_table): (u32, u32, LuaTable)| {
            let mut client = this.inner.borrow_mut();
            // First get the current context to use as a base
            let resp = client.send_and_receive(&DebuggerRequest::GetThreadContext { pid, tid })
                .map_err(|e| mlua::Error::external(e))?;
            let original = match resp {
                DebuggerResponse::ThreadContext { context } => context,
                _ => return Err(mlua::Error::external(anyhow::anyhow!("Failed to get current context"))),
            };

            let new_ctx = lua_table_to_context(&ctx_table, &original)?;
            let resp = client.send_and_receive(&DebuggerRequest::SetThreadContext {
                pid, tid, context: new_ctx,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::SetContextAck => Ok(()),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("SetThreadContext failed: {}", message),
                )),
                _ => Ok(()),
            }
        });

        methods.add_method("get_arguments", |lua, this, (pid, tid, count): (u32, u32, usize)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::GetFunctionArguments {
                pid, tid, count,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::FunctionArguments { arguments } => {
                    let table = lua.create_table()?;
                    for (i, arg) in arguments.iter().enumerate() {
                        table.set(i + 1, *arg)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("GetFunctionArguments failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Symbols ----

        methods.add_method("find_symbol", |lua, this, (name, max_results): (String, Option<usize>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::FindSymbol {
                symbol_name: name,
                max_results: max_results.unwrap_or(10),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::ResolvedSymbolList { symbols } => {
                    let table = lua.create_table()?;
                    for (i, sym) in symbols.iter().enumerate() {
                        table.set(i + 1, resolved_symbol_to_lua_table(lua, sym)?)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("FindSymbol failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("resolve_address", |lua, this, (pid, addr): (u32, u64)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::ResolveAddressToSymbol {
                pid, address: addr,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::AddressSymbol { module_path, symbol, offset } => {
                    address_symbol_to_lua_table(lua, module_path, symbol, offset)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ResolveAddress failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("try_resolve_addresses", |lua, this, (pid, addrs): (u32, Vec<u64>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::TryResolveAddressesToSymbols {
                pid, addresses: addrs,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::AddressSymbolBatch { results } => {
                    // One table per input address, in order; an unresolved (or
                    // still-loading) address yields an EMPTY table, never a hole,
                    // so `#table` stays the input length.
                    let table = lua.create_table()?;
                    for (i, result) in results.into_iter().enumerate() {
                        let entry = match result {
                            Some((module, sym, offset)) =>
                                address_symbol_to_lua_table(lua, Some(module), Some(sym), Some(offset))?,
                            None => lua.create_table()?,
                        };
                        table.set(i + 1, entry)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("TryResolveAddresses failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("symbols_in_range", |lua, this, (pid, start, len, max_results): (u32, u64, u64, Option<usize>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::SymbolsInRange {
                pid, start, len, max_results: max_results.unwrap_or(1000),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::ResolvedSymbolList { symbols } => {
                    let table = lua.create_table()?;
                    for (i, sym) in symbols.iter().enumerate() {
                        table.set(i + 1, resolved_symbol_to_lua_table(lua, sym)?)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("SymbolsInRange failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("list_symbols", |lua, this, module_path: String| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::ListSymbols {
                module_path,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::SymbolList { symbols } => {
                    let table = lua.create_table()?;
                    for (i, sym) in symbols.iter().enumerate() {
                        let st = lua.create_table()?;
                        st.set("name", sym.name.as_str())?;
                        st.set("rva", sym.rva as u64)?;
                        st.set("is_function", sym.is_function)?;
                        table.set(i + 1, st)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ListSymbols failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("resolve_rva", |lua, this, (module_path, rva): (String, u32)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::ResolveRvaToSymbol {
                module_path, rva,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::AddressSymbol { module_path, symbol, offset } => {
                    address_symbol_to_lua_table(lua, module_path, symbol, offset)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ResolveRvaToSymbol failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("symbol_status", |lua, this, pid: Option<u32>| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::GetSymbolStatus { pid })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::SymbolStatusList { statuses } => {
                    let table = lua.create_table()?;
                    for (i, status) in statuses.iter().enumerate() {
                        let st = lua.create_table()?;
                        st.set("module", status.module_path.as_str())?;
                        st.set("base", status.module_base)?;
                        match &status.state {
                            SymbolLoadState::Loaded { symbol_count } => {
                                st.set("state", "loaded")?;
                                st.set("symbol_count", *symbol_count)?;
                            }
                            SymbolLoadState::ExportsOnly { export_count, error } => {
                                st.set("state", "exports_only")?;
                                st.set("symbol_count", *export_count)?;
                                st.set("error", error.as_str())?;
                            }
                            SymbolLoadState::Loading => st.set("state", "loading")?,
                            SymbolLoadState::Failed { error } => {
                                st.set("state", "failed")?;
                                st.set("error", error.as_str())?;
                            }
                            SymbolLoadState::NotRequested => st.set("state", "not_requested")?,
                        }
                        if let Some(pdb_path) = &status.pdb_path {
                            st.set("pdb_path", pdb_path.as_str())?;
                        }
                        table.set(i + 1, st)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("GetSymbolStatus failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("load_pdb", |lua, this, (pid, module_base, pdb_path, force): (u32, u64, String, Option<bool>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::LoadPdbFromPath {
                pid, module_base, pdb_path, force: force.unwrap_or(false),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::PdbLoaded { symbol_count, .. } => {
                    let table = lua.create_table()?;
                    table.set("loaded", true)?;
                    table.set("symbol_count", symbol_count)?;
                    Ok(table)
                }
                DebuggerResponse::PdbMismatch(info) => {
                    let table = lua.create_table()?;
                    table.set("loaded", false)?;
                    let mismatch = lua.create_table()?;
                    mismatch.set("pe_guid", info.pe_guid)?;
                    mismatch.set("pe_age", info.pe_age)?;
                    mismatch.set("pdb_guid", info.pdb_guid)?;
                    mismatch.set("pdb_age", info.pdb_age)?;
                    table.set("mismatch", mismatch)?;
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("LoadPdbFromPath failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("retry_symbols", |_lua, this, (pid, module_base): (u32, u64)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::RetrySymbolLoad { pid, module_base })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::Ack => Ok(true),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("RetrySymbolLoad failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("unload_symbols", |_lua, this, (pid, module_base): (u32, u64)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::UnloadModuleSymbols { pid, module_base })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::Ack => Ok(true),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("UnloadModuleSymbols failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("set_symbol_deny_list", |_lua, this, modules: Vec<String>| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::SetSymbolDenyList { modules })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::Ack => Ok(true),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("SetSymbolDenyList failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Types (PDB TPI stream) ----

        methods.add_method("list_types", |lua, this, (filter, pid, module_base, max_results): (Option<String>, Option<u32>, Option<u64>, Option<usize>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::ListTypes {
                pid, module_base, filter, max_results: max_results.unwrap_or(1000),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::TypeList { types } => {
                    let table = lua.create_table()?;
                    for (i, t) in types.iter().enumerate() {
                        let st = lua.create_table()?;
                        st.set("name", t.name.as_str())?;
                        st.set("size", t.size as u64)?;
                        st.set("index", t.index as u64)?;
                        st.set("module_base", t.module_base)?;
                        st.set("module", t.module_name.as_str())?;
                        table.set(i + 1, st)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ListTypes failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("get_type", |lua, this, (name, pid, module_base): (String, Option<u32>, Option<u64>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::GetType {
                pid, module_base, name,
            }).map_err(|e| mlua::Error::external(e))?;
            type_result_to_lua(lua, resp, "GetType")
        });

        methods.add_method("get_type_by_index", |lua, this, (module_base, index, pid): (u64, u32, Option<u32>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::GetTypeByIndex {
                pid, module_base, index,
            }).map_err(|e| mlua::Error::external(e))?;
            type_result_to_lua(lua, resp, "GetTypeByIndex")
        });

        methods.add_method("get_teb_address", |_lua, this, (tid, pid): (u32, Option<u32>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::GetTebAddress { pid, tid })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::TebAddress { address } => Ok(address),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("GetTebAddress failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("get_peb_address", |_lua, this, pid: Option<u32>| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::GetPebAddress { pid })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::PebAddress { address } => Ok(address),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("GetPebAddress failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Source lines (PDB line tables) ----

        methods.add_method("resolve_line", |lua, this, (pid, addr): (u32, u64)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::ResolveAddressToLine {
                pid, address: addr,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::AddressLine { info } => {
                    match info {
                        Some(info) => {
                            let table = lua.create_table()?;
                            table.set("module", info.module_path.as_str())?;
                            table.set("module_base", info.module_base)?;
                            table.set("rva", info.rva as u64)?;
                            table.set("file", info.file.path.as_str())?;
                            table.set("checksum_kind", info.file.checksum_kind.as_str())?;
                            table.set("checksum", info.file.checksum.as_str())?;
                            table.set("line", info.line_entry.line_start)?;
                            table.set("line_end", info.line_entry.line_end)?;
                            table.set("length", info.line_entry.length as u64)?;
                            Ok(mlua::Value::Table(table))
                        }
                        None => Ok(mlua::Value::Nil),
                    }
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ResolveAddressToLine failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("line_map", |lua, this, (pid, module_base, file_path, start_line, end_line): (u32, u64, String, Option<u32>, Option<u32>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::GetSourceFileLineMap {
                pid, module_base, file_path, start_line, end_line,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::SourceFileLineMap { file: _, entries } => {
                    let table = lua.create_table()?;
                    for (i, entry) in entries.iter().enumerate() {
                        let et = lua.create_table()?;
                        et.set("rva", entry.rva as u64)?;
                        et.set("length", entry.length as u64)?;
                        et.set("line", entry.line_start)?;
                        et.set("line_end", entry.line_end)?;
                        table.set(i + 1, et)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("GetSourceFileLineMap failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("source_files", |lua, this, (pid, module_base): (u32, u64)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::ListSourceFiles { pid, module_base })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::SourceFileList { files } => {
                    let table = lua.create_table()?;
                    for (i, file) in files.iter().enumerate() {
                        let ft = lua.create_table()?;
                        ft.set("path", file.path.as_str())?;
                        ft.set("checksum_kind", file.checksum_kind.as_str())?;
                        ft.set("checksum", file.checksum.as_str())?;
                        table.set(i + 1, ft)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ListSourceFiles failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Disassembly ----

        methods.add_method("disassemble", |lua, this, (pid, addr, count): (u32, u64, Option<usize>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::DisassembleMemory {
                pid, address: addr, count: count.unwrap_or(10),
                arch: Architecture::from_native(),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::Instructions { instructions } => {
                    let table = lua.create_table()?;
                    for (i, inst) in instructions.iter().enumerate() {
                        table.set(i + 1, instruction_to_lua_table(lua, inst)?)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("Disassemble failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("disassemble_function", |lua, this, (pid, addr, max): (u32, u64, Option<usize>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::DisassembleFunction {
                pid, address: addr, max_instructions: max.unwrap_or(1000),
                arch: Architecture::from_native(),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::FunctionDisassembly { instructions, function_start, function_end, function_name } => {
                    let result = lua.create_table()?;
                    let insts_table = lua.create_table()?;
                    for (i, inst) in instructions.iter().enumerate() {
                        insts_table.set(i + 1, instruction_to_lua_table(lua, inst)?)?;
                    }
                    result.set("instructions", insts_table)?;
                    if let Some(start) = function_start { result.set("start", start)?; }
                    if let Some(end) = function_end { result.set("end", end)?; }
                    if let Some(name) = function_name { result.set("name", name)?; }
                    Ok(result)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("DisassembleFunction failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("disassemble_backward", |lua, this, (pid, target, count): (u32, u64, Option<usize>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::DisassembleBackward {
                pid, target, count: count.unwrap_or(10),
                arch: Architecture::from_native(),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::Instructions { instructions } => {
                    let table = lua.create_table()?;
                    for (i, inst) in instructions.iter().enumerate() {
                        table.set(i + 1, instruction_to_lua_table(lua, inst)?)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("DisassembleBackward failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Call stack ----

        methods.add_method("get_call_stack", |lua, this, (pid, tid): (Option<u32>, Option<u32>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let tid = tid.or(client.current_tid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current tid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::GetCallStack { pid, tid })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::CallStack { frames } => {
                    let table = lua.create_table()?;
                    for (i, frame) in frames.iter().enumerate() {
                        table.set(i + 1, callframe_to_lua_table(lua, frame)?)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("GetCallStack failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Module/Thread/Process listing ----

        methods.add_method("list_modules", |lua, this, pid: u32| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::ListModules { pid })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::ModuleList { modules: mods } => {
                    let table = lua.create_table()?;
                    for (i, m) in mods.iter().enumerate() {
                        table.set(i + 1, module_to_lua_table(lua, m)?)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ListModules failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // Instruction-set architecture of the debuggee: "x86" (WOW64), "x64" or "arm64".
        methods.add_method("arch", |_lua, this, pid: u32| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::GetProcessArchitecture { pid })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::ProcessArchitecture { arch } => Ok(match arch {
                    crate::interfaces::Architecture::X86 => "x86",
                    crate::interfaces::Architecture::X64 => "x64",
                    crate::interfaces::Architecture::Arm64 => "arm64",
                }.to_string()),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("GetProcessArchitecture failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("list_threads", |lua, this, pid: u32| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::ListThreads { pid })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::ThreadList { threads } => {
                    let table = lua.create_table()?;
                    for (i, t) in threads.iter().enumerate() {
                        let tt = lua.create_table()?;
                        tt.set("tid", t.tid)?;
                        tt.set("start_address", t.start_address)?;
                        tt.set("suspend_count", t.suspend_count)?;
                        table.set(i + 1, tt)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ListThreads failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // Handles, windows, TCP connections and privileges of a process
        // (the Handles window). Returns a table with `handles`, `windows`,
        // `tcp_connections`, `privileges`, `desktop_window`, `warnings`.
        methods.add_method("process_objects", |lua, this, pid: u32| {
            let mut client = this.inner.borrow_mut();
            match client.send_and_receive(&DebuggerRequest::ListProcessObjects { pid })
                .map_err(mlua::Error::external)? {
                DebuggerResponse::ProcessObjects { objects } => process_objects_to_lua_table(lua, &objects),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ListProcessObjects failed: {}", message))),
                other => Err(mlua::Error::external(
                    anyhow::anyhow!("Unexpected response to ListProcessObjects: {:?}", other))),
            }
        });

        methods.add_method("close_remote_handle", |_lua, this, (pid, handle): (u32, u64)| {
            let mut client = this.inner.borrow_mut();
            ack_method("CloseRemoteHandle", client.send_and_receive(&DebuggerRequest::CloseRemoteHandle { pid, handle }))
        });

        methods.add_method("set_privilege", |_lua, this, (pid, name, enable): (u32, String, bool)| {
            let mut client = this.inner.borrow_mut();
            ack_method("SetPrivilege", client.send_and_receive(&DebuggerRequest::SetPrivilege { pid, name, enable }))
        });

        methods.add_method("set_window_enabled", |_lua, this, (pid, hwnd, enabled): (u32, u64, bool)| {
            let mut client = this.inner.borrow_mut();
            ack_method("SetWindowEnabled", client.send_and_receive(&DebuggerRequest::SetWindowEnabled { pid, hwnd, enabled }))
        });

        methods.add_method("list_processes", |lua, this, ()| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::ListProcesses)
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::ProcessList { processes } => {
                    let table = lua.create_table()?;
                    for (i, p) in processes.iter().enumerate() {
                        let pt = lua.create_table()?;
                        pt.set("pid", p.pid)?;
                        pt.set("name", p.name.as_str())?;
                        table.set(i + 1, pt)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ListProcesses failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Memory regions ----

        methods.add_method("query_memory", |lua, this, (pid, addr): (u32, u64)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::QueryMemoryRegion {
                pid, address: addr,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::MemoryRegionInfo { info } => {
                    region_to_lua_table(lua, &info)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("QueryMemoryRegion failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("enumerate_regions", |lua, this, pid: u32| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::EnumerateMemoryRegions { pid })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::MemoryRegionList { regions } => {
                    let table = lua.create_table()?;
                    for (i, r) in regions.iter().enumerate() {
                        table.set(i + 1, region_to_lua_table(lua, &r)?)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("EnumerateMemoryRegions failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Dereference ----

        // probe_start (default true): `addr` is a pointer whose target is described
        // first (registers). Pass false for a memory slot so only its stored value
        // is followed — see PlatformAPI::dereference.
        methods.add_method("dereference", |lua, this, (pid, addr, count, ref_base, probe_start): (u32, u64, Option<usize>, Option<u64>, Option<bool>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::Dereference {
                pid, address: addr, count: count.unwrap_or(1), reference_base: ref_base,
                probe_start: probe_start.unwrap_or(true),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::DereferenceResult { entries } => {
                    let table = lua.create_table()?;
                    for (i, entry) in entries.iter().enumerate() {
                        table.set(i + 1, deref_entry_to_lua_table(lua, entry)?)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("Dereference failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("dereference_batch", |lua, this, (pid, addrs, count, ref_base, probe_start): (u32, Vec<u64>, Option<usize>, Option<u64>, Option<bool>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::DereferenceBatch {
                pid, addresses: addrs, count: count.unwrap_or(1), reference_base: ref_base,
                probe_start: probe_start.unwrap_or(true),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::DereferenceBatchResult { results } => {
                    // One inner table (list of entries) per input address, in order.
                    let table = lua.create_table()?;
                    for (i, entries) in results.iter().enumerate() {
                        let inner = lua.create_table()?;
                        for (j, entry) in entries.iter().enumerate() {
                            inner.set(j + 1, deref_entry_to_lua_table(lua, entry)?)?;
                        }
                        table.set(i + 1, inner)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("DereferenceBatch failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Module extra info ----

        methods.add_method("get_module_info", |lua, this, (pid, base): (u32, u64)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::GetModuleExtraInfo {
                pid, module_base: base,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::ModuleExtraInfo { info } => {
                    let table = lua.create_table()?;
                    table.set("nt_signature", info.nt_headers.Signature as u64)?;
                    table.set("entry_point", info.nt_headers.OptionalHeader.AddressOfEntryPoint as u64)?;
                    table.set("image_base", info.nt_headers.OptionalHeader.ImageBase)?;
                    table.set("size_of_image", info.nt_headers.OptionalHeader.SizeOfImage as u64)?;
                    // Sections
                    let sections = lua.create_table()?;
                    for (i, sec) in info.sections.iter().enumerate() {
                        let st = lua.create_table()?;
                        st.set("name", sec.name_string())?;
                        st.set("virtual_address", sec.VirtualAddress as u64)?;
                        st.set("virtual_size", sec.VirtualSize as u64)?;
                        st.set("raw_data_size", sec.SizeOfRawData as u64)?;
                        sections.set(i + 1, st)?;
                    }
                    table.set("sections", sections)?;
                    // TLS callbacks (RVAs)
                    let tls = lua.create_table()?;
                    for (i, rva) in info.tls_callbacks.iter().enumerate() {
                        tls.set(i + 1, *rva as u64)?;
                    }
                    table.set("tls_callbacks", tls)?;
                    // Runtime functions (Exception Directory)
                    if let Some(ref rfs) = info.runtime_functions {
                        let rf_table = lua.create_table()?;
                        for (i, rf) in rfs.iter().enumerate() {
                            let entry = lua.create_table()?;
                            entry.set("begin_address", rf.BeginAddress as u64)?;
                            entry.set("end_address", rf.EndAddress as u64)?;
                            entry.set("unwind_data", rf.UnwindData as u64)?;
                            rf_table.set(i + 1, entry)?;
                        }
                        table.set("runtime_functions", rf_table)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("GetModuleExtraInfo failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Tracing & Emulation ----

        methods.add_method("trace", |lua, this, (pid, tid, max, exit_addr): (u32, u32, Option<usize>, Option<u64>)| {
            let mut client = this.inner.borrow_mut();
            let exit_condition = if let Some(addr) = exit_addr {
                TraceExitCondition::ReachAddress(addr)
            } else {
                TraceExitCondition::InstructionLimit(max.unwrap_or(1000))
            };
            let resp = client.send_and_receive(&DebuggerRequest::TraceInstructions {
                pid, tid,
                exit_condition,
                max_instructions: max.unwrap_or(1000),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::TenetTrace { trace_text, stop_reason, trace_time_us, stats_text, .. } => {
                    let table = lua.create_table()?;
                    table.set("trace", trace_text)?;
                    table.set("stop_reason", stop_reason)?;
                    table.set("time_us", trace_time_us)?;
                    table.set("stats", stats_text)?;
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("Trace failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("emulate", |lua, this, (pid, tid, max, mode_str, exit_addr, mem_reads_tbl): (u32, u32, Option<usize>, Option<String>, Option<u64>, Option<LuaTable>)| {
            let mut client = this.inner.borrow_mut();
            let mode = match mode_str.as_deref().unwrap_or("basic") {
                "basic" => EmulationMode::Basic,
                "trace" => EmulationMode::InstructionTrace,
                "block" => EmulationMode::BasicBlock,
                "module" => EmulationMode::ModuleTransition,
                "syscall" => EmulationMode::Syscall,
                s => return Err(mlua::Error::external(
                    anyhow::anyhow!("Invalid emulation mode: '{}'", s),
                )),
            };
            let exit_condition = exit_addr.map(TraceExitCondition::ReachAddress);

            // Parse memory_reads: table of {address, size} pairs
            let memory_reads = if let Some(tbl) = mem_reads_tbl {
                let mut reads = Vec::new();
                for i in 1..=tbl.raw_len() {
                    if let Ok(entry) = tbl.get::<LuaTable>(i) {
                        let addr: u64 = entry.get(1).or_else(|_| entry.get("address"))?;
                        let size: usize = entry.get(2).or_else(|_| entry.get("size"))?;
                        reads.push((addr, size));
                    }
                }
                reads
            } else {
                vec![]
            };

            let resp = client.send_and_receive(&DebuggerRequest::EmulateInstructions {
                pid, tid,
                max_instructions: max.unwrap_or(1000),
                mode,
                exit_condition,
                memory_reads,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::TenetTrace { trace_text, stop_reason, trace_time_us, stats_text, .. } => {
                    let table = lua.create_table()?;
                    table.set("trace", trace_text)?;
                    table.set("stop_reason", stop_reason)?;
                    table.set("time_us", trace_time_us)?;
                    table.set("stats", stats_text)?;
                    Ok(table)
                }
                DebuggerResponse::EmulationResult { final_pc, instructions_executed, stop_reason, emulation_time_us, pages_loaded, basic_blocks, stats_text, memory_snapshots } => {
                    let table = lua.create_table()?;
                    table.set("final_pc", final_pc)?;
                    table.set("instructions_executed", instructions_executed as u64)?;
                    table.set("stop_reason", stop_reason)?;
                    table.set("time_us", emulation_time_us)?;
                    table.set("pages_loaded", pages_loaded as u64)?;
                    table.set("stats", stats_text)?;
                    if !basic_blocks.is_empty() {
                        let bb = lua.create_table()?;
                        for (i, addr) in basic_blocks.iter().enumerate() {
                            bb.set(i + 1, *addr)?;
                        }
                        table.set("basic_blocks", bb)?;
                    }
                    if !memory_snapshots.is_empty() {
                        let snaps = lua.create_table()?;
                        for (i, (addr, data)) in memory_snapshots.iter().enumerate() {
                            let snap = lua.create_table()?;
                            snap.set("address", *addr)?;
                            snap.set("data", lua.create_string(data)?)?;
                            snaps.set(i + 1, snap)?;
                        }
                        table.set("memory_snapshots", snaps)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("Emulate failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Memory scanning ----

        methods.add_method("scan_start", |lua, this, (pid, value_type_str, compare_str, value_str): (u32, String, String, Option<String>)| {
            let mut client = this.inner.borrow_mut();
            let value_type = parse_scan_value_type(&value_type_str)?;
            let compare_type = parse_scan_compare_type(&compare_str)?;
            let value = value_str.as_deref().map(|v| parse_scan_value(&value_type, v)).transpose()?;

            let resp = client.send_and_receive(&DebuggerRequest::ScanMemoryStart {
                pid, value_type, compare_type, value, value2: None,
                alignment: None, float_tolerance: None, writable_only: Some(true),
                thread_count: None,
            }).map_err(|e| mlua::Error::external(e))?;
            scan_result_to_lua(lua, resp, "ScanMemoryStart")
        });

        methods.add_method("scan_next", |lua, this, (scan_id, compare_str, value_str, value_type_str): (u64, String, Option<String>, Option<String>)| {
            let mut client = this.inner.borrow_mut();
            let compare_type = parse_scan_compare_type(&compare_str)?;
            let value_type = value_type_str.as_deref().map(|s| parse_scan_value_type(s)).transpose()?.unwrap_or(ScanValueType::U64);
            let value = value_str.as_deref().map(|v| parse_scan_value(&value_type, v)).transpose()?;

            let resp = client.send_and_receive(&DebuggerRequest::ScanMemoryNext {
                scan_id, compare_type, value, value2: None, float_tolerance: None,
            }).map_err(|e| mlua::Error::external(e))?;
            scan_result_to_lua(lua, resp, "ScanMemoryNext")
        });

        methods.add_method("scan_results", |lua, this, (scan_id, offset, count): (u64, Option<u64>, Option<u64>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::ScanMemoryGetResults {
                scan_id, offset: offset.unwrap_or(0), count: count.unwrap_or(100),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::ScanMemoryResults { addresses, values: _, total_count } => {
                    let table = lua.create_table()?;
                    let addrs = lua.create_table()?;
                    for (i, a) in addresses.iter().enumerate() {
                        addrs.set(i + 1, *a)?;
                    }
                    table.set("addresses", addrs)?;
                    table.set("total_count", total_count)?;
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("ScanMemoryGetResults failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("scan_reset", |_lua, this, scan_id: u64| {
            let mut client = this.inner.borrow_mut();
            let _ = client.send_and_receive(&DebuggerRequest::ScanMemoryReset { scan_id });
            Ok(())
        });

        // ---- Pointer scanning ----

        // ptr_scan_start(pid, target_address, [max_offset=0x1000], [max_depth=5], [modules])
        // `modules` is an optional list of base module addresses to restrict the
        // static base of returned paths to. -> { results_path, match_count, scan_time_us }
        methods.add_method("ptr_scan_start", |lua, this, (pid, target_address, max_offset, max_depth, modules, writable_only): (u32, u64, Option<u64>, Option<u32>, Option<Vec<u64>>, Option<bool>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::PointerScanStart {
                pid,
                target_address,
                max_offset: max_offset.unwrap_or(0x1000),
                max_depth: max_depth.unwrap_or(5),
                alignment: None,
                max_results: None,
                modules,
                thread_count: None,
                writable_only: writable_only.unwrap_or(false),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::PointerScanResult { results_path, match_count, scan_time_us } => {
                    let table = lua.create_table()?;
                    table.set("results_path", results_path)?;
                    table.set("match_count", match_count)?;
                    table.set("scan_time_us", scan_time_us)?;
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("PointerScanStart failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ptr_scan_results(pid, results_path, [offset=0], [count=100], [offset_filter])
        // `offset_filter` is an optional list of chain offsets; only paths whose
        // offsets contain ALL of them are returned (and total_count reflects that).
        // -> { total_count, paths = { { module_index, module_base, base_offset, offsets={..}, resolved }, .. } }
        methods.add_method("ptr_scan_results", |lua, this, (pid, results_path, offset, count, offset_filter): (u32, String, Option<u64>, Option<u64>, Option<Vec<u64>>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::PointerScanGetResults {
                pid, results_path, offset: offset.unwrap_or(0), count: count.unwrap_or(100),
                offset_filter: offset_filter.unwrap_or_default(),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::PointerScanResults { paths, total_count } => {
                    let table = lua.create_table()?;
                    let path_list = lua.create_table()?;
                    for (i, p) in paths.iter().enumerate() {
                        let pt = lua.create_table()?;
                        pt.set("module_index", p.module_index)?;
                        pt.set("module_base", p.module_base)?;
                        pt.set("base_offset", p.base_offset)?;
                        pt.set("resolved", p.resolved)?;
                        let offs = lua.create_table()?;
                        for (j, o) in p.offsets.iter().enumerate() {
                            offs.set(j + 1, *o)?;
                        }
                        pt.set("offsets", offs)?;
                        path_list.set(i + 1, pt)?;
                    }
                    table.set("paths", path_list)?;
                    table.set("total_count", total_count)?;
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("PointerScanGetResults failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("ptr_scan_reset", |_lua, this, results_path: String| {
            let mut client = this.inner.borrow_mut();
            let _ = client.send_and_receive(&DebuggerRequest::PointerScanReset { results_path });
            Ok(())
        });

        // ptr_scan_apply_filter(results_path, offset_filter)
        // Reduce the file to only paths containing ALL listed offsets; writes a new
        // file (old deleted). -> { results_path, match_count, scan_time_us }
        methods.add_method("ptr_scan_apply_filter", |lua, this, (results_path, offset_filter): (String, Vec<u64>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::PointerScanApplyFilter {
                results_path, offset_filter,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::PointerScanResult { results_path, match_count, scan_time_us } => {
                    let table = lua.create_table()?;
                    table.set("results_path", results_path)?;
                    table.set("match_count", match_count)?;
                    table.set("scan_time_us", scan_time_us)?;
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("PointerScanApplyFilter failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ptr_scan_rescan(pid, results_path, target_address)
        // Keep only paths that still resolve to target_address. -> { results_path, match_count, scan_time_us }
        methods.add_method("ptr_scan_rescan", |lua, this, (pid, results_path, target_address): (u32, String, u64)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::PointerScanRescan {
                pid, results_path, target_address,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::PointerScanResult { results_path, match_count, scan_time_us } => {
                    let table = lua.create_table()?;
                    table.set("results_path", results_path)?;
                    table.set("match_count", match_count)?;
                    table.set("scan_time_us", scan_time_us)?;
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("PointerScanRescan failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- String scanning ----

        // string_scan_start(pid, start_address, size, [min_length=5], [region_filter="readable"], [encodings="both"], [contains=""])
        // Scan [start_address, start_address+size) for printable ASCII/UTF-16
        // strings. `region_filter` is "readable"|"writable"|"executable"|"image"|
        // "mapped"|"private"; `encodings` is "both"|"ascii"|"utf16"; `contains`
        // keeps only strings containing the substring (case-insensitive).
        // -> { results_path, match_count, scan_time_us, capped }
        methods.add_method("string_scan_start", |lua, this, (pid, start_address, size, min_length, region_filter, encodings, contains): (u32, u64, u64, Option<u32>, Option<String>, Option<String>, Option<String>)| {
            let region_filter = region_filter
                .map(|s| s.parse().map_err(mlua::Error::external))
                .transpose()?
                .unwrap_or_default();
            let encodings = encodings
                .map(|s| s.parse().map_err(mlua::Error::external))
                .transpose()?
                .unwrap_or_default();
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::StringScanStart {
                pid, start_address, size,
                min_length: min_length.unwrap_or(5),
                max_results: None,
                thread_count: None,
                region_filter,
                encodings,
                contains: contains.unwrap_or_default(),
            }).map_err(mlua::Error::external)?;
            match resp {
                DebuggerResponse::StringScanResult { results_path, match_count, scan_time_us, capped } => {
                    let table = lua.create_table()?;
                    table.set("results_path", results_path)?;
                    table.set("match_count", match_count)?;
                    table.set("scan_time_us", scan_time_us)?;
                    table.set("capped", capped)?;
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("StringScanStart failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // string_scan_results(results_path, [offset=0], [count=100], [filter=""], [sort="address"], [ascending=true])
        // `sort` is "address", "value", or "length". -> { total_count, strings = { { address, encoding, length, text, truncated }, .. } }
        methods.add_method("string_scan_results", |lua, this, (results_path, offset, count, filter, sort, ascending): (String, Option<u64>, Option<u64>, Option<String>, Option<String>, Option<bool>)| {
            let sort: StringSortKey = sort.as_deref().and_then(|s| s.parse().ok()).unwrap_or_default();
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::StringScanGetResults {
                results_path, offset: offset.unwrap_or(0), count: count.unwrap_or(100),
                filter: filter.unwrap_or_default(), sort, ascending: ascending.unwrap_or(true),
            }).map_err(mlua::Error::external)?;
            match resp {
                DebuggerResponse::StringScanResults { strings, total_count } => {
                    let table = lua.create_table()?;
                    let list = lua.create_table()?;
                    for (i, s) in strings.iter().enumerate() {
                        let st = lua.create_table()?;
                        st.set("address", s.address)?;
                        st.set("encoding", s.encoding.as_str())?;
                        st.set("length", s.length)?;
                        st.set("text", s.text.clone())?;
                        st.set("truncated", s.truncated)?;
                        list.set(i + 1, st)?;
                    }
                    table.set("strings", list)?;
                    table.set("total_count", total_count)?;
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("StringScanGetResults failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        methods.add_method("string_scan_reset", |_lua, this, results_path: String| {
            let mut client = this.inner.borrow_mut();
            let _ = client.send_and_receive(&DebuggerRequest::StringScanReset { results_path });
            Ok(())
        });

        // ---- Code Coverage ----

        // enumerate_coverage_targets(module_path, [pid], [sources])
        //   -> { { address, rva, symbol, source }, .. }
        // Every address in the module worth arming coverage on: `.pdata`
        // RUNTIME_FUNCTION starts unioned with symbols, where symbols the PDB
        // does not mark as functions must pass a code-sanity check first.
        // `symbol` is nil when nothing names the address; `source` is one of
        // "pdata", "function_symbol", "validated_symbol". Works on modules with
        // no symbols at all — feed `address` values straight to start_coverage.
        // `sources` is an optional list of those same strings restricting which
        // tiers contribute; omit it (or pass {}) for all. {"pdata"} gives the
        // exception directory alone, with no heuristics involved.
        methods.add_method("enumerate_coverage_targets", |lua, this, (module_path, pid, sources): (String, Option<u32>, Option<Vec<String>>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let sources = sources.unwrap_or_default().into_iter()
                .map(|s| s.parse::<crate::protocol::CoverageTargetSource>().map_err(mlua::Error::external))
                .collect::<Result<Vec<_>, _>>()?;
            let resp = client.send_and_receive(&DebuggerRequest::EnumerateCoverageTargets { pid, module_path, sources })
                .map_err(mlua::Error::external)?;
            match resp {
                DebuggerResponse::CoverageTargetList { targets } => {
                    let table = lua.create_table()?;
                    for (i, target) in targets.iter().enumerate() {
                        let entry = lua.create_table()?;
                        entry.set("address", target.address)?;
                        entry.set("rva", target.rva)?;
                        entry.set("symbol", target.symbol.clone())?;
                        entry.set("source", target.source.as_str())?;
                        table.set(i + 1, entry)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("EnumerateCoverageTargets failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // start_coverage([pid], addrs, [limit=1])
        // Arm silent, server-side-counted coverage breakpoints on every address in
        // `addrs`. Hits are counted in the server and the debuggee auto-continues
        // without a client event; poll counts with `get_coverage`. `limit` is the
        // hit count after which each breakpoint auto-removes (1 = remove on first
        // hit = pure coverage, >1 = heat map, 0 = never remove).
        methods.add_method("start_coverage", |_lua, this, (pid, addrs, limit): (Option<u32>, Vec<u64>, Option<u64>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::StartCodeCoverage {
                pid, addrs, limit: limit.unwrap_or(1),
            }).map_err(mlua::Error::external)?;
            match resp {
                DebuggerResponse::Ack => Ok(()),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("StartCodeCoverage failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // get_coverage([pid])
        //   -> { { address, hit_count, first_hit_seq, first_hit_us, thread_ids }, .. }
        // One entry per coverage breakpoint hit at least once (never-hit addresses
        // are omitted; the caller knows the armed set). `first_hit_seq` is the
        // 1-based first-execution order across the run (reset by stop_coverage);
        // `first_hit_us` is microseconds from the start of the run to that first
        // hit, so subtracting two entries gives the gap between them (only the
        // first hit is timed — it says nothing about a heat run's repeats);
        // `thread_ids` lists the distinct threads that hit it, in first-hit order.
        methods.add_method("get_coverage", |lua, this, pid: Option<u32>| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::GetCodeCoverage { pid })
                .map_err(mlua::Error::external)?;
            match resp {
                DebuggerResponse::CoverageResults { hits } => {
                    let table = lua.create_table()?;
                    for (i, hit) in hits.iter().enumerate() {
                        let entry = lua.create_table()?;
                        entry.set("address", hit.address)?;
                        entry.set("hit_count", hit.hit_count)?;
                        entry.set("first_hit_seq", hit.first_hit_seq)?;
                        entry.set("first_hit_us", hit.first_hit_us)?;
                        entry.set("thread_ids", hit.thread_ids.clone())?;
                        table.set(i + 1, entry)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("GetCodeCoverage failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // stop_coverage([pid])
        // Remove all coverage breakpoints and clear the coverage map.
        methods.add_method("stop_coverage", |_lua, this, pid: Option<u32>| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::StopCodeCoverage { pid })
                .map_err(mlua::Error::external)?;
            match resp {
                DebuggerResponse::Ack => Ok(()),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("StopCodeCoverage failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Hardware access trace ("find what reads/writes an address") ----

        // start_watchpoint_trace([pid], addr, type, [size="1"])
        // Arm a hardware watchpoint at `addr` in silent "collect accessors" mode:
        // every access is recorded server-side (the accessing instruction) and the
        // target auto-continues instead of breaking. `type` is 'write'/'w' or
        // 'readwrite'/'rw' (x86 cannot trap read-only). Poll with
        // `get_watchpoint_accesses`; tear down with `stop_watchpoint_trace`.
        methods.add_method("start_watchpoint_trace", |_lua, this, (pid, addr, bp_type_str, size_str): (Option<u32>, u64, String, Option<String>)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let bp_type = parse_hw_type_str(&bp_type_str, false)?;
            let size = parse_hw_size_str(size_str.as_deref().unwrap_or("1"))?;
            let resp = client.send_and_receive(&DebuggerRequest::StartWatchpointTrace { pid, addr, bp_type, size })
                .map_err(mlua::Error::external)?;
            match resp {
                DebuggerResponse::Ack => Ok(()),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("StartWatchpointTrace failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // get_watchpoint_accesses([pid], addr) -> { { accessor, accessor_raw_rip, hit_count, first_seq, thread_ids }, .. }
        // One entry per distinct instruction that has accessed `addr`. `accessor`
        // is the attributed accessing instruction (on x86 the hardware traps
        // *after* the access; the server back-steps to attribute it);
        // `accessor_raw_rip` is the raw trap PC.
        methods.add_method("get_watchpoint_accesses", |lua, this, (pid, addr): (Option<u32>, u64)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::GetWatchpointAccesses { pid, addr })
                .map_err(mlua::Error::external)?;
            match resp {
                DebuggerResponse::WatchpointAccesses { accesses } => {
                    let table = lua.create_table()?;
                    for (i, acc) in accesses.iter().enumerate() {
                        let entry = lua.create_table()?;
                        entry.set("accessor", acc.accessor)?;
                        entry.set("accessor_raw_rip", acc.accessor_raw_rip)?;
                        entry.set("hit_count", acc.hit_count)?;
                        entry.set("first_seq", acc.first_seq)?;
                        entry.set("thread_ids", acc.thread_ids.clone())?;
                        table.set(i + 1, entry)?;
                    }
                    Ok(table)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("GetWatchpointAccesses failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // stop_watchpoint_trace([pid], addr)
        // Remove the watchpoint at `addr` and clear its collected accesses.
        methods.add_method("stop_watchpoint_trace", |_lua, this, (pid, addr): (Option<u32>, u64)| {
            let mut client = this.inner.borrow_mut();
            let pid = pid.or(client.current_pid).ok_or_else(|| mlua::Error::external(anyhow::anyhow!("No current pid")))?;
            let resp = client.send_and_receive(&DebuggerRequest::StopWatchpointTrace { pid, addr })
                .map_err(mlua::Error::external)?;
            match resp {
                DebuggerResponse::Ack => Ok(()),
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("StopWatchpointTrace failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Utility: current state ----

        methods.add_method("pid", |_lua, this, ()| {
            Ok(this.inner.borrow().current_pid)
        });

        methods.add_method("tid", |_lua, this, ()| {
            Ok(this.inner.borrow().current_tid)
        });

        methods.add_method("address", |_lua, this, ()| {
            Ok(this.inner.borrow().current_address)
        });

        // ---- repl_on_break property ----

        methods.add_method("set_repl_on_break", |_lua, this, val: bool| {
            this.inner.borrow_mut().handlers.repl_on_break = val;
            Ok(())
        });

        // ---- Assembler ----

        methods.add_method("assemble", |lua, _this, (code, address): (String, Option<u64>)| {
            let addr = address.unwrap_or(0);
            let arch = Architecture::from_native();
            let result = crate::assembler::assemble(arch, &code, addr)
                .map_err(|e| mlua::Error::external(anyhow::anyhow!("Assemble failed: {}", e)))?;
            let table = lua.create_table()?;
            table.set("bytes", lua.create_string(&result.bytes)?)?;
            table.set("size", result.bytes.len())?;
            let hex_str: String = result.bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
            table.set("hex", hex_str)?;
            Ok(table)
        });

        // ---- Assemble and write to memory ----

        methods.add_method("assemble_to", |lua, this, (pid, address, code): (u32, u64, String)| {
            let arch = Architecture::from_native();
            let result = crate::assembler::assemble(arch, &code, address)
                .map_err(|e| mlua::Error::external(anyhow::anyhow!("Assemble failed: {}", e)))?;
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::WriteMemory {
                pid, address, data: result.bytes.clone(),
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::WriteAck => {}
                DebuggerResponse::Error { message } => {
                    return Err(mlua::Error::external(anyhow::anyhow!("WriteMemory failed: {}", message)));
                }
                _ => {}
            }
            let table = lua.create_table()?;
            table.set("bytes", lua.create_string(&result.bytes)?)?;
            table.set("size", result.bytes.len())?;
            Ok(table)
        });

        // ---- Anti-anti-debug ----

        methods.add_method("hide_peb", |lua, this, (pid, opts_tbl): (u32, Option<LuaTable>)| {
            // Parse opts table: missing keys = false; `{ all = true }` = enable all.
            let mut options = crate::anti_anti_debug::PebHideOptions::default();
            if let Some(tbl) = opts_tbl {
                let all: bool = tbl.get("all").unwrap_or(false);
                if all {
                    options = crate::anti_anti_debug::PebHideOptions::all();
                } else {
                    options.being_debugged  = tbl.get("being_debugged").unwrap_or(false);
                    options.heap_flags      = tbl.get("heap_flags").unwrap_or(false);
                    options.nt_global_flag  = tbl.get("nt_global_flag").unwrap_or(false);
                    options.startup_info    = tbl.get("startup_info").unwrap_or(false);
                    options.os_build_number = tbl.get("os_build_number").unwrap_or(false);
                }
            } else {
                options = crate::anti_anti_debug::PebHideOptions::all();
            }

            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::HidePeb { pid, options })
                .map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::PebHideResult { report } => {
                    let t = lua.create_table()?;
                    t.set("peb_address", report.peb_address)?;
                    let applied = lua.create_table()?;
                    for (i, name) in report.applied.iter().enumerate() {
                        applied.set(i + 1, name.clone())?;
                    }
                    t.set("applied", applied)?;
                    let failures = lua.create_table()?;
                    for (i, (name, msg)) in report.failures.iter().enumerate() {
                        let row = lua.create_table()?;
                        row.set("technique", name.clone())?;
                        row.set("error", msg.clone())?;
                        failures.set(i + 1, row)?;
                    }
                    t.set("failures", failures)?;
                    Ok(t)
                }
                DebuggerResponse::Error { message } => Err(mlua::Error::external(
                    anyhow::anyhow!("HidePeb failed: {}", message),
                )),
                _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
            }
        });

        // ---- Inline hooks ----

        methods.add_method("hook", |lua, _this, (addr, callback): (u64, LuaFunction)| {
            let mut engine = HOOK_ENGINE.lock().unwrap();
            let (hook_id, trampoline) = engine.hook(addr as *const u8, lua, callback)
                .map_err(|e| mlua::Error::external(anyhow::anyhow!("hook failed: {}", e)))?;
            let table = lua.create_table()?;
            table.set("id", hook_id)?;
            table.set("trampoline", trampoline as u64)?;
            table.set("address", addr)?;
            Ok(table)
        });

        methods.add_method("unhook", |_lua, _this, addr: u64| {
            let mut engine = HOOK_ENGINE.lock().unwrap();
            engine.unhook(addr)
                .map_err(|e| mlua::Error::external(anyhow::anyhow!("unhook failed: {}", e)))?;
            Ok(())
        });

        // (In-process memory access is registered as globals via register_mem_functions)
    }
}

#[cfg(windows)]
use std::sync::{LazyLock, Mutex};

#[cfg(windows)]
static HOOK_ENGINE: LazyLock<Mutex<crate::inline_hook::LuaHookEngine>> =
    LazyLock::new(|| Mutex::new(crate::inline_hook::LuaHookEngine::new()));

/// Register in-process memory access functions as a `mem` global table.
pub fn register_mem_functions(lua: &Lua) -> mlua::Result<()> {
    let mem = lua.create_table()?;

    mem.set("read", lua.create_function(|lua, (addr, size): (u64, usize)| {
        if size == 0 || size > 1024 * 1024 {
            return Err(mlua::Error::external(anyhow::anyhow!("invalid size")));
        }
        let data = unsafe { std::slice::from_raw_parts(addr as *const u8, size) };
        lua.create_string(data)
    })?)?;

    mem.set("write", lua.create_function(|_lua, (addr, data): (u64, mlua::String)| {
        let bytes = data.as_bytes();
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len());
        }
        Ok(())
    })?)?;

    mem.set("read_u8", lua.create_function(|_lua, addr: u64| {
        Ok(unsafe { *(addr as *const u8) } as u64)
    })?)?;

    mem.set("read_u16", lua.create_function(|_lua, addr: u64| {
        Ok(unsafe { std::ptr::read_unaligned(addr as *const u16) } as u64)
    })?)?;

    mem.set("read_u32", lua.create_function(|_lua, addr: u64| {
        Ok(unsafe { std::ptr::read_unaligned(addr as *const u32) } as u64)
    })?)?;

    mem.set("read_u64", lua.create_function(|_lua, addr: u64| {
        Ok(unsafe { std::ptr::read_unaligned(addr as *const u64) })
    })?)?;

    mem.set("write_u8", lua.create_function(|_lua, (addr, val): (u64, u64)| {
        unsafe { *(addr as *mut u8) = val as u8; }
        Ok(())
    })?)?;

    mem.set("write_u16", lua.create_function(|_lua, (addr, val): (u64, u64)| {
        unsafe { std::ptr::write_unaligned(addr as *mut u16, val as u16); }
        Ok(())
    })?)?;

    mem.set("write_u32", lua.create_function(|_lua, (addr, val): (u64, u64)| {
        unsafe { std::ptr::write_unaligned(addr as *mut u32, val as u32); }
        Ok(())
    })?)?;

    mem.set("write_u64", lua.create_function(|_lua, (addr, val): (u64, u64)| {
        unsafe { std::ptr::write_unaligned(addr as *mut u64, val); }
        Ok(())
    })?)?;

    mem.set("read_str", lua.create_function(|lua, (addr, max_len): (u64, Option<usize>)| {
        let max = max_len.unwrap_or(4096);
        let ptr = addr as *const u8;
        let mut len = 0;
        while len < max {
            if unsafe { *ptr.add(len) } == 0 { break; }
            len += 1;
        }
        let data = unsafe { std::slice::from_raw_parts(ptr, len) };
        lua.create_string(data)
    })?)?;

    mem.set("read_wstr", lua.create_function(|_lua, (addr, max_len): (u64, Option<usize>)| {
        let max = max_len.unwrap_or(4096);
        let ptr = addr as *const u16;
        let mut len = 0;
        while len < max {
            if unsafe { std::ptr::read_unaligned(ptr.add(len)) } == 0 { break; }
            len += 1;
        }
        let wchars: Vec<u16> = (0..len)
            .map(|i| unsafe { std::ptr::read_unaligned(ptr.add(i)) })
            .collect();
        Ok(String::from_utf16_lossy(&wchars))
    })?)?;

    lua.globals().set("mem", mem)?;
    Ok(())
}

// ---- Memory formatting helpers (exposed as Lua globals) ----

/// Register memory formatting functions as Lua globals.
pub fn register_memory_formatters(lua: &mlua::Lua) -> mlua::Result<()> {
    #[cfg(windows)]
    {
        use crate::formatting::memory;
        lua.globals().set("mem_state", lua.create_function(|_, state: u32| {
            Ok(memory::state_to_str(state).to_string())
        })?)?;
        lua.globals().set("mem_type", lua.create_function(|_, region_type: u32| {
            Ok(memory::type_to_str(region_type).to_string())
        })?)?;
        lua.globals().set("mem_protect", lua.create_function(|_, protect: u32| {
            Ok(memory::protect_to_str(protect).to_string())
        })?)?;
    }
    Ok(())
}

// ---- Scan value parsing helpers ----

fn parse_scan_value_type(s: &str) -> mlua::Result<ScanValueType> {
    match s {
        "u8" => Ok(ScanValueType::U8),
        "u16" => Ok(ScanValueType::U16),
        "u32" => Ok(ScanValueType::U32),
        "u64" => Ok(ScanValueType::U64),
        "f32" => Ok(ScanValueType::F32),
        "f64" => Ok(ScanValueType::F64),
        _ => Err(mlua::Error::external(
            anyhow::anyhow!("Invalid value type: '{}'. Use u8/u16/u32/u64/f32/f64", s),
        )),
    }
}

fn parse_scan_compare_type(s: &str) -> mlua::Result<ScanCompareType> {
    match s {
        "exact" => Ok(ScanCompareType::ExactValue),
        "unknown" => Ok(ScanCompareType::UnknownInitialValue),
        "bigger" | ">" => Ok(ScanCompareType::BiggerThan),
        "smaller" | "<" => Ok(ScanCompareType::SmallerThan),
        "between" => Ok(ScanCompareType::ValueBetween),
        "increased" => Ok(ScanCompareType::IncreasedValue),
        "decreased" => Ok(ScanCompareType::DecreasedValue),
        "changed" => Ok(ScanCompareType::Changed),
        "unchanged" => Ok(ScanCompareType::Unchanged),
        _ => Err(mlua::Error::external(
            anyhow::anyhow!("Invalid compare type: '{}'. Use exact/unknown/bigger/smaller/between/increased/decreased/changed/unchanged", s),
        )),
    }
}

fn parse_scan_value(vt: &ScanValueType, s: &str) -> mlua::Result<ScanValue> {
    let s = s.trim();
    match vt {
        ScanValueType::U8 => {
            let v = parse_int(s)?;
            Ok(ScanValue::U8(v as u8))
        }
        ScanValueType::U16 => {
            let v = parse_int(s)?;
            Ok(ScanValue::U16(v as u16))
        }
        ScanValueType::U32 => {
            let v = parse_int(s)?;
            Ok(ScanValue::U32(v as u32))
        }
        ScanValueType::U64 => {
            let v = parse_int(s)?;
            Ok(ScanValue::U64(v))
        }
        ScanValueType::F32 => {
            let v: f32 = s.parse().map_err(|e| mlua::Error::external(
                anyhow::anyhow!("Invalid f32: {}", e),
            ))?;
            Ok(ScanValue::F32(v))
        }
        ScanValueType::F64 => {
            let v: f64 = s.parse().map_err(|e| mlua::Error::external(
                anyhow::anyhow!("Invalid f64: {}", e),
            ))?;
            Ok(ScanValue::F64(v))
        }
    }
}

fn parse_int(s: &str) -> mlua::Result<u64> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| mlua::Error::external(
            anyhow::anyhow!("Invalid hex: {}", e),
        ))
    } else {
        s.parse::<u64>().map_err(|e| mlua::Error::external(
            anyhow::anyhow!("Invalid integer: {}", e),
        ))
    }
}

/// Resolve a Lua value (integer or symbol name string) to an address.
fn resolve_addr_or_sym(client: &mut DebugClient, val: LuaValue) -> mlua::Result<u64> {
    match val {
        LuaValue::Integer(n) => Ok(n as u64),
        LuaValue::String(s) => {
            let sym_name = s.to_str()?;
            let resp = client.send_and_receive(&DebuggerRequest::FindSymbol {
                symbol_name: sym_name.to_string(),
                max_results: 1,
            }).map_err(|e| mlua::Error::external(e))?;
            match resp {
                DebuggerResponse::ResolvedSymbolList { symbols } if !symbols.is_empty() => {
                    Ok(symbols[0].va)
                }
                _ => Err(mlua::Error::external(
                    anyhow::anyhow!("Symbol '{}' not found", sym_name),
                )),
            }
        }
        _ => Err(mlua::Error::external(
            anyhow::anyhow!("Address must be integer or symbol name string"),
        )),
    }
}

/// Parse a Lua hardware-breakpoint type string. `allow_execute` is false for
/// watchpoint traces (data access only).
fn parse_hw_type_str(s: &str, allow_execute: bool) -> mlua::Result<HardwareBreakpointType> {
    match s {
        "execute" | "x" if allow_execute => Ok(HardwareBreakpointType::Execute),
        "write" | "w" => Ok(HardwareBreakpointType::Write),
        "readwrite" | "rw" => Ok(HardwareBreakpointType::ReadWrite),
        _ => Err(mlua::Error::external(anyhow::anyhow!(
            "Invalid type: '{}'. Use {}'write'/'w' or 'readwrite'/'rw'",
            s,
            if allow_execute { "'execute'/'x', " } else { "" },
        ))),
    }
}

/// Parse a Lua hardware-breakpoint size string ("1" | "2" | "4" | "8").
fn parse_hw_size_str(s: &str) -> mlua::Result<HardwareBreakpointSize> {
    match s {
        "1" => Ok(HardwareBreakpointSize::Byte1),
        "2" => Ok(HardwareBreakpointSize::Byte2),
        "4" => Ok(HardwareBreakpointSize::Byte4),
        "8" => Ok(HardwareBreakpointSize::Byte8),
        _ => Err(mlua::Error::external(
            anyhow::anyhow!("Invalid size: '{}'. Use '1', '2', '4', or '8'", s),
        )),
    }
}

/// Read N bytes from process memory and decode as a little-endian unsigned integer.
fn read_memory_uint(client: &mut DebugClient, pid: u32, addr: u64, size: usize) -> mlua::Result<u64> {
    let resp = client.send_and_receive(&DebuggerRequest::ReadMemory {
        pid, address: addr, size,
    }).map_err(|e| mlua::Error::external(e))?;
    match resp {
        DebuggerResponse::MemoryData { data } if data.len() >= size => {
            let mut buf = [0u8; 8];
            buf[..size].copy_from_slice(&data[..size]);
            Ok(u64::from_le_bytes(buf) & if size < 8 { (1u64 << (size * 8)) - 1 } else { u64::MAX })
        }
        DebuggerResponse::Error { message } => Err(mlua::Error::external(anyhow::anyhow!("{}", message))),
        _ => Err(mlua::Error::external(anyhow::anyhow!("ReadMemory failed"))),
    }
}

/// Convert an AddressSymbol response to a Lua table.
fn address_symbol_to_lua_table(lua: &Lua, module_path: Option<String>, symbol: Option<ModuleSymbol>, offset: Option<u64>) -> mlua::Result<LuaTable> {
    let table = lua.create_table()?;
    if let Some(path) = module_path {
        table.set("module", path)?;
    }
    if let Some(sym) = symbol {
        table.set("name", sym.name)?;
        table.set("rva", sym.rva as u64)?;
        table.set("is_function", sym.is_function)?;
    }
    if let Some(off) = offset {
        table.set("offset", off)?;
    }
    Ok(table)
}

/// Convert a resolved `TypeLayout` into a Lua table:
/// `{ name, size, kind, index, module_base, members = { {name, offset, type, size, kind,
///    [type_index], [pointee], [element], [count], [bit_position], [bit_length]} },
///    values = { {name, value} } }`.
/// `type_index` (for udt/enum members) feeds `dbg:get_type_by_index`; `pointee`/
/// `element` are nested `{type, size, kind, [type_index], ...}` tables.
fn type_layout_to_lua_table(lua: &Lua, layout: &TypeLayout) -> mlua::Result<LuaTable> {
    let table = lua.create_table()?;
    table.set("name", layout.name.as_str())?;
    table.set("size", layout.size as u64)?;
    table.set("index", layout.index as u64)?;
    table.set("module_base", layout.module_base)?;
    table.set("kind", type_kind_str(layout.kind))?;

    let members = lua.create_table()?;
    for (i, m) in layout.members.iter().enumerate() {
        let mt = lua.create_table()?;
        mt.set("name", m.name.as_str())?;
        mt.set("offset", m.offset as u64)?;
        mt.set("type", m.type_ref.name.as_str())?;
        mt.set("size", m.type_ref.size as u64)?;
        mt.set("kind", type_class_str(&m.type_ref.class))?;
        set_type_class_fields(lua, &mt, &m.type_ref.class)?;
        if let Some(bp) = m.bit_position {
            mt.set("bit_position", bp as u64)?;
        }
        if let Some(bl) = m.bit_length {
            mt.set("bit_length", bl as u64)?;
        }
        members.set(i + 1, mt)?;
    }
    table.set("members", members)?;

    if !layout.enum_values.is_empty() {
        let values = lua.create_table()?;
        for (i, v) in layout.enum_values.iter().enumerate() {
            let vt = lua.create_table()?;
            vt.set("name", v.name.as_str())?;
            vt.set("value", v.value)?;
            values.set(i + 1, vt)?;
        }
        table.set("values", values)?;
    }
    Ok(table)
}

fn type_kind_str(kind: UdtKind) -> &'static str {
    match kind {
        UdtKind::Struct => "struct",
        UdtKind::Class => "class",
        UdtKind::Union => "union",
        UdtKind::Enum => "enum",
    }
}

fn type_class_str(class: &TypeClass) -> &'static str {
    match class {
        TypeClass::Int => "int",
        TypeClass::UInt => "uint",
        TypeClass::Float => "float",
        TypeClass::Bool => "bool",
        TypeClass::Char => "char",
        TypeClass::WChar => "wchar",
        TypeClass::Void => "void",
        TypeClass::Pointer { .. } => "pointer",
        TypeClass::Array { .. } => "array",
        TypeClass::Udt { .. } => "udt",
        TypeClass::Enum { .. } => "enum",
        TypeClass::Unknown => "unknown",
    }
}

/// Structured fields for a type class, mirroring what the protocol carries:
/// the TPI `type_index` for udt/enum (feeds `get_type_by_index`), and nested
/// `pointee`/`element` (+ `count`) tables for pointers/arrays.
fn set_type_class_fields(lua: &Lua, table: &LuaTable, class: &TypeClass) -> mlua::Result<()> {
    match class {
        TypeClass::Udt { index } | TypeClass::Enum { index } => {
            table.set("type_index", *index as u64)?;
        }
        TypeClass::Pointer { pointee } => {
            table.set("pointee", type_ref_to_lua(lua, pointee)?)?;
        }
        TypeClass::Array { element, count } => {
            table.set("element", type_ref_to_lua(lua, element)?)?;
            table.set("count", *count as u64)?;
        }
        _ => {}
    }
    Ok(())
}

/// Build a Lua array (1-based) of tables, one per item, each filled by `fill`.
/// Shared by the `ProcessObjects` sections, which are all arrays of flat records.
fn lua_rows<T>(lua: &Lua, items: &[T], fill: impl Fn(&LuaTable, &T) -> mlua::Result<()>) -> mlua::Result<LuaTable> {
    let arr = lua.create_table()?;
    for (i, item) in items.iter().enumerate() {
        let t = lua.create_table()?;
        fill(&t, item)?;
        arr.set(i + 1, t)?;
    }
    Ok(arr)
}

/// Convert a `ProcessObjects` snapshot (the Handles window) to a Lua table.
fn process_objects_to_lua_table(lua: &Lua, o: &ProcessObjects) -> mlua::Result<LuaTable> {
    let out = lua.create_table()?;
    out.set("handles", lua_rows(lua, &o.handles, |t, h| {
        t.set("handle", h.handle)?;
        t.set("type_index", h.type_index)?;
        t.set("type_name", h.type_name.as_str())?;
        t.set("granted_access", h.granted_access)?;
        t.set("attributes", h.attributes)?;
        t.set("name", h.name.as_str())
    })?)?;
    out.set("windows", lua_rows(lua, &o.windows, |t, w| {
        t.set("handle", w.handle)?;
        t.set("parent", w.parent)?;
        t.set("thread_id", w.thread_id)?;
        t.set("style", w.style)?;
        t.set("style_ex", w.style_ex)?;
        t.set("wnd_proc", w.wnd_proc)?;
        t.set("enabled", w.enabled)?;
        t.set("left", w.left)?;
        t.set("top", w.top)?;
        t.set("width", w.width)?;
        t.set("height", w.height)?;
        t.set("title", w.title.as_str())?;
        t.set("class_name", w.class_name.as_str())
    })?)?;
    out.set("tcp_connections", lua_rows(lua, &o.tcp_connections, |t, c| {
        t.set("local_address", c.local_address.as_str())?;
        t.set("local_port", c.local_port)?;
        t.set("remote_address", c.remote_address.as_str())?;
        t.set("remote_port", c.remote_port)?;
        t.set("state", c.state.as_str())
    })?)?;
    out.set("privileges", lua_rows(lua, &o.privileges, |t, p| {
        t.set("name", p.name.as_str())?;
        t.set("state", match p.state {
            PrivilegeState::Disabled => "disabled",
            PrivilegeState::Enabled => "enabled",
            PrivilegeState::EnabledByDefault => "enabled_by_default",
        })
    })?)?;
    out.set("desktop_window", o.desktop_window)?;
    let warnings = lua.create_table()?;
    for (i, w) in o.warnings.iter().enumerate() {
        warnings.set(i + 1, w.as_str())?;
    }
    out.set("warnings", warnings)?;
    Ok(out)
}

/// Convert a `TypeRef` (a pointer's pointee / an array's element) to a Lua table.
fn type_ref_to_lua(lua: &Lua, r: &TypeRef) -> mlua::Result<LuaTable> {
    let table = lua.create_table()?;
    table.set("type", r.name.as_str())?;
    table.set("size", r.size as u64)?;
    table.set("kind", type_class_str(&r.class))?;
    set_type_class_fields(lua, &table, &r.class)?;
    Ok(table)
}

/// Convert a TypeResult response (from GetType / GetTypeByIndex) to a Lua value:
/// the layout table, or nil when the type wasn't found.
fn type_result_to_lua(lua: &Lua, resp: DebuggerResponse, op_name: &str) -> mlua::Result<LuaValue> {
    match resp {
        DebuggerResponse::TypeResult { layout } => match layout {
            Some(layout) => Ok(LuaValue::Table(type_layout_to_lua_table(lua, &layout)?)),
            None => Ok(LuaValue::Nil),
        },
        DebuggerResponse::Error { message } => Err(mlua::Error::external(
            anyhow::anyhow!("{} failed: {}", op_name, message),
        )),
        _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
    }
}

/// Convert a ScanMemoryResult response to a Lua table.
fn scan_result_to_lua(lua: &Lua, resp: DebuggerResponse, op_name: &str) -> mlua::Result<LuaTable> {
    match resp {
        DebuggerResponse::ScanMemoryResult { scan_id, match_count, scan_time_us } => {
            let table = lua.create_table()?;
            table.set("scan_id", scan_id)?;
            table.set("match_count", match_count)?;
            table.set("time_us", scan_time_us)?;
            Ok(table)
        }
        DebuggerResponse::Error { message } => Err(mlua::Error::external(
            anyhow::anyhow!("{} failed: {}", op_name, message),
        )),
        _ => Err(mlua::Error::external(anyhow::anyhow!("Unexpected response"))),
    }
}
