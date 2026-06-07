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

        methods.add_method("launch", |_lua, this, (command, debug_children, working_directory): (String, Option<bool>, Option<String>)| {
            let mut client = this.inner.borrow_mut();
            // Launch just sends the request. Events start flowing through the stream.
            // Call dbg:run() to enter the event loop.
            client.send_request_only(&DebuggerRequest::Launch {
                command,
                debug_children: debug_children.unwrap_or(false),
                working_directory,
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

            let bp_type = match bp_type_str.as_str() {
                "execute" | "x" => HardwareBreakpointType::Execute,
                "write" | "w" => HardwareBreakpointType::Write,
                "readwrite" | "rw" => HardwareBreakpointType::ReadWrite,
                _ => return Err(mlua::Error::external(
                    anyhow::anyhow!("Invalid bp_type: '{}'. Use 'execute'/'x', 'write'/'w', or 'readwrite'/'rw'", bp_type_str),
                )),
            };

            let size = match size_str.as_deref().unwrap_or("1") {
                "1" => HardwareBreakpointSize::Byte1,
                "2" => HardwareBreakpointSize::Byte2,
                "4" => HardwareBreakpointSize::Byte4,
                "8" => HardwareBreakpointSize::Byte8,
                s => return Err(mlua::Error::external(
                    anyhow::anyhow!("Invalid size: '{}'. Use '1', '2', '4', or '8'", s),
                )),
            };

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

        // ---- Disassembly ----

        methods.add_method("disassemble", |lua, this, (pid, addr, count): (u32, u64, Option<usize>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::DisassembleMemory {
                pid, address: addr, count: count.unwrap_or(10),
                arch: Architecture::X64, // TODO: detect
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
                arch: Architecture::X64, // TODO: detect
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

        methods.add_method("dereference", |lua, this, (pid, addr, count, ref_base): (u32, u64, Option<usize>, Option<u64>)| {
            let mut client = this.inner.borrow_mut();
            let resp = client.send_and_receive(&DebuggerRequest::Dereference {
                pid, address: addr, count: count.unwrap_or(1), reference_base: ref_base,
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
                DebuggerResponse::TenetTrace { trace_text, stop_reason, trace_time_us, stats_text } => {
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
                DebuggerResponse::TenetTrace { trace_text, stop_reason, trace_time_us, stats_text } => {
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
            }).map_err(|e| mlua::Error::external(e))?;
            scan_result_to_lua(lua, resp, "ScanMemoryStart")
        });

        methods.add_method("scan_next", |lua, this, (scan_id, compare_str, value_str, value_type_str): (u64, String, Option<String>, Option<String>)| {
            let mut client = this.inner.borrow_mut();
            let compare_type = parse_scan_compare_type(&compare_str)?;
            let value_type = value_type_str.as_deref().map(|s| parse_scan_value_type(s)).transpose()?.unwrap_or(ScanValueType::U64);
            let value = value_str.as_deref().map(|v| parse_scan_value(&value_type, v)).transpose()?;

            let resp = client.send_and_receive(&DebuggerRequest::ScanMemoryNext {
                scan_id, compare_type, value, value2: None,
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
            let arch = Architecture::X64; // TODO: detect from target
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
            let arch = Architecture::X64; // TODO: detect from target
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
                    t.set("wow64_skipped", report.wow64_skipped)?;
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
