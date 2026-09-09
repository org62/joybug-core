//! Emulation entry points
//!
//! Contains the main emulation loops: `emulate_instructions` (simple, no hooks)
//! and `emulate_with_mode` (hook-based with multiple modes).

use unicorn_engine::unicorn_const::uc_error;
use unicorn_engine::RegisterX86;

use crate::interfaces::Architecture;
use crate::protocol::{EmulationMode, MemoryAccess, MemoryAccessType};

use super::{Emulator, ImportPolicy};
use super::target::{EmuTarget, FetchIntercept};
use super::types::{StopReason, EmulationResult};
use super::error::EmulatorError;

/// What the execution loop should do after an unmapped fetch was examined.
enum FetchOutcome {
    /// Not a synthetic address; fall through to the normal page loader.
    NotIntercepted,
    /// Handled (the import was skipped); keep emulating.
    Continue,
    /// Emulation is over.
    Stop(StopReason),
}

impl<'a> Emulator<'a> {
    /// Classify an unmapped fetch at `addr` against the target's synthetic
    /// addresses (import stubs, the return sentinel) and apply the import
    /// policy. Both loops call this before trying to page `addr` in.
    fn handle_fetch_intercept<T: EmuTarget>(&mut self, target: &T, addr: u64) -> FetchOutcome {
        match target.intercept_fetch(addr) {
            None => FetchOutcome::NotIntercepted,
            Some(FetchIntercept::ReturnSentinel) => FetchOutcome::Stop(StopReason::ReturnedToCaller),
            Some(FetchIntercept::Import(name)) => match self.import_policy {
                ImportPolicy::Stop => {
                    let from = self.return_address().unwrap_or(0);
                    FetchOutcome::Stop(StopReason::ImportCall { name, from })
                }
                ImportPolicy::Skip { value } => match self.return_to_caller(value) {
                    Ok(()) => {
                        tracing::debug!("skipped import {} -> returned to 0x{:X}", name, self.get_pc().unwrap_or(0));
                        FetchOutcome::Continue
                    }
                    Err(e) => FetchOutcome::Stop(StopReason::Error(format!("skip {}: {}", name, e))),
                },
            },
        }
    }

    /// Emulate with a specific mode that determines which hooks are installed
    ///
    /// Modes:
    /// - Basic: No per-instruction hooks (fastest)
    /// - InstructionTrace: CODE hook records every instruction (addr, size)
    /// - BasicBlock: BLOCK hook records basic block starts
    /// - ModuleTransition: Stop when execution moves to a different module
    /// - Syscall: Stop on first syscall instruction
    pub fn emulate_with_mode<T: EmuTarget>(
        &mut self,
        target: &T,
        max_instructions: usize,
        mode: EmulationMode,
        exit_condition: Option<crate::protocol::TraceExitCondition>,
        memory_reads: &[(u64, usize)],
    ) -> Result<EmulationResult, EmulatorError> {
        use std::time::Instant;
        use crate::protocol::TraceExitCondition;

        let start_time = Instant::now();

        let start_pc = self.get_pc()?;
        let mut instructions_executed = 0;
        let mut stop_reason = StopReason::InstructionLimit;

        let exit_address = match &exit_condition {
            Some(TraceExitCondition::ReachAddress(addr)) => Some(*addr),
            _ => None,
        };

        let pages_before = {
            let state = self.shared_state.read().unwrap();
            state.mapped_regions.len()
        };

        // Clear previous state
        {
            let mut state = self.shared_state.write().unwrap();
            state.basic_blocks.clear();
            state.basic_blocks.push(start_pc);
            state.pending_memory_fault = None;
            state.module_transition = None;
            state.stop_requested = false;
            state.last_instruction_addr = None;
            state.last_instruction_size = None;
            state.instruction_trace.clear();
            state.register_trace.clear();
            state.memory_trace.clear();
            state.pending_write_ops.clear();
            state.retrying_after_fault = false;
            state.syscall_address = None;
            state.exception_intno = None;
            state.exit_address = exit_address;

            if mode == EmulationMode::ModuleTransition {
                state.current_module = state.modules.iter()
                    .find(|m| start_pc >= m.base && start_pc < m.end)
                    .map(|m| m.name.clone());
            }
        }

        // Pre-load initial code and stack regions
        let preload_start = std::time::Instant::now();
        self.load_memory_region(target, start_pc)?;
        let sp = self.get_sp()?;
        let _ = self.load_memory_region(target, sp);
        let preload_us = preload_start.elapsed().as_micros() as u64;
        let preload_pages = {
            let state = self.shared_state.read().unwrap();
            state.mapped_regions.len() - pages_before
        };

        // Install mode-specific hooks
        let hook_setup_start = std::time::Instant::now();
        let mut hook_handles: Vec<unicorn_engine::UcHookId> = Vec::new();
        let mut exec_time_us: u64 = 0;
        let mut page_load_time_us: u64 = 0;
        let mut page_load_count: usize = 0;
        let mut loop_iterations: usize = 0;

        match mode {
            EmulationMode::Basic => {
                hook_handles.push(self.install_syscall_hook()?);
            }
            EmulationMode::InstructionTrace => {
                hook_handles.push(self.install_code_hook()?);
                hook_handles.push(self.install_syscall_hook()?);
            }
            EmulationMode::BasicBlock => {
                hook_handles.push(self.install_block_hook()?);
                hook_handles.push(self.install_syscall_hook()?);
            }
            EmulationMode::ModuleTransition => {
                hook_handles.push(self.install_syscall_hook()?);
            }
            EmulationMode::Syscall => {
                hook_handles.push(self.install_syscall_hook()?);
            }
        };

        let use_instruction_counting = mode == EmulationMode::InstructionTrace;
        let hook_setup_us = hook_setup_start.elapsed().as_micros() as u64;

        // =========================================================================
        // CRITICAL: count=0 for non-tracing modes (Basic, BasicBlock,
        //           ModuleTransition, Syscall)
        // =========================================================================
        // Passing count=0 to emu_start() is MANDATORY for non-tracing modes.
        // count=0 lets Unicorn build multi-instruction JIT translation blocks,
        // giving 10-100x better performance than count>0. Setting count>0 forces
        // Unicorn to create single-instruction translation blocks, completely
        // destroying JIT performance. NEVER change this to count>0.
        //
        // Safety mechanism: Non-tracing modes use Unicorn's built-in timeout
        // parameter, which spawns a background thread that calls emu_stop()
        // after the time budget expires. This provides a hard safety net without
        // any instruction-counting overhead. In normal operation, hooks (syscall,
        // module transition, etc.) stop emulation well before the timeout fires.
        //
        // InstructionTrace mode uses count=TRACE_BATCH_SIZE to batch instructions
        // between the CODE hook and the outer loop.
        // =========================================================================
        const TRACE_BATCH_SIZE: usize = 1000;
        const SAFETY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

        let mut remaining = max_instructions;
        loop {
            if use_instruction_counting && remaining == 0 {
                break;
            }

            if !use_instruction_counting && start_time.elapsed() > SAFETY_TIMEOUT {
                stop_reason = StopReason::InstructionLimit;
                break;
            }

            loop_iterations += 1;
            let pc_before = self.get_pc()?;

            {
                let mut state = self.shared_state.write().unwrap();
                state.pending_memory_fault = None;
            }

            let (count, timeout_us) = if use_instruction_counting {
                (TRACE_BATCH_SIZE.min(remaining), 0u64)
            } else {
                let remaining_us = SAFETY_TIMEOUT
                    .saturating_sub(start_time.elapsed())
                    .as_micros() as u64;
                (0, remaining_us.max(1))
            };
            tracing::debug!("emu_start: pc=0x{:X}, count={}, iteration={}", pc_before, count, loop_iterations);
            let emu_call_start = std::time::Instant::now();
            match self.emu.emu_start(pc_before, u64::MAX, timeout_us, count) {
                Ok(()) => {
                    let elapsed = emu_call_start.elapsed().as_micros() as u64;
                    exec_time_us += elapsed;
                    let pc_after = self.get_pc().unwrap_or(pc_before);
                    tracing::debug!("emu_start returned Ok: pc=0x{:X}->0x{:X}, elapsed={}us, iteration={}", pc_before, pc_after, elapsed, loop_iterations);

                    if use_instruction_counting {
                        let state = self.shared_state.read().unwrap();
                        let executed = state.instruction_trace.len().saturating_sub(instructions_executed);
                        instructions_executed += executed;
                        remaining = remaining.saturating_sub(executed);
                    }

                    {
                        let state = self.shared_state.read().unwrap();
                        if state.stop_requested {
                            if let Some(intno) = state.exception_intno {
                                let pc = self.get_pc().unwrap_or(0);
                                stop_reason = StopReason::Error(format!(
                                    "Unhandled exception (intno={}) at PC=0x{:X}", intno, pc
                                ));
                            } else if let Some(addr) = state.syscall_address {
                                stop_reason = StopReason::Syscall { address: addr };
                            } else if let Some(addr) = state.exit_address {
                                stop_reason = StopReason::ReachedAddress(addr);
                            } else {
                                stop_reason = StopReason::Stopped;
                            }
                            break;
                        }
                    }

                    continue;
                }
                Err(err @ (uc_error::READ_UNMAPPED | uc_error::FETCH_UNMAPPED | uc_error::WRITE_UNMAPPED)) => {
                    exec_time_us += emu_call_start.elapsed().as_micros() as u64;
                    if use_instruction_counting {
                        let state = self.shared_state.read().unwrap();
                        let traced = state.instruction_trace.len();
                        let delta = traced.saturating_sub(instructions_executed);
                        instructions_executed = traced;
                        remaining = remaining.saturating_sub(delta);
                        drop(state);
                        let mut state = self.shared_state.write().unwrap();
                        state.retrying_after_fault = true;
                    }
                    let pc_after = self.get_pc().unwrap_or(pc_before);

                    let fault_addr = {
                        let state = self.shared_state.read().unwrap();
                        state.pending_memory_fault
                    };

                    if let Some(addr) = fault_addr {
                        // Synthetic addresses (import stubs, the return
                        // sentinel) are never pageable — classify them first.
                        if err == uc_error::FETCH_UNMAPPED {
                            match self.handle_fetch_intercept(target, addr) {
                                FetchOutcome::NotIntercepted => {}
                                FetchOutcome::Continue => continue,
                                FetchOutcome::Stop(reason) => {
                                    stop_reason = reason;
                                    break;
                                }
                            }
                        }

                        // For ModuleTransition mode, check if we're loading from a different module
                        if mode == EmulationMode::ModuleTransition {
                            let transition = {
                                let state = self.shared_state.read().unwrap();
                                let target_module = state.modules.iter()
                                    .find(|m| addr >= m.base && addr < m.end)
                                    .map(|m| m.name.clone());

                                if let (Some(current), Some(target)) = (&state.current_module, &target_module) {
                                    if current != target {
                                        Some((current.clone(), target.clone(), addr))
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            };

                            if let Some((from, to, at_addr)) = transition {
                                let symbol = target.symbolize(at_addr);
                                stop_reason = StopReason::ModuleTransition { from, to, address: at_addr, symbol };
                                break;
                            }
                        }

                        let load_start = std::time::Instant::now();
                        match self.load_memory_region(target, addr) {
                            Ok(()) => {
                                page_load_time_us += load_start.elapsed().as_micros() as u64;
                                page_load_count += 1;
                                continue;
                            }
                            Err(_) => {
                                page_load_time_us += load_start.elapsed().as_micros() as u64;
                                if self.try_pac_fetch_recovery(target, addr, err == uc_error::FETCH_UNMAPPED) {
                                    continue;
                                }
                                stop_reason = StopReason::UnmappedMemory(addr);
                                break;
                            }
                        }
                    } else {
                        let load_start = std::time::Instant::now();
                        let sp = self.get_sp().unwrap_or(0);
                        let _ = self.load_memory_region(target, pc_after);
                        if sp > 0 && sp >= 0x1000 {
                            let _ = self.load_memory_region(target, sp - 0x1000);
                        }
                        page_load_time_us += load_start.elapsed().as_micros() as u64;
                        page_load_count += 1;
                        if pc_after != pc_before {
                            continue;
                        }
                        match self.emu.emu_start(pc_before, u64::MAX, 0, 1) {
                            Ok(()) => {
                                if use_instruction_counting {
                                    let state = self.shared_state.read().unwrap();
                                    let traced = state.instruction_trace.len();
                                    let delta = traced.saturating_sub(instructions_executed);
                                    instructions_executed = traced;
                                    remaining = remaining.saturating_sub(delta);
                                }
                                {
                                    let state = self.shared_state.read().unwrap();
                                    if state.stop_requested {
                                        if let Some(intno) = state.exception_intno {
                                            let pc = self.get_pc().unwrap_or(0);
                                            stop_reason = StopReason::Error(format!(
                                                "Unhandled exception (intno={}) at PC=0x{:X}", intno, pc
                                            ));
                                        } else if let Some(addr) = state.syscall_address {
                                            stop_reason = StopReason::Syscall { address: addr };
                                        } else if let Some(addr) = state.exit_address {
                                            stop_reason = StopReason::ReachedAddress(addr);
                                        } else {
                                            stop_reason = StopReason::Stopped;
                                        }
                                        break;
                                    }
                                }
                                continue;
                            }
                            Err(_) => {
                                stop_reason = StopReason::UnmappedMemory(pc_before);
                                break;
                            }
                        }
                    }
                }
                Err(uc_error::EXCEPTION) => {
                    exec_time_us += emu_call_start.elapsed().as_micros() as u64;
                    let pc_after = self.get_pc().unwrap_or(pc_before);

                    if pc_after != pc_before {
                        if use_instruction_counting {
                            let state = self.shared_state.read().unwrap();
                            let traced = state.instruction_trace.len();
                            let delta = traced.saturating_sub(instructions_executed);
                            instructions_executed = traced;
                            remaining = remaining.saturating_sub(delta);
                        }
                        let _ = self.load_memory_region(target, pc_after);
                        continue;
                    }

                    // WOW64's user→kernel transition is a far `jmp` into the
                    // 64-bit side, which Unicorn (no GDT) faults on: for a
                    // 32-bit target that is the syscall stop.
                    if self.is_x86_far_jump_at(pc_before) {
                        stop_reason = StopReason::Syscall { address: pc_before };
                        break;
                    }
                    // PC didn't move - this is a real exception
                    self.log_exception_details(target, pc_before);
                    stop_reason = StopReason::Error("EXCEPTION".into());
                    break;
                }
                Err(e) => {
                    exec_time_us += emu_call_start.elapsed().as_micros() as u64;
                    if use_instruction_counting {
                        let state = self.shared_state.read().unwrap();
                        instructions_executed = state.instruction_trace.len();
                    }
                    stop_reason = StopReason::Error(format!("{:?}", e));
                    break;
                }
            }
        }

        // Remove hooks
        let cleanup_start = std::time::Instant::now();
        for hook in hook_handles {
            let _ = self.emu.remove_hook(hook);
        }

        // Capture any final pending writes from the last instruction
        if mode == EmulationMode::InstructionTrace {
            let mut state = self.shared_state.write().unwrap();
            if !state.pending_write_ops.is_empty() && !state.memory_trace.is_empty() {
                let pending_ops: Vec<_> = state.pending_write_ops.drain(..).collect();
                let last_mem = state.memory_trace.last_mut().unwrap();
                for (write_addr, write_size) in pending_ops {
                    if let Ok(data) = self.emu.mem_read_as_vec(write_addr, write_size) {
                        last_mem.push(MemoryAccess {
                            access_type: MemoryAccessType::Write,
                            address: write_addr,
                            data,
                        });
                    }
                }
            }
        }
        let cleanup_us = cleanup_start.elapsed().as_micros() as u64;

        let emulation_time_us = start_time.elapsed().as_micros() as u64;
        let total_pages = {
            let state = self.shared_state.read().unwrap();
            state.mapped_regions.len() - pages_before
        };
        let stats_text = format!(
            "preload: {}us ({}pg) | hooks: {}us | exec: {}us | pgload: {}us ({}pg) | cleanup: {}us | total: {}us | pages: {}",
            preload_us, preload_pages,
            hook_setup_us,
            exec_time_us,
            page_load_time_us, page_load_count,
            cleanup_us,
            emulation_time_us,
            total_pages,
        );
        self.build_result(instructions_executed, stop_reason, emulation_time_us, pages_before, stats_text, memory_reads)
    }

    /// Whether the instruction at `pc` is a far `jmp` (`EA`) in a 32-bit
    /// target — `wow64cpu!KiFastSystemCall2` / xtajit's gate, reached through
    /// `call [ntdll!Wow64Transition]` by every 32-bit syscall stub.
    fn is_x86_far_jump_at(&self, pc: u64) -> bool {
        self.architecture == Architecture::X86
            && self.emu.mem_read_as_vec(pc, 1).map(|b| b[0] == 0xEA).unwrap_or(false)
    }

    /// Log detailed diagnostics for a CPU exception (PC didn't move).
    fn log_exception_details<T: EmuTarget>(&self, target: &T, pc: u64) {
        let fault_addr = {
            let state = self.shared_state.read().unwrap();
            state.pending_memory_fault
        };

        let rax = self.emu.reg_read(RegisterX86::RAX).unwrap_or(0);
        let rbx = self.emu.reg_read(RegisterX86::RBX).unwrap_or(0);
        let rcx = self.emu.reg_read(RegisterX86::RCX).unwrap_or(0);
        let rdx = self.emu.reg_read(RegisterX86::RDX).unwrap_or(0);
        let rsi = self.emu.reg_read(RegisterX86::RSI).unwrap_or(0);
        let rdi = self.emu.reg_read(RegisterX86::RDI).unwrap_or(0);
        let rbp = self.emu.reg_read(RegisterX86::RBP).unwrap_or(0);
        let rsp = self.emu.reg_read(RegisterX86::RSP).unwrap_or(0);
        let r8 = self.emu.reg_read(RegisterX86::R8).unwrap_or(0);
        let r9 = self.emu.reg_read(RegisterX86::R9).unwrap_or(0);
        let r10 = self.emu.reg_read(RegisterX86::R10).unwrap_or(0);
        let r11 = self.emu.reg_read(RegisterX86::R11).unwrap_or(0);
        let r12 = self.emu.reg_read(RegisterX86::R12).unwrap_or(0);
        let r13 = self.emu.reg_read(RegisterX86::R13).unwrap_or(0);
        let r14 = self.emu.reg_read(RegisterX86::R14).unwrap_or(0);
        let r15 = self.emu.reg_read(RegisterX86::R15).unwrap_or(0);
        let rflags = self.emu.reg_read(RegisterX86::RFLAGS).unwrap_or(0);

        tracing::warn!(
            "EXCEPTION at RIP=0x{:X}, fault_addr={:?}\n\
             RAX={:016X} RBX={:016X} RCX={:016X} RDX={:016X}\n\
             RSI={:016X} RDI={:016X} RBP={:016X} RSP={:016X}\n\
             R8 ={:016X} R9 ={:016X} R10={:016X} R11={:016X}\n\
             R12={:016X} R13={:016X} R14={:016X} R15={:016X}\n\
             RFLAGS={:016X}",
            pc, fault_addr,
            rax, rbx, rcx, rdx,
            rsi, rdi, rbp, rsp,
            r8, r9, r10, r11,
            r12, r13, r14, r15,
            rflags
        );

        if let Some(insn) = target.disassemble_one(pc) {
            tracing::warn!(
                "Faulting instruction: {} {}",
                insn.mnemonic, insn.op_str
            );
        }

        let rdi_page = rdi & !0xFFF;
        {
            let state = self.shared_state.read().unwrap();
            if let Some(region) = state.mapped_regions.get(&rdi_page) {
                tracing::warn!(
                    "RDI 0x{:X} -> mapped region: base=0x{:X} size=0x{:X}",
                    rdi, region.base, region.size
                );
            } else {
                tracing::warn!("RDI 0x{:X} -> NOT MAPPED in emulator", rdi);
            }
        }

        if rdi != 0 {
            match target.region(rdi) {
                Some(region) => {
                    tracing::warn!(
                        "RDI 0x{:X} in target: base=0x{:X} size=0x{:X} prot={} committed={}",
                        rdi, region.base, region.size,
                        Self::prot_to_str(region.prot),
                        region.committed
                    );
                }
                None => {
                    tracing::warn!("RDI 0x{:X} is not mapped in the target", rdi);
                }
            }
        }
    }
}
