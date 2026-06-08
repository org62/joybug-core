//! Emulator unit tests

use std::sync::{Arc, RwLock};

use unicorn_engine::{
    unicorn_const::{Arch, Mode, Prot},
    Unicorn, RegisterX86,
};

use super::types::EmulatorSharedState;

#[test]
fn test_emulator_x64_creates() {
    let shared = Arc::new(RwLock::new(EmulatorSharedState::new(Vec::new())));
    let emu = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, shared);
    assert!(emu.is_ok());
}

#[test]
fn test_memory_operations() {
    let shared = Arc::new(RwLock::new(EmulatorSharedState::new(Vec::new())));
    let mut emu = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, shared).unwrap();

    emu.mem_map(0x1000, 0x1000, Prot::ALL).unwrap();

    let code = [0x90u8, 0x90, 0x90, 0xC3];
    emu.mem_write(0x1000, &code).unwrap();

    let read_back = emu.mem_read_as_vec(0x1000, 4).unwrap();
    assert_eq!(read_back, code);
}

#[test]
fn test_simple_emulation() {
    let shared = Arc::new(RwLock::new(EmulatorSharedState::new(Vec::new())));
    let mut emu = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, shared).unwrap();

    emu.mem_map(0x1000, 0x1000, Prot::ALL).unwrap();

    // mov rax, 0x1234; ret
    let code: [u8; 12] = [
        0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00,
        0xC3, 0x90, 0x90, 0x90, 0x90,
    ];
    emu.mem_write(0x1000, &code).unwrap();

    emu.mem_map(0x7FFF0000, 0x1000, Prot::ALL).unwrap();
    emu.reg_write(RegisterX86::RSP, 0x7FFF0FF0u64).unwrap();
    emu.mem_write(0x7FFF0FF0, &0x1100u64.to_le_bytes()).unwrap();

    let result = emu.emu_start(0x1000, 0x1100, 0, 10);
    assert!(result.is_ok());

    let rax: u64 = emu.reg_read(RegisterX86::RAX).unwrap();
    assert_eq!(rax, 0x1234);
}
