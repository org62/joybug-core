use crate::interfaces::{Architecture, PlatformError, SymbolInfo, symbolize_operands};
use crate::protocol::{DereferenceEntry, DereferenceValue};
use std::collections::HashSet;

/// Maximum depth for pointer chain traversal
const MAX_CHAIN_DEPTH: usize = 8;

/// Minimum address considered a valid pointer (below this is null guard page)
const MIN_VALID_POINTER: u64 = 0x10000;

/// Maximum string length to read
const MAX_STRING_LEN: usize = 64;

/// Dereference memory starting at `address` for `count` consecutive pointer-sized slots.
/// Returns a vector of DereferenceEntry, one for each slot examined.
///
/// If `symbol_resolver` is provided, instruction operands will be symbolized.
pub(super) fn dereference<F>(
    pid: u32,
    address: u64,
    count: usize,
    reference_base: Option<u64>,
    arch: Architecture,
    symbol_resolver: Option<F>,
) -> Result<Vec<DereferenceEntry>, PlatformError>
where
    F: Fn(u64) -> Option<SymbolInfo>,
{
    let pointer_size: usize = match arch {
        Architecture::X64 | Architecture::Arm64 => 8,
    };
    let base = reference_base.unwrap_or(address);

    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        let slot_addr = address.wrapping_add((i * pointer_size) as u64);
        let offset = (slot_addr as i64).wrapping_sub(base as i64);

        let chain = build_dereference_chain(pid, slot_addr, arch, &symbol_resolver)?;

        entries.push(DereferenceEntry {
            address: slot_addr,
            offset,
            chain,
        });
    }

    Ok(entries)
}

/// Build the dereference chain for a single address
fn build_dereference_chain<F>(
    pid: u32,
    start_address: u64,
    arch: Architecture,
    symbol_resolver: &Option<F>,
) -> Result<Vec<DereferenceValue>, PlatformError>
where
    F: Fn(u64) -> Option<SymbolInfo>,
{
    let pointer_size: usize = match arch {
        Architecture::X64 | Architecture::Arm64 => 8,
    };

    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut current_addr = start_address;

    for _depth in 0..MAX_CHAIN_DEPTH {
        // Check for loop
        if visited.contains(&current_addr) {
            chain.push(DereferenceValue::LoopDetected(current_addr));
            break;
        }
        visited.insert(current_addr);

        // Try to read the value at current address
        let value = match read_pointer(pid, current_addr, pointer_size) {
            Ok(v) => v,
            Err(_) => {
                // Memory not readable - end of chain
                break;
            }
        };

        // Check if the value points to readable memory (i.e., is a valid pointer)
        // A pointer is only a pointer if we can dereference it
        let can_read_target = value >= MIN_VALID_POINTER
            && read_pointer(pid, value, pointer_size).is_ok();

        if !can_read_target {
            // Not a dereferenceable pointer - check for string/instruction or output as Value
            if let Some(s) = try_read_string(pid, value) {
                chain.push(DereferenceValue::String(s));
            } else if let Some(instr) = try_read_instruction(pid, value, arch, symbol_resolver) {
                chain.push(DereferenceValue::Instruction(instr));
            } else {
                chain.push(DereferenceValue::Value(value));
            }
            break;
        }

        // It's a valid pointer (we can read from the target address)
        // Try to resolve its symbol
        let symbol_str = symbol_resolver.as_ref().and_then(|resolver| {
            resolver(value).map(|info| info.format_symbol())
        });
        chain.push(DereferenceValue::Pointer(value, symbol_str));

        // Check if the target is a string
        if let Some(s) = try_read_string(pid, value) {
            chain.push(DereferenceValue::String(s));
            break;
        }

        // Check if the target is executable code
        if let Some(instr) = try_read_instruction(pid, value, arch, symbol_resolver) {
            chain.push(DereferenceValue::Instruction(instr));
            break;
        }

        // Continue chasing the pointer
        current_addr = value;
    }

    Ok(chain)
}

/// Read a pointer-sized value from memory
fn read_pointer(pid: u32, address: u64, size: usize) -> Result<u64, PlatformError> {
    let data = super::memory::read_memory_unlocked(pid, address, size)?;
    if data.len() < size {
        return Err(PlatformError::Other("Partial read".to_string()));
    }

    let value = match size {
        8 => u64::from_le_bytes(data[..8].try_into().unwrap()),
        4 => u32::from_le_bytes(data[..4].try_into().unwrap()) as u64,
        _ => return Err(PlatformError::Other("Unsupported pointer size".to_string())),
    };

    Ok(value)
}

/// Try to read a string at the given address
fn try_read_string(pid: u32, address: u64) -> Option<String> {
    // First try ASCII string
    if let Some(s) = try_read_ascii_string(pid, address) {
        return Some(s);
    }

    // Then try UTF-16 string
    if let Some(s) = try_read_utf16_string(pid, address) {
        return Some(s);
    }

    None
}

/// Try to read an ASCII string at the given address
fn try_read_ascii_string(pid: u32, address: u64) -> Option<String> {
    let data = super::memory::read_memory_unlocked(pid, address, MAX_STRING_LEN).ok()?;

    if data.is_empty() {
        return None;
    }

    // Check if it looks like a printable ASCII string
    let mut end = 0;
    for (i, &byte) in data.iter().enumerate() {
        if byte == 0 {
            end = i;
            break;
        }
        // Must be printable ASCII (space to tilde) or common whitespace
        if !((0x20..=0x7E).contains(&byte) || byte == b'\t' || byte == b'\n' || byte == b'\r') {
            return None;
        }
        end = i + 1;
    }

    // Must have at least 4 printable characters to be considered a string
    if end < 4 {
        return None;
    }

    let s = String::from_utf8_lossy(&data[..end]).to_string();
    Some(format!("\"{}\"", s))
}

/// Try to read a UTF-16 string at the given address
/// Only accepts ASCII-range characters (English text) to avoid false positives
fn try_read_utf16_string(pid: u32, address: u64) -> Option<String> {
    let data = super::memory::read_memory_unlocked(pid, address, MAX_STRING_LEN * 2).ok()?;

    if data.len() < 4 {
        return None;
    }

    // Parse as UTF-16LE - only accept ASCII printable characters
    let mut chars = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let c = u16::from_le_bytes([data[i], data[i + 1]]);
        if c == 0 {
            break;
        }
        // Only accept printable ASCII (space to tilde) or common whitespace
        // This avoids false positives from random memory that happens to have
        // bytes that decode to valid but nonsensical Unicode
        if !((0x20..=0x7E).contains(&c) || c == 0x09 || c == 0x0A || c == 0x0D) {
            return None;
        }
        chars.push(c);
        i += 2;
    }

    // Must have at least 4 characters
    if chars.len() < 4 {
        return None;
    }

    let s = String::from_utf16_lossy(&chars);
    Some(format!("L\"{}\"", s))
}

/// Try to disassemble an instruction at the given address
fn try_read_instruction<F>(
    pid: u32,
    address: u64,
    arch: Architecture,
    symbol_resolver: &Option<F>,
) -> Option<String>
where
    F: Fn(u64) -> Option<SymbolInfo>,
{
    // Check if the memory is executable
    let region = super::memory::query_memory_region_unlocked(pid, address).ok()?;

    // Check for executable protection flags (PAGE_EXECUTE*)
    // PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80
    let is_executable = (region.protect & 0xF0) != 0;
    if !is_executable {
        return None;
    }

    // Read enough bytes for one instruction (max instruction size)
    let max_instr_size = match arch {
        Architecture::X64 => 15,  // x86-64 max instruction length
        Architecture::Arm64 => 4, // ARM64 fixed instruction size
    };

    let data = super::memory::read_memory_unlocked(pid, address, max_instr_size).ok()?;
    if data.is_empty() {
        return None;
    }

    // Try to disassemble using capstone
    use crate::windows_platform::disassembler::CapstoneDisassembler;
    use crate::interfaces::DisassemblerProvider;

    let disasm = CapstoneDisassembler::new().ok()?;
    let instructions = disasm.disassemble(arch, &data, address, 1).ok()?;

    if let Some(instr) = instructions.first() {
        let raw_instr = if instr.op_str.is_empty() {
            instr.mnemonic.clone()
        } else {
            format!("{} {}", instr.mnemonic, instr.op_str)
        };

        // Symbolize operands if resolver is available
        if let Some(resolver) = symbol_resolver {
            Some(symbolize_operands(&raw_instr, resolver))
        } else {
            Some(raw_instr)
        }
    } else {
        None
    }
}
