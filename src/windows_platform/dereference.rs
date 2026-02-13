use crate::interfaces::{Architecture, PlatformError, SymbolInfo};
use crate::protocol::{DereferenceEntry, DereferenceValue, MemoryRegionInfo};
use std::collections::HashSet;

/// Maximum depth for pointer chain traversal
const MAX_CHAIN_DEPTH: usize = 8;

/// Maximum string length to read
const MAX_STRING_LEN: usize = 64;

/// Windows memory state constants
const MEM_COMMIT: u32 = 0x1000;

/// Windows page protection constants
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_GUARD: u32 = 0x100;

/// Maximum valid user-mode address on x64 Windows
const MAX_USER_MODE_ADDRESS: u64 = 0x00007FFFFFFFFFFF;

/// Find the region containing the given address using binary search
fn find_region(regions: &[MemoryRegionInfo], address: u64) -> Option<&MemoryRegionInfo> {
    // Quick check: address must be within valid user-mode range
    if address == 0 || address > MAX_USER_MODE_ADDRESS {
        return None;
    }

    // Binary search for the region where base_address <= address
    let idx = match regions.binary_search_by(|r| r.base_address.cmp(&address)) {
        Ok(i) => i, // Exact match on base_address
        Err(0) => return None, // Address is before all regions
        Err(i) => i - 1, // Address is after regions[i-1].base_address
    };

    let region = &regions[idx];

    // Check if address is within this region
    if address >= region.base_address && address < region.base_address + region.region_size {
        Some(region)
    } else {
        None
    }
}

/// Check if an address is in a readable memory region
fn is_readable(regions: &[MemoryRegionInfo], address: u64) -> bool {
    let region = match find_region(regions, address) {
        Some(r) => r,
        None => return false,
    };

    // Must be committed memory
    if region.state != MEM_COMMIT {
        return false;
    }

    // Check protection - must not be NOACCESS or have GUARD flag
    if region.protect == PAGE_NOACCESS || (region.protect & PAGE_GUARD) != 0 {
        return false;
    }

    true
}

/// Check if an address is in an executable memory region
fn is_executable(regions: &[MemoryRegionInfo], address: u64) -> bool {
    let region = match find_region(regions, address) {
        Some(r) => r,
        None => return false,
    };

    // Must be committed memory
    if region.state != MEM_COMMIT {
        return false;
    }

    // Check for executable protection flags (PAGE_EXECUTE*)
    // PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80
    (region.protect & 0xF0) != 0
}

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

    // Query all memory regions once upfront
    let regions = super::memory::enumerate_memory_regions_unlocked(pid)?;

    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        let slot_addr = address.wrapping_add((i * pointer_size) as u64);
        let offset = (slot_addr as i64).wrapping_sub(base as i64);

        let chain = build_dereference_chain(pid, slot_addr, arch, &symbol_resolver, &regions)?;

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
    regions: &[MemoryRegionInfo],
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

    // Check if start_address itself contains recognizable data (string/instruction)
    // before trying to read it as a pointer. This handles registers pointing directly
    // to strings, where we want to show the string content, not interpret string bytes
    // as a pointer value.
    if let Some(s) = try_read_string(pid, start_address, regions) {
        return Ok(vec![DereferenceValue::String(s)]);
    }
    if let Some((instr, symbol)) = try_read_instruction(pid, start_address, arch, symbol_resolver, regions) {
        return Ok(vec![DereferenceValue::Instruction(instr, symbol)]);
    }

    for _depth in 0..MAX_CHAIN_DEPTH {
        // Check for loop
        if visited.contains(&current_addr) {
            chain.push(DereferenceValue::LoopDetected(current_addr));
            break;
        }
        visited.insert(current_addr);

        // Check if address is readable before attempting to read
        if !is_readable(regions, current_addr) {
            // Address not in a readable region - end of chain
            break;
        }

        // Try to read the value at current address
        let value = match read_pointer(pid, current_addr, pointer_size) {
            Ok(v) => v,
            Err(_) => {
                // Memory read failed - end of chain
                break;
            }
        };

        // Check if the value points to readable memory (i.e., is a valid pointer)
        let can_read_target = is_readable(regions, value);

        if !can_read_target {
            // Not a dereferenceable pointer - check for string/instruction or output as Value
            if let Some(s) = try_read_string(pid, value, regions) {
                chain.push(DereferenceValue::String(s));
            } else if let Some((instr, symbol)) = try_read_instruction(pid, value, arch, symbol_resolver, regions) {
                chain.push(DereferenceValue::Instruction(instr, symbol));
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
        if let Some(s) = try_read_string(pid, value, regions) {
            chain.push(DereferenceValue::String(s));
            break;
        }

        // Check if the target is executable code
        if let Some((instr, symbol)) = try_read_instruction(pid, value, arch, symbol_resolver, regions) {
            chain.push(DereferenceValue::Instruction(instr, symbol));
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
fn try_read_string(pid: u32, address: u64, regions: &[MemoryRegionInfo]) -> Option<String> {
    // Check if the address is in a readable memory region
    if !is_readable(regions, address) {
        return None;
    }

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
/// Returns (disassembly_text, optional_symbol)
fn try_read_instruction<F>(
    pid: u32,
    address: u64,
    arch: Architecture,
    symbol_resolver: &Option<F>,
    regions: &[MemoryRegionInfo],
) -> Option<(String, Option<String>)>
where
    F: Fn(u64) -> Option<SymbolInfo>,
{
    // Check if the address is in an executable memory region
    if !is_executable(regions, address) {
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
        let mut op_str = instr.op_str.clone();

        // Symbolize operand addresses using pre-extracted address list (no regex)
        if let Some(resolver) = symbol_resolver {
            for addr in &instr.addresses_to_symbolize {
                if let Some(symbol) = resolver(*addr) {
                    let symbol_str = symbol.format_symbol();
                    let hex_lower = format!("0x{:x}", addr);
                    let hex_upper = format!("0x{:X}", addr);
                    let before = op_str.clone();
                    op_str = op_str.replace(&hex_lower, &symbol_str);
                    op_str = op_str.replace(&hex_upper, &symbol_str);

                    // Fallback: RIP-relative pattern replacement
                    if op_str == before {
                        let disp = (*addr).wrapping_sub(instr.address + instr.size as u64) as i64;
                        let (pattern, replacement) = if disp >= 0 {
                            (format!("[rip + 0x{:x}]", disp), format!("[{}]", symbol_str))
                        } else {
                            (format!("[rip - 0x{:x}]", disp.unsigned_abs()), format!("[{}]", symbol_str))
                        };
                        op_str = op_str.replace(&pattern, &replacement);
                    }
                }
            }
        }

        // Resolve symbol for the instruction's address itself
        let instr_symbol = symbol_resolver.as_ref().and_then(|resolver| {
            resolver(address).map(|info| info.format_symbol())
        });

        let disasm_text = if op_str.is_empty() {
            instr.mnemonic.clone()
        } else {
            format!("{} {}", instr.mnemonic, op_str)
        };

        Some((disasm_text, instr_symbol))
    } else {
        None
    }
}
