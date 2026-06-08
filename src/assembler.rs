use crate::interfaces::Architecture;
use keystone_engine::{Keystone, Arch, Mode, OptionType, OptionValue};

pub struct AssembleOutput {
    pub bytes: Vec<u8>,
    pub stat_count: u32,
}

#[derive(Debug)]
pub struct AssembleError {
    pub message: String,
}

impl std::fmt::Display for AssembleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AssembleError {}

pub fn assemble(arch: Architecture, code: &str, address: u64) -> Result<AssembleOutput, AssembleError> {
    let map_err = |e: keystone_engine::KeystoneError| AssembleError {
        message: format!("{}", e),
    };

    match arch {
        Architecture::X64 => assemble_x64(code, address),
        Architecture::Arm64 => {
            let engine = Keystone::new(Arch::ARM64, Mode::LITTLE_ENDIAN).map_err(map_err)?;
            let output = engine.asm(code.to_string(), address).map_err(map_err)?;
            Ok(AssembleOutput {
                bytes: output.bytes,
                stat_count: output.stat_count,
            })
        }
    }
}

/// Assemble x86-64 code with proper RIP-relative address handling.
///
/// Keystone's NASM mode with `default rel` treats `[addr]` values as raw
/// RIP displacements rather than absolute addresses. To work around this,
/// we process each statement individually: for statements containing bare
/// `[0xADDR]` memory operands, we compute the correct RIP-relative
/// displacement via a two-pass approach (first pass to get instruction
/// length, second pass with the computed displacement).
///
/// Input may use Intel syntax (e.g. `qword ptr [rsp+8]` from Capstone
/// disassembly). We automatically strip `ptr` since NASM doesn't use it.
fn assemble_x64(code: &str, address: u64) -> Result<AssembleOutput, AssembleError> {
    let map_err = |e: keystone_engine::KeystoneError| AssembleError {
        message: format!("{}", e),
    };

    let engine = Keystone::new(Arch::X86, Mode::MODE_64).map_err(map_err)?;
    engine
        .option(OptionType::SYNTAX, OptionValue::SYNTAX_NASM)
        .map_err(map_err)?;

    let statements = split_statements(code);
    let mut output_bytes = Vec::new();
    let mut stat_count = 0u32;

    for statement in &statements {
        let trimmed = statement.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Strip Intel-style "ptr" keyword (NASM doesn't use it).
        // "qword ptr [rsp+8]" → "qword [rsp+8]"
        let trimmed = &strip_intel_ptr(trimmed);

        let current_addr = address + output_bytes.len() as u64;

        if let Some((target_addr, prefix, suffix)) = extract_bracket_address(trimmed) {
            // Two-pass for absolute address operands:
            // Pass 1: assemble with dummy displacement to get instruction length
            let dummy_code = format!("default rel\n{}[0x0]{}", prefix, suffix);
            let dummy_result = engine.asm(dummy_code, current_addr).map_err(map_err)?;
            let instr_len = dummy_result.bytes.len() as u64;

            // Compute correct RIP-relative displacement
            let rip_next = current_addr + instr_len;
            let disp64 = target_addr as i64 - rip_next as i64;
            if disp64 > i32::MAX as i64 || disp64 < i32::MIN as i64 {
                return Err(AssembleError {
                    message: format!(
                        "Target address 0x{:x} is too far from code address 0x{:x} \
                         for RIP-relative encoding (displacement 0x{:x} exceeds 32 bits)",
                        target_addr, current_addr, disp64
                    ),
                });
            }

            // Pass 2: assemble with correct displacement (as unsigned 32-bit hex)
            let disp32 = disp64 as i32 as u32;
            let fixed_code = format!("default rel\n{}[0x{:x}]{}", prefix, disp32, suffix);
            let result = engine.asm(fixed_code, current_addr).map_err(map_err)?;
            stat_count += 1;
            output_bytes.extend_from_slice(&result.bytes);
        } else {
            // No absolute address — assemble directly
            let asm_code = format!("default rel\n{}", trimmed);
            let result = engine.asm(asm_code, current_addr).map_err(map_err)?;
            stat_count += result.stat_count;
            output_bytes.extend_from_slice(&result.bytes);
        }
    }

    if output_bytes.is_empty() {
        return Err(AssembleError {
            message: "Assembly produced no output".to_string(),
        });
    }

    Ok(AssembleOutput {
        bytes: output_bytes,
        stat_count,
    })
}

/// Strip Intel-syntax `ptr` keyword from assembly text.
/// Converts e.g. `qword ptr [rsp+8]` → `qword [rsp+8]`.
fn strip_intel_ptr(s: &str) -> String {
    let lower = s.to_lowercase();
    let mut result = String::with_capacity(s.len());
    let mut i = 0;
    let chars: Vec<char> = s.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();

    while i < chars.len() {
        // Look for " ptr" followed by space or '['
        if i + 4 <= chars.len()
            && lower_chars[i] == ' '
            && lower_chars[i + 1] == 'p'
            && lower_chars[i + 2] == 't'
            && lower_chars[i + 3] == 'r'
        {
            let after = if i + 4 < chars.len() { lower_chars[i + 4] } else { '\0' };
            if after == ' ' || after == '[' || after == '\0' {
                // Skip " ptr" but keep the leading space
                result.push(' ');
                // Also skip trailing space after ptr to avoid double spaces
                i += if after == ' ' { 5 } else { 4 };
                continue;
            }
        }
        result.push(chars[i]);
        i += 1;
    }
    result
}

/// Split assembly code into individual statements by newlines and semicolons.
fn split_statements(code: &str) -> Vec<String> {
    let mut statements = Vec::new();
    for line in code.lines() {
        for part in line.split(';') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                statements.push(trimmed.to_string());
            }
        }
    }
    statements
}

/// Check if a statement contains a bare absolute hex address in brackets
/// like `[0x7ff64cff8004]`. Returns `(address, prefix, suffix)` where
/// prefix is everything before `[` and suffix is everything after `]`.
///
/// Does NOT match register-based operands like `[rax+0x10]` or operands
/// that already use `rel`.
fn extract_bracket_address(statement: &str) -> Option<(u64, &str, &str)> {
    let open = statement.find('[')?;
    let close = statement[open..].find(']')? + open;

    let inside = statement[open + 1..close].trim();

    // Skip if it contains `rel` (already relative)
    if inside.contains("rel") || inside.contains("REL") {
        return None;
    }

    // Must be just a hex literal: 0x followed by hex digits
    let hex_str = inside.trim();
    if !hex_str.starts_with("0x") && !hex_str.starts_with("0X") {
        return None;
    }

    let digits = &hex_str[2..];
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    // Must be a "large" address (> 32-bit) to need rewriting, but we
    // handle all bare addresses for correctness since keystone never
    // computes the displacement correctly with `default rel`.
    let addr = u64::from_str_radix(digits, 16).ok()?;

    let prefix = &statement[..open];
    let suffix = &statement[close + 1..];
    Some((addr, prefix, suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bracket_address() {
        // Bare hex address
        let (addr, pre, suf) = extract_bracket_address("mov eax, [0x1000]").unwrap();
        assert_eq!(addr, 0x1000);
        assert_eq!(pre, "mov eax, ");
        assert_eq!(suf, "");

        // With size prefix
        let (addr, pre, suf) = extract_bracket_address("mov eax, dword [0x1000]").unwrap();
        assert_eq!(addr, 0x1000);
        assert_eq!(pre, "mov eax, dword ");
        assert_eq!(suf, "");

        // Large address
        let (addr, _, _) = extract_bracket_address("mov eax, [0x7ff64cff8004]").unwrap();
        assert_eq!(addr, 0x7ff64cff8004);

        // Register-based — should return None
        assert!(extract_bracket_address("mov eax, [rax+0x10]").is_none());

        // Already has rel — should return None
        assert!(extract_bracket_address("mov eax, [rel 0x1000]").is_none());

        // No brackets
        assert!(extract_bracket_address("mov eax, 2").is_none());

        // Not a hex address
        assert!(extract_bracket_address("mov eax, [rsp]").is_none());
    }

    #[test]
    fn test_assemble_x64_basic() {
        let result = assemble(Architecture::X64, "nop", 0).unwrap();
        assert_eq!(result.bytes, vec![0x90]);
    }

    #[test]
    fn test_assemble_x64_mov_ret() {
        let result = assemble(Architecture::X64, "mov eax, 2\nret", 0).unwrap();
        assert_eq!(result.bytes, vec![0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3]);
    }

    #[test]
    fn test_assemble_x64_rip_relative() {
        // Assemble `mov eax, [0x1000]` at address 0x100
        // Expected: RIP-relative encoding where disp32 = 0x1000 - (0x100 + 6) = 0xEFA
        let result = assemble(Architecture::X64, "mov eax, [0x1000]", 0x100).unwrap();
        assert_eq!(result.bytes[0], 0x8B);
        assert_eq!(result.bytes[1], 0x05);
        let disp = i32::from_le_bytes([
            result.bytes[2],
            result.bytes[3],
            result.bytes[4],
            result.bytes[5],
        ]);
        assert_eq!(disp, 0xEFA, "RIP-relative displacement should be 0xEFA");
    }

    #[test]
    fn test_assemble_x64_rip_relative_high_address() {
        // Test with high 64-bit addresses (typical user-space addresses on Windows)
        let base = 0x7FF600000100u64;
        let target = 0x7FF600001000u64;
        let code = format!("mov eax, [0x{:x}]", target);
        let result = assemble(Architecture::X64, &code, base).unwrap();
        assert_eq!(result.bytes[0], 0x8B);
        assert_eq!(result.bytes[1], 0x05);
        let disp = i32::from_le_bytes([
            result.bytes[2],
            result.bytes[3],
            result.bytes[4],
            result.bytes[5],
        ]);
        let expected_disp = (target as i64 - (base + 6) as i64) as i32;
        assert_eq!(disp, expected_disp);
    }

    #[test]
    fn test_assemble_x64_invalid_register() {
        // rbxxxx is not a valid register - must be rejected
        let result = assemble(Architecture::X64, "mov qword [rsp + 8], rbxxxx", 0x1000);
        assert!(result.is_err(), "Expected error for invalid register 'rbxxxx', got {:?}", result.as_ref().map(|r| &r.bytes));

        // Also test with Intel "ptr" syntax (what Capstone outputs)
        let result_ptr = assemble(Architecture::X64, "mov qword ptr [rsp + 8], rbxxxx", 0x1000);
        assert!(result_ptr.is_err(), "Expected error for invalid register 'rbxxxx' with ptr syntax, got {:?}", result_ptr.as_ref().map(|r| &r.bytes));
    }

    #[test]
    fn test_assemble_x64_intel_ptr_syntax() {
        // Intel "ptr" syntax (from Capstone) must work after automatic stripping
        let result = assemble(Architecture::X64, "mov qword ptr [rsp + 8], rbx", 0x1000).unwrap();
        assert!(!result.bytes.is_empty());

        let nasm_result = assemble(Architecture::X64, "mov qword [rsp + 8], rbx", 0x1000).unwrap();
        assert_eq!(result.bytes, nasm_result.bytes, "ptr syntax should produce same bytes as NASM syntax");
    }

    #[test]
    fn test_strip_intel_ptr() {
        assert_eq!(strip_intel_ptr("mov qword ptr [rsp + 8], rbx"), "mov qword [rsp + 8], rbx");
        assert_eq!(strip_intel_ptr("mov DWORD PTR [rax], 1"), "mov DWORD [rax], 1");
        assert_eq!(strip_intel_ptr("mov byte ptr[rcx], 0"), "mov byte [rcx], 0");
        // No ptr — unchanged
        assert_eq!(strip_intel_ptr("mov qword [rsp + 8], rbx"), "mov qword [rsp + 8], rbx");
        assert_eq!(strip_intel_ptr("nop"), "nop");
    }

    #[test]
    fn test_assemble_x64_rip_relative_with_ret() {
        // Multiple instructions: mov eax, [addr]; ret
        let base = 0x7FF600000100u64;
        let target = 0x7FF600001000u64;
        let code = format!("mov eax, [0x{:x}]\nret", target);
        let result = assemble(Architecture::X64, &code, base).unwrap();

        // First 6 bytes: mov eax, [rip+disp32]
        assert_eq!(result.bytes[0], 0x8B);
        assert_eq!(result.bytes[1], 0x05);
        let disp = i32::from_le_bytes([
            result.bytes[2],
            result.bytes[3],
            result.bytes[4],
            result.bytes[5],
        ]);
        let expected_disp = (target as i64 - (base + 6) as i64) as i32;
        assert_eq!(disp, expected_disp);

        // Last byte: ret
        assert_eq!(*result.bytes.last().unwrap(), 0xC3);
    }
}
