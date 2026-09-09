//! The `pe` global: offline PE analysis from Lua, with no server and no
//! process. `pe.open(path)` returns an image object whose methods mirror the
//! `dbg:*` disassembly/memory API but read the file's mapped image, plus
//! xrefs, function recovery, byte-pattern search and process-less emulation.

use std::path::Path;

use mlua::prelude::*;

use crate::emulator::{EmulationResult, ImportPolicy};
use crate::interfaces::{Architecture, ResolvedSymbol};
use crate::protocol::{EmulationMode, StringEncodingFilter};
use crate::static_pe::{EmulateSpec, PeImage};

use super::debug_client::{
    arch_name, emulation_result_to_lua_table, instruction_to_lua_table, memory_reads_from_lua,
    register_snapshot_to_lua_table, resolved_symbol_to_lua_table,
};
use super::opt;

/// `pe.open()` result. Mutating calls (`load_pdb`) go through `add_method_mut`.
pub struct LuaPeImage(PeImage);

fn ext<E: std::fmt::Display>(e: E) -> LuaError {
    LuaError::external(anyhow::anyhow!("{}", e))
}

fn instructions_table(lua: &Lua, instrs: &[crate::interfaces::Instruction]) -> LuaResult<LuaTable> {
    let t = lua.create_table()?;
    for (i, inst) in instrs.iter().enumerate() {
        t.set(i + 1, instruction_to_lua_table(lua, inst)?)?;
    }
    Ok(t)
}

fn symbol_table(lua: &Lua, img: &PeImage, s: &crate::interfaces::ModuleSymbol) -> LuaResult<LuaTable> {
    resolved_symbol_to_lua_table(lua, &ResolvedSymbol {
        name: s.name.clone(),
        module_name: img.module_name().to_string(),
        rva: s.rva,
        va: img.base() + s.rva as u64,
        is_function: s.is_function,
    })
}

fn xrefs_table(lua: &Lua, xrefs: &[crate::static_pe::Xref]) -> LuaResult<LuaTable> {
    let out = lua.create_table()?;
    for x in xrefs {
        let t = lua.create_table()?;
        t.set("from", x.from)?;
        t.set("to", x.to)?;
        t.set("kind", x.kind.as_str())?;
        out.push(t)?;
    }
    Ok(out)
}

/// The `dbg:emulate` result table plus `regs`, the import that stopped the
/// run, and the Tenet trace text in trace mode.
fn emulation_result_table(lua: &Lua, result: &EmulationResult, mode: EmulationMode, arch: Architecture) -> LuaResult<LuaTable> {
    let t = emulation_result_to_lua_table(
        lua, result.final_pc, result.instructions_executed, &result.stop_reason.to_string(),
        result.emulation_time_us, result.pages_loaded, &result.stats_text, &result.basic_blocks, &result.memory_snapshots,
    )?;
    t.set("regs", register_snapshot_to_lua_table(lua, &result.final_registers, arch)?)?;
    if let crate::emulator::StopReason::ImportCall { name, from } = &result.stop_reason {
        t.set("import", name.as_str())?;
        t.set("return_address", *from)?;
    }
    if mode == EmulationMode::InstructionTrace {
        t.set("trace", crate::tenet_format::traces_to_tenet(&result.register_trace, &result.memory_trace))?;
    }
    Ok(t)
}

/// `img:emulate(va, opts)` options → an `EmulateSpec`.
fn emulate_spec(va: u64, opts: Option<&LuaTable>) -> LuaResult<EmulateSpec> {
    let mut spec = EmulateSpec::at(va);
    if let Some(max) = opt::<usize>(opts, "max")? { spec.max_instructions = max; }
    if let Some(mode) = opt::<String>(opts, "mode")? { spec.mode = mode.parse().map_err(ext)?; }
    spec.exit = opt::<u64>(opts, "exit")?;
    if let Some(size) = opt::<u64>(opts, "stack_size")? { spec.stack_size = size; }
    let ret: u64 = opt(opts, "ret")?.unwrap_or(0);
    spec.import_policy = match opt::<String>(opts, "imports")?.as_deref().unwrap_or("stop") {
        "stop" => ImportPolicy::Stop,
        "skip" => ImportPolicy::Skip { value: ret },
        other => return Err(ext(format!("imports must be \"stop\" or \"skip\", got {:?}", other))),
    };
    if let Some(regs) = opt::<LuaTable>(opts, "regs")? {
        for pair in regs.pairs::<String, u64>() {
            let (name, value) = pair?;
            spec.registers.push((name, value));
        }
    }
    spec.memory_reads = memory_reads_from_lua(opt::<LuaTable>(opts, "mem_reads")?.as_ref())?;
    if let Some(writes) = opt::<LuaTable>(opts, "mem_writes")? {
        for i in 1..=writes.raw_len() {
            let entry: LuaTable = writes.get(i)?;
            let addr: u64 = entry.get(1).or_else(|_| entry.get("address"))?;
            let data: LuaString = entry.get(2).or_else(|_| entry.get("data"))?;
            spec.memory_writes.push((addr, data.as_bytes().to_vec()));
        }
    }
    Ok(spec)
}

impl LuaUserData for LuaPeImage {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        // ---- Identity ----
        methods.add_method("path", |_, this, ()| Ok(this.0.path().to_string()));
        methods.add_method("arch", |_, this, ()| Ok(arch_name(this.0.arch())));
        methods.add_method("base", |_, this, ()| Ok(this.0.base()));
        methods.add_method("size", |_, this, ()| Ok(this.0.image_size()));
        methods.add_method("file_size", |_, this, ()| Ok(this.0.file_size() as u64));
        methods.add_method("entry_point", |_, this, ()| Ok(this.0.entry_point()));
        methods.add_method("module_name", |_, this, ()| Ok(this.0.module_name().to_string()));

        // ---- Structure ----
        methods.add_method("sections", |lua, this, ()| {
            let img = &this.0;
            let out = lua.create_table()?;
            for s in &img.info().sections {
                let t = lua.create_table()?;
                t.set("name", s.name_string())?;
                t.set("va", img.base() + s.VirtualAddress as u64)?;
                t.set("rva", s.VirtualAddress)?;
                t.set("vsize", s.VirtualSize)?;
                t.set("raw", s.PointerToRawData)?;
                t.set("rsize", s.SizeOfRawData)?;
                t.set("chars", s.Characteristics)?;
                out.push(t)?;
            }
            Ok(out)
        });
        methods.add_method("imports", |lua, this, ()| {
            let out = lua.create_table()?;
            for imp in this.0.imports() {
                let t = lua.create_table()?;
                t.set("dll", imp.dll)?;
                t.set("name", imp.name)?;
                t.set("ordinal", imp.ordinal)?;
                t.set("iat_va", imp.iat_va)?;
                out.push(t)?;
            }
            Ok(out)
        });
        methods.add_method("exports", |lua, this, ()| {
            use crate::pe_types::ExportKind;
            let img = &this.0;
            let out = lua.create_table()?;
            if let Some(exports) = &img.info().exports {
                for e in &exports.entries {
                    let t = lua.create_table()?;
                    t.set("ordinal", e.ordinal)?;
                    t.set("name", e.name.clone())?;
                    match &e.kind {
                        ExportKind::Symbol { rva } => {
                            t.set("rva", *rva)?;
                            t.set("va", img.base() + *rva as u64)?;
                        }
                        ExportKind::Forward { target } => t.set("forward", target.as_str())?,
                        ExportKind::Error(err) => t.set("error", err.as_str())?,
                    }
                    out.push(t)?;
                }
            }
            Ok(out)
        });
        methods.add_method("resources", |lua, this, ()| {
            let out = lua.create_table()?;
            for r in this.0.resources() {
                let t = lua.create_table()?;
                t.set("type", r.type_name)?;
                t.set("name", r.name)?;
                t.set("lang", r.lang)?;
                t.set("rva", r.rva)?;
                t.set("va", r.va)?;
                t.set("size", r.size)?;
                t.set("code_page", r.code_page)?;
                out.push(t)?;
            }
            Ok(out)
        });
        methods.add_method("tls_callbacks", |lua, this, ()| {
            let img = &this.0;
            let out = lua.create_table()?;
            for &rva in &img.info().tls_callbacks {
                out.push(img.base() + rva as u64)?;
            }
            Ok(out)
        });

        // ---- Addresses & memory ----
        methods.add_method("va2off", |_, this, va: u64| Ok(this.0.va_to_offset(va).map(|o| o as u64)));
        methods.add_method("off2va", |_, this, off: u64| Ok(this.0.offset_to_va(off as usize)));
        methods.add_method("read", |lua, this, (va, len): (u64, usize)| {
            match this.0.read(va, len) {
                Some(bytes) => lua.create_string(bytes),
                None => Err(ext(format!("0x{:X}+{} is outside the image", va, len))),
            }
        });
        for (name, size) in [("read_u8", 1usize), ("read_u16", 2), ("read_u32", 4), ("read_u64", 8)] {
            methods.add_method(name, move |_, this, va: u64| {
                this.0.read_uint(va, size).ok_or_else(|| ext(format!("0x{:X} is outside the image", va)))
            });
        }
        // img:read_string(va[, max_chars]) — ASCII; img:read_wstring for UTF-16.
        methods.add_method("read_string", |_, this, (va, max): (u64, Option<usize>)| {
            this.0.read_string(va, false, max.unwrap_or(4096))
                .ok_or_else(|| ext(format!("0x{:X} is outside the image", va)))
        });
        methods.add_method("read_wstring", |_, this, (va, max): (u64, Option<usize>)| {
            this.0.read_string(va, true, max.unwrap_or(4096))
                .ok_or_else(|| ext(format!("0x{:X} is outside the image", va)))
        });

        // ---- Disassembly ----
        methods.add_method("disassemble", |lua, this, (va, count): (u64, Option<usize>)| {
            let instrs = this.0.disassemble(va, count.unwrap_or(10)).map_err(ext)?;
            instructions_table(lua, &instrs)
        });
        methods.add_method("disassemble_backward", |lua, this, (target, count): (u64, Option<usize>)| {
            let instrs = this.0.disassemble_backward(target, count.unwrap_or(10)).map_err(ext)?;
            instructions_table(lua, &instrs)
        });
        methods.add_method("disassemble_function", |lua, this, (va, max): (u64, Option<usize>)| {
            let (instrs, start, end, name) = this.0.disassemble_function(va, max.unwrap_or(1000)).map_err(ext)?;
            let t = lua.create_table()?;
            t.set("instructions", instructions_table(lua, &instrs)?)?;
            if let Some(s) = start { t.set("start", s)?; }
            if let Some(e) = end { t.set("end", e)?; }
            if let Some(n) = name { t.set("name", n)?; }
            Ok(t)
        });

        // ---- Search ----
        // img:strings{ min = 6, encoding = "ascii"|"utf16"|"both", contains = "", file = false }
        methods.add_method("strings", |lua, this, opts: Option<LuaTable>| {
            let opts = opts.as_ref();
            let min: usize = opt(opts, "min")?.unwrap_or(6);
            let enc: StringEncodingFilter = opt::<String>(opts, "encoding")?
                .map(|s| s.parse().map_err(ext)).transpose()?.unwrap_or_default();
            let contains: String = opt(opts, "contains")?.unwrap_or_default();
            let in_file: bool = opt(opts, "file")?.unwrap_or(false);
            let img = &this.0;
            let hits = if in_file { img.strings_in_file(min, enc, &contains) } else { img.strings(min, enc, &contains) };
            let out = lua.create_table()?;
            for h in hits {
                let t = lua.create_table()?;
                t.set("address", h.address)?;
                t.set("encoding", h.encoding.as_str())?;
                t.set("length", h.length)?;
                t.set("text", h.text)?;
                t.set("truncated", h.truncated)?;
                out.push(t)?;
            }
            Ok(out)
        });
        methods.add_method("find_bytes", |lua, this, (pattern, max): (String, Option<usize>)| {
            let hits = this.0.find_bytes(&pattern, max.unwrap_or(10_000)).map_err(ext)?;
            let out = lua.create_table()?;
            for (i, va) in hits.iter().enumerate() {
                out.set(i + 1, *va)?;
            }
            Ok(out)
        });

        // ---- Imports & xrefs ----
        methods.add_method("import_slot", |_, this, spec: String| Ok(this.0.import_slot(&spec)));
        methods.add_method("xrefs_to", |lua, this, va: u64| xrefs_table(lua, &this.0.xrefs_to(va)));
        methods.add_method("xrefs_from", |lua, this, va: u64| xrefs_table(lua, &this.0.xrefs_from(va)));
        methods.add_method("xrefs_to_import", |lua, this, spec: String| {
            let xrefs = this.0.xrefs_to_import(&spec)
                .ok_or_else(|| ext(format!("import {:?} not found in the import table", spec)))?;
            xrefs_table(lua, &xrefs)
        });
        methods.add_method("functions", |lua, this, ()| {
            let out = lua.create_table()?;
            for f in this.0.functions() {
                let t = lua.create_table()?;
                t.set("start", f.start)?;
                t.set("end", f.end)?;
                t.set("name", f.name.clone())?;
                t.set("source", f.source)?;
                out.push(t)?;
            }
            Ok(out)
        });

        // ---- Symbols ----
        // img:load_pdb([path]) -> loaded, count, error. Without a path, looks
        // next to the file, in the local cache and on the symbol server.
        methods.add_method_mut("load_pdb", |_, this, path: Option<String>| {
            let status = this.0.load_symbols(path.as_deref().map(Path::new), false);
            Ok((status.loaded, status.count as u64, status.error))
        });
        methods.add_method("has_symbols", |_, this, ()| Ok(this.0.has_symbols()));
        methods.add_method("symbols", |lua, this, (pattern, limit): (Option<String>, Option<usize>)| {
            let img = &this.0;
            let out = lua.create_table()?;
            for s in img.find_symbols(pattern.as_deref().unwrap_or(""), limit.unwrap_or(usize::MAX)) {
                out.push(symbol_table(lua, img, s)?)?;
            }
            Ok(out)
        });
        methods.add_method("find_symbol", |lua, this, name: String| {
            match this.0.find_symbol_exact(&name) {
                Some(s) => Ok(LuaValue::Table(symbol_table(lua, &this.0, s)?)),
                None => Ok(LuaValue::Nil),
            }
        });
        methods.add_method("resolve_address", |_, this, va: u64| {
            Ok(this.0.resolve_va(va).map(|s| s.format_symbol()))
        });

        // ---- Emulation ----
        // img:emu_layout([stack_size]) -> { stack_base, stack_top, sp, teb, sentinel, stub_base }
        methods.add_method("emu_layout", |lua, this, stack_size: Option<u64>| {
            let l = crate::static_pe::emu_layout(this.0.arch(), stack_size.unwrap_or(crate::static_pe::DEFAULT_STACK_SIZE));
            let t = lua.create_table()?;
            t.set("stack_base", l.stack_base)?;
            t.set("stack_top", l.stack_top)?;
            t.set("sp", l.sp)?;
            t.set("teb", l.teb)?;
            t.set("sentinel", l.sentinel)?;
            t.set("stub_base", l.stub_base)?;
            Ok(t)
        });
        methods.add_method("emulate", |lua, this, (va, opts): (u64, Option<LuaTable>)| {
            let spec = emulate_spec(va, opts.as_ref())?;
            let result = this.0.emulate(&spec).map_err(ext)?;
            emulation_result_table(lua, &result, spec.mode, this.0.arch())
        });
    }
}

/// Register the `pe` table.
pub fn register_pe_functions(lua: &Lua) -> LuaResult<()> {
    let pe = lua.create_table()?;
    // pe.open(path[, { base = 0x400000, pdb = "..." }])
    pe.set("open", lua.create_function(|lua, (path, opts): (String, Option<LuaTable>)| {
        let opts = opts.as_ref();
        let base: Option<u64> = opt(opts, "base")?;
        let pdb: Option<String> = opt(opts, "pdb")?;
        let img = PeImage::open(&path, base, pdb.as_deref().map(Path::new)).map_err(ext)?;
        lua.create_userdata(LuaPeImage(img))
    })?)?;
    lua.globals().set("pe", pe)?;
    Ok(())
}
