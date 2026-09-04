use crate::interfaces::PlatformError;
use crate::pe_types::{DosHeader as SerDosHeader, ImageFileHeader as SerImageFileHeader, ImageOptionalHeader as SerImageOptionalHeader, ImageDataDirectory as SerImageDataDirectory, NtHeaders as SerNtHeaders, ModuleExtraInfo, ImportDescriptorInfo, ImportEntry, ImportItem, ImportKind, ExportInfo, ExportEntry, ExportKind, RuntimeFunction};
use super::WindowsPlatform;
use pelite::pe64::exception_arm64::Arm64ExceptionExt;
// The pe64 `Pe` trait is only needed for the exception directory, which is
// read on the `Wrap::T64` arm; everything else goes through the format-agnostic
// `pelite::PeFile` wrap (32-bit and 64-bit images alike).
use pelite::pe64::Pe as _;
use pelite::{PeFile, Wrap};
use tracing::trace;
use windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_ARM64;

impl WindowsPlatform {

    pub(crate) fn parse_module_extra_info(&self, pid: u32, module_base: u64) -> Result<ModuleExtraInfo, PlatformError> {
        // Resolve module path from our manager
        let modules = self.modules_for(pid);
        let module_path = modules.iter().find(|m| m.base == module_base).map(|m| m.name.clone())
            .ok_or_else(|| PlatformError::Other("Module not found at base".to_string()))?;

        // Read file bytes and delegate to the byte-based parser
        let file_bytes = std::fs::read(&module_path)
            .map_err(|e| PlatformError::Other(format!("Failed to read module file '{}': {}", module_path, e)))?;
        trace!({module_path, file_size = file_bytes.len()}, "Reading module extra info");
        parse_module_extra_info_from_bytes(&file_bytes)
    }
}

/// Parse a PE image (PE32 or PE32+) from raw file bytes into serializable extra info.
///
/// This is the session-independent core of [`WindowsPlatform::parse_module_extra_info`]:
/// it maps pelite headers/sections/imports/exports/exception-directory into our
/// `ModuleExtraInfo` without requiring a debug session or loaded module. Both
/// 32-bit and 64-bit images are handled; PE32's narrower header fields are widened
/// into the shared wire struct and `ImageOptionalHeader::is_pe32` tells them apart.
pub fn parse_module_extra_info_from_bytes(file_bytes: &[u8]) -> Result<ModuleExtraInfo, PlatformError> {
        let pe = PeFile::from_bytes(file_bytes)
            .map_err(|e| PlatformError::Other(format!("pelite failed to parse PE: {:?}", e)))?;
        let is_pe32 = matches!(pe, Wrap::T32(_));

        // Map pelite headers into our serializable types
        let dos = pe.dos_header();
        let file_header = pe.file_header();

        let dos_header = SerDosHeader {
            e_magic: dos.e_magic,
            e_cblp: dos.e_cblp,
            e_cp: dos.e_cp,
            e_crlc: dos.e_crlc,
            e_cparhdr: dos.e_cparhdr,
            e_minalloc: dos.e_minalloc,
            e_maxalloc: dos.e_maxalloc,
            e_ss: dos.e_ss,
            e_sp: dos.e_sp,
            e_csum: dos.e_csum,
            e_ip: dos.e_ip,
            e_cs: dos.e_cs,
            e_lfarlc: dos.e_lfarlc,
            e_ovno: dos.e_ovno,
            e_res: dos.e_res,
            e_oemid: dos.e_oemid,
            e_oeminfo: dos.e_oeminfo,
            e_res2: dos.e_res2,
            e_lfanew: dos.e_lfanew as i32,
        };

        let image_file_header = SerImageFileHeader {
            Machine: file_header.Machine,
            NumberOfSections: file_header.NumberOfSections,
            TimeDateStamp: file_header.TimeDateStamp,
            PointerToSymbolTable: file_header.PointerToSymbolTable,
            NumberOfSymbols: file_header.NumberOfSymbols,
            SizeOfOptionalHeader: file_header.SizeOfOptionalHeader,
            Characteristics: file_header.Characteristics,
        };

        // Data directories: pelite exposes the already-clamped slice for both formats
        // (the in-struct array is declared 0-length).
        let mut data_directory = [SerImageDataDirectory { VirtualAddress: 0, Size: 0 }; 16];
        for (out, dir) in data_directory.iter_mut().zip(pe.data_directory().iter()) {
            *out = SerImageDataDirectory { VirtualAddress: dir.VirtualAddress, Size: dir.Size };
        }

        // The two optional-header layouts share every field name except `BaseOfData`
        // (PE32 only) and the width of ImageBase / SizeOfStack* / SizeOfHeap*, so one
        // builder serves both arms; the narrow PE32 fields widen losslessly.
        macro_rules! optional_header {
            ($oh:expr, $base_of_data:expr) => {
                SerImageOptionalHeader {
                    Magic: $oh.Magic,
                    MajorLinkerVersion: $oh.LinkerVersion.Major,
                    MinorLinkerVersion: $oh.LinkerVersion.Minor,
                    SizeOfCode: $oh.SizeOfCode,
                    SizeOfInitializedData: $oh.SizeOfInitializedData,
                    SizeOfUninitializedData: $oh.SizeOfUninitializedData,
                    AddressOfEntryPoint: $oh.AddressOfEntryPoint,
                    BaseOfCode: $oh.BaseOfCode,
                    BaseOfData: $base_of_data,
                    ImageBase: $oh.ImageBase as u64,
                    SectionAlignment: $oh.SectionAlignment,
                    FileAlignment: $oh.FileAlignment,
                    MajorOperatingSystemVersion: $oh.OperatingSystemVersion.Major,
                    MinorOperatingSystemVersion: $oh.OperatingSystemVersion.Minor,
                    MajorImageVersion: $oh.ImageVersion.Major,
                    MinorImageVersion: $oh.ImageVersion.Minor,
                    MajorSubsystemVersion: $oh.SubsystemVersion.Major,
                    MinorSubsystemVersion: $oh.SubsystemVersion.Minor,
                    Win32VersionValue: $oh.Win32VersionValue,
                    SizeOfImage: $oh.SizeOfImage,
                    SizeOfHeaders: $oh.SizeOfHeaders,
                    CheckSum: $oh.CheckSum,
                    Subsystem: $oh.Subsystem,
                    DllCharacteristics: $oh.DllCharacteristics,
                    SizeOfStackReserve: $oh.SizeOfStackReserve as u64,
                    SizeOfStackCommit: $oh.SizeOfStackCommit as u64,
                    SizeOfHeapReserve: $oh.SizeOfHeapReserve as u64,
                    SizeOfHeapCommit: $oh.SizeOfHeapCommit as u64,
                    LoaderFlags: $oh.LoaderFlags,
                    NumberOfRvaAndSizes: $oh.NumberOfRvaAndSizes,
                    DataDirectory: data_directory,
                }
            };
        }
        let image_optional_header = match pe.optional_header() {
            Wrap::T32(oh) => optional_header!(oh, Some(oh.BaseOfData)),
            Wrap::T64(oh) => optional_header!(oh, None),
        };
        let image_base = image_optional_header.ImageBase;
        let size_of_image = image_optional_header.SizeOfImage as u64;

        let nt_headers = SerNtHeaders {
            Signature: match pe.nt_headers() {
                Wrap::T32(h) => h.Signature,
                Wrap::T64(h) => h.Signature,
            },
            FileHeader: image_file_header,
            OptionalHeader: image_optional_header,
        };

        // Collect section headers using pelite API
        let sections = pe.section_headers()
            .iter()
            .map(|s| crate::pe_types::ImageSectionHeader {
                Name: s.Name,
                VirtualSize: s.VirtualSize,
                VirtualAddress: s.VirtualAddress,
                SizeOfRawData: s.SizeOfRawData,
                PointerToRawData: s.PointerToRawData,
                PointerToRelocations: s.PointerToRelocations,
                PointerToLinenumbers: s.PointerToLinenumbers,
                NumberOfRelocations: s.NumberOfRelocations,
                NumberOfLinenumbers: s.NumberOfLinenumbers,
                Characteristics: s.Characteristics,
            })
            .collect::<Vec<_>>();

        // Parse imports
        let imports = match pe.imports() {
            Ok(imports) => {
                let mut out = Vec::new();
                for desc in imports {
                    let dll_name = match desc.dll_name() {
                        Ok(cstr) => cstr.to_str().unwrap_or("<invalid>").to_string(),
                        Err(e) => format!("<dll name error: {}>", e),
                    };
                    let mut entries: Vec<ImportEntry> = Vec::new();
                    match (desc.iat(), desc.int()) {
                        (Ok(iat), Ok(int)) => {
                            let first_thunk_rva: u32 = desc.image().FirstThunk;
                            // IAT slots are pointer-sized: 4 bytes in PE32, 8 in PE32+.
                            let pointer_size_bytes: usize = if is_pe32 { 4 } else { 8 };
                            for (index, (_slot_value, res)) in Iterator::zip(iat, int).enumerate() {
                                let slot_rva = first_thunk_rva.wrapping_add((index * pointer_size_bytes) as u32);
                                let kind = match res {
                                    Ok(item) => match item {
                                        pelite::pe64::imports::Import::ByName { hint, name } => {
                                            ImportKind::Item(ImportItem::ByName { name: name.to_string(), hint })
                                        }
                                        pelite::pe64::imports::Import::ByOrdinal { ord } => {
                                            ImportKind::Item(ImportItem::ByOrdinal { ordinal: ord })
                                        }
                                    },
                                    Err(e) => ImportKind::Error(format!("{}", e)),
                                };
                                entries.push(ImportEntry { iat_rva: slot_rva, kind });
                            }
                        }
                        (Err(e), _) => entries.push(ImportEntry { iat_rva: 0, kind: ImportKind::Error(format!("IAT error: {}", e)) }),
                        (_, Err(e)) => entries.push(ImportEntry { iat_rva: 0, kind: ImportKind::Error(format!("INT error: {}", e)) }),
                    }
                    out.push(ImportDescriptorInfo { dll_name, entries });
                }
                out
            }
            Err(e) => vec![ImportDescriptorInfo { dll_name: format!("<imports error: {}>", e), entries: Vec::new() }],
        };

        // Parse exports
        let exports = match pe.exports() {
            Ok(exports) => {
                // dll name
                let dll_name = match exports.dll_name() {
                    Ok(cstr) => cstr.to_str().unwrap_or("<invalid>").to_string(),
                    Err(e) => format!("<dll name error: {}>", e),
                };

                // Build name index lookup
                let mut index_to_name: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
                if let Ok(by) = exports.by() {
                    for (name_res, func_index) in by.iter_name_indices() {
                        if let (Ok(cname), idx) = (name_res, func_index) {
                            index_to_name.insert(idx, cname.to_str().unwrap_or("<invalid>").to_string());
                        }
                    }
                }

                let ordinal_base = exports.ordinal_base() as u32;
                let mut entries: Vec<ExportEntry> = Vec::new();
                match exports.by() {
                    Ok(by) => {
                        for (index, result) in by.iter().enumerate() {
                            let ordinal = ordinal_base + index as u32;
                            match result {
                                Ok(exp) => {
                                    let name = index_to_name.get(&index).cloned();
                                    let kind = match exp {
                                        pelite::pe::exports::Export::Symbol(rva) if *rva == 0 => continue, // unused ordinal slot
                                        pelite::pe::exports::Export::Symbol(rva) => ExportKind::Symbol { rva: *rva },
                                        pelite::pe::exports::Export::Forward(fwd) => ExportKind::Forward { target: fwd.to_string() },
                                    };
                                    entries.push(ExportEntry { ordinal, name, kind });
                                }
                                Err(_) => {
                                    // Unused ordinal slot (null address) — skip
                                    continue;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        entries.push(ExportEntry { ordinal: ordinal_base, name: None, kind: ExportKind::Error(format!("export lookup error: {}", e)) });
                    }
                }

                Some(ExportInfo { dll_name, ordinal_base, entries })
            }
            Err(_) => None,
        };

        // Parse Exception Directory (Runtime Functions). PE32 (x86) images have no
        // exception directory — x86 unwinds through frame pointers / FPO data — so
        // only the 64-bit arm reads one.
        let runtime_functions: Option<Vec<RuntimeFunction>> = match &pe {
            Wrap::T32(_) => None,
            Wrap::T64(pe64) if file_header.Machine == IMAGE_FILE_MACHINE_ARM64 => {
                match pe64.exception_arm64() {
                    Ok(exception_dir) => {
                        let entries = exception_dir.image();
                        let mut out: Vec<RuntimeFunction> = Vec::with_capacity(entries.len());
                        for func in exception_dir.functions() {
                            let begin = func.begin_address();
                            let unwind = func.raw_unwind_data();
                            let end = func.end_address().ok().flatten().unwrap_or(0);
                            out.push(RuntimeFunction {
                                BeginAddress: begin,
                                EndAddress: end,
                                UnwindData: unwind,
                            });
                        }
                        Some(out)
                    }
                    Err(_) => None,
                }
            }
            Wrap::T64(pe64) => {
                match pe64.exception() {
                    Ok(exception_dir) => {
                        let entries = exception_dir.image();
                        let mut out: Vec<RuntimeFunction> = Vec::with_capacity(entries.len());
                        for rf in entries.iter() {
                            out.push(RuntimeFunction {
                                BeginAddress: rf.BeginAddress,
                                EndAddress: rf.EndAddress,
                                UnwindData: rf.UnwindData,
                            });
                        }
                        Some(out)
                    }
                    Err(_) => None,
                }
            }
        };

        // Parse TLS callbacks (data directory 9). pelite returns each callback as an
        // absolute VA at the file's preferred ImageBase (32-bit in PE32); store RVAs so
        // they rebase onto the actual (ASLR) load base at the call site. Null and
        // out-of-image VAs are dropped. Absent/empty TLS => no callbacks.
        let va_to_rva = |va: u64| -> Option<u32> {
            (va != 0 && va >= image_base && va - image_base < size_of_image)
                .then(|| (va - image_base) as u32)
        };
        let tls_callbacks: Vec<u32> = match pe.tls().and_then(|tls| tls.callbacks()) {
            Ok(Wrap::T32(cbs)) => cbs.iter().filter_map(|&va| va_to_rva(va as u64)).collect(),
            Ok(Wrap::T64(cbs)) => cbs.iter().filter_map(|&va| va_to_rva(va)).collect(),
            Err(_) => Vec::new(),
        };

        // Return dos + complete nt headers + sections + imports + exports + runtime functions + tls
        let info = ModuleExtraInfo { dos_header, nt_headers, sections, imports, exports, runtime_functions, tls_callbacks };
        Ok(info)
}



