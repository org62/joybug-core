use crate::interfaces::PlatformError;
use crate::pe_types::{DosHeader as SerDosHeader, ImageFileHeader as SerImageFileHeader, ImageOptionalHeader64 as SerImageOptionalHeader64, ImageDataDirectory as SerImageDataDirectory, NtHeaders64 as SerNtHeaders64, ModuleExtraInfo, ImportDescriptorInfo, ImportEntry, ImportItem, ImportKind, ExportInfo, ExportEntry, ExportKind, RuntimeFunction};
use super::WindowsPlatform;
use pelite::pe64::exception_arm64::Arm64ExceptionExt;
use pelite::pe64::{Pe, PeFile};
use tracing::trace;
use windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_ARM64;

impl WindowsPlatform {

    pub(crate) fn parse_module_extra_info(&self, pid: u32, module_base: u64) -> Result<ModuleExtraInfo, PlatformError> {
        let process = self.get_process(pid)?;
        // Resolve module path from our manager
        let modules = process.module_manager().list_modules();
        let module_path = modules.iter().find(|m| m.base == module_base).map(|m| m.name.clone())
            .ok_or_else(|| PlatformError::Other("Module not found at base".to_string()))?;

        // Read file bytes and parse with pelite
        let file_bytes = std::fs::read(&module_path)
            .map_err(|e| PlatformError::Other(format!("Failed to read module file '{}': {}", module_path, e)))?;
        let pe = PeFile::from_bytes(&file_bytes)
            .map_err(|e| PlatformError::Other(format!("pelite failed to parse '{}': {:?}", module_path, e)))?;
        trace!({module_path, file_size = file_bytes.len()}, "Reading module extra info");

        // Map pelite headers into our serializable types
        let dos = pe.dos_header();
        let file_header = pe.file_header();
        let optional_header = pe.optional_header();

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

        // Map OptionalHeader64 and DataDirectory (0-length array in pelite, construct slice)
        let data_directory = unsafe {
            let max = 16usize;
            let count = std::cmp::min(optional_header.NumberOfRvaAndSizes as usize, max);
            let ptr = optional_header.DataDirectory.as_ptr();
            let slice = std::slice::from_raw_parts(ptr, count);
            let mut out: [SerImageDataDirectory; 16] = [SerImageDataDirectory { VirtualAddress: 0, Size: 0 }; 16];
            for i in 0..count {
                out[i] = SerImageDataDirectory { VirtualAddress: slice[i].VirtualAddress, Size: slice[i].Size };
            }
            out
        };

        let image_optional_header = SerImageOptionalHeader64 {
            Magic: optional_header.Magic,
            MajorLinkerVersion: optional_header.LinkerVersion.Major,
            MinorLinkerVersion: optional_header.LinkerVersion.Minor,
            SizeOfCode: optional_header.SizeOfCode,
            SizeOfInitializedData: optional_header.SizeOfInitializedData,
            SizeOfUninitializedData: optional_header.SizeOfUninitializedData,
            AddressOfEntryPoint: optional_header.AddressOfEntryPoint,
            BaseOfCode: optional_header.BaseOfCode,
            ImageBase: optional_header.ImageBase,
            SectionAlignment: optional_header.SectionAlignment,
            FileAlignment: optional_header.FileAlignment,
            MajorOperatingSystemVersion: optional_header.OperatingSystemVersion.Major,
            MinorOperatingSystemVersion: optional_header.OperatingSystemVersion.Minor,
            MajorImageVersion: optional_header.ImageVersion.Major,
            MinorImageVersion: optional_header.ImageVersion.Minor,
            MajorSubsystemVersion: optional_header.SubsystemVersion.Major,
            MinorSubsystemVersion: optional_header.SubsystemVersion.Minor,
            Win32VersionValue: optional_header.Win32VersionValue,
            SizeOfImage: optional_header.SizeOfImage,
            SizeOfHeaders: optional_header.SizeOfHeaders,
            CheckSum: optional_header.CheckSum,
            Subsystem: optional_header.Subsystem,
            DllCharacteristics: optional_header.DllCharacteristics,
            SizeOfStackReserve: optional_header.SizeOfStackReserve,
            SizeOfStackCommit: optional_header.SizeOfStackCommit,
            SizeOfHeapReserve: optional_header.SizeOfHeapReserve,
            SizeOfHeapCommit: optional_header.SizeOfHeapCommit,
            LoaderFlags: optional_header.LoaderFlags,
            NumberOfRvaAndSizes: optional_header.NumberOfRvaAndSizes,
            DataDirectory: data_directory,
        };

        let nt_headers = SerNtHeaders64 {
            Signature: pe.nt_headers().Signature,
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
                            let pointer_size_bytes: usize = 8; // 64-bit PE (we are in pe64)
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
                                        pelite::pe::exports::Export::Symbol(rva) => ExportKind::Symbol { rva: *rva },
                                        pelite::pe::exports::Export::Forward(fwd) => ExportKind::Forward { target: fwd.to_string() },
                                    };
                                    entries.push(ExportEntry { ordinal, name, kind });
                                }
                                Err(e) => {
                                    entries.push(ExportEntry { ordinal, name: index_to_name.get(&index).cloned(), kind: ExportKind::Error(format!("{}", e)) });
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

        // Parse Exception Directory (Runtime Functions)
        let runtime_functions: Option<Vec<RuntimeFunction>> = if file_header.Machine == IMAGE_FILE_MACHINE_ARM64 {
            match pe.exception_arm64() {
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
        } else {
            match pe.exception() {
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
        };

        // Return dos + complete nt headers + sections + imports + exports + runtime functions
        let info = ModuleExtraInfo { dos_header, nt_headers, sections, imports, exports, runtime_functions };
        Ok(info)
    }
}



