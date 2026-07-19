// Re declare windows_sys::Win32::System::SystemServices::* structs. 
// The only difference is that those are serializable.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[allow(non_snake_case)]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageFileHeader {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[allow(non_snake_case)]
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct ImageDataDirectory {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[allow(non_snake_case)]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageOptionalHeader64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [ImageDataDirectory; 16],
}

#[allow(non_snake_case)]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct NtHeaders64 {
    pub Signature: u32,
    pub FileHeader: ImageFileHeader,
    pub OptionalHeader: ImageOptionalHeader64,
}

#[allow(non_snake_case)]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageSectionHeader {
    pub Name: [u8; 8],
    pub VirtualSize: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

impl ImageSectionHeader {
    pub fn name_string(&self) -> String {
        let nul = self.Name.iter().position(|&b| b == 0).unwrap_or(self.Name.len());
        String::from_utf8_lossy(&self.Name[..nul]).to_string()
    }
}

impl std::fmt::Debug for ImageSectionHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct HexU32(u32);
        impl std::fmt::Debug for HexU32 {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "0x{:08x}", self.0)
            }
        }

        struct HexU16(u16);
        impl std::fmt::Debug for HexU16 {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "0x{:04x}", self.0)
            }
        }

        f.debug_struct("ImageSectionHeader")
            .field("Name", &self.name_string())
            .field("VirtualSize", &HexU32(self.VirtualSize))
            .field("VirtualAddress", &HexU32(self.VirtualAddress))
            .field("SizeOfRawData", &HexU32(self.SizeOfRawData))
            .field("PointerToRawData", &HexU32(self.PointerToRawData))
            .field("PointerToRelocations", &HexU32(self.PointerToRelocations))
            .field("PointerToLinenumbers", &HexU32(self.PointerToLinenumbers))
            .field("NumberOfRelocations", &HexU16(self.NumberOfRelocations))
            .field("NumberOfLinenumbers", &HexU16(self.NumberOfLinenumbers))
            .field("Characteristics", &HexU32(self.Characteristics))
            .finish()
    }
}

impl std::fmt::Display for ImageSectionHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ImageSectionHeader {{")?;
        writeln!(f, "  Name: {}", self.name_string())?;
        writeln!(f, "  VirtualSize: 0x{:08x}", self.VirtualSize)?;
        writeln!(f, "  VirtualAddress: 0x{:08x}", self.VirtualAddress)?;
        writeln!(f, "  SizeOfRawData: 0x{:08x}", self.SizeOfRawData)?;
        writeln!(f, "  PointerToRawData: 0x{:08x}", self.PointerToRawData)?;
        writeln!(f, "  PointerToRelocations: 0x{:08x}", self.PointerToRelocations)?;
        writeln!(f, "  PointerToLinenumbers: 0x{:08x}", self.PointerToLinenumbers)?;
        writeln!(f, "  NumberOfRelocations: 0x{:04x}", self.NumberOfRelocations)?;
        writeln!(f, "  NumberOfLinenumbers: 0x{:04x}", self.NumberOfLinenumbers)?;
        writeln!(f, "  Characteristics: 0x{:08x}", self.Characteristics)?;
        write!(f, "}}")
    }
}

impl std::fmt::Debug for DosHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct HexU16(u16);
        impl std::fmt::Debug for HexU16 { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "0x{:04x}", self.0) } }
        struct HexI32(i32);
        impl std::fmt::Debug for HexI32 { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "0x{:08x}", self.0 as u32) } }

        f.debug_struct("DosHeader")
            .field("e_magic", &HexU16(self.e_magic))
            .field("e_cblp", &HexU16(self.e_cblp))
            .field("e_cp", &HexU16(self.e_cp))
            .field("e_crlc", &HexU16(self.e_crlc))
            .field("e_cparhdr", &HexU16(self.e_cparhdr))
            .field("e_minalloc", &HexU16(self.e_minalloc))
            .field("e_maxalloc", &HexU16(self.e_maxalloc))
            .field("e_ss", &HexU16(self.e_ss))
            .field("e_sp", &HexU16(self.e_sp))
            .field("e_csum", &HexU16(self.e_csum))
            .field("e_ip", &HexU16(self.e_ip))
            .field("e_cs", &HexU16(self.e_cs))
            .field("e_lfarlc", &HexU16(self.e_lfarlc))
            .field("e_ovno", &HexU16(self.e_ovno))
            .field("e_res", &self.e_res)
            .field("e_oemid", &HexU16(self.e_oemid))
            .field("e_oeminfo", &HexU16(self.e_oeminfo))
            .field("e_res2", &self.e_res2)
            .field("e_lfanew", &HexI32(self.e_lfanew))
            .finish()
    }
}

impl std::fmt::Debug for ImageFileHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct HexU16(u16);
        impl std::fmt::Debug for HexU16 { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "0x{:04x}", self.0) } }
        struct HexU32(u32);
        impl std::fmt::Debug for HexU32 { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "0x{:08x}", self.0) } }

        f.debug_struct("ImageFileHeader")
            .field("Machine", &HexU16(self.Machine))
            .field("NumberOfSections", &HexU16(self.NumberOfSections))
            .field("TimeDateStamp", &HexU32(self.TimeDateStamp))
            .field("PointerToSymbolTable", &HexU32(self.PointerToSymbolTable))
            .field("NumberOfSymbols", &HexU32(self.NumberOfSymbols))
            .field("SizeOfOptionalHeader", &HexU16(self.SizeOfOptionalHeader))
            .field("Characteristics", &HexU16(self.Characteristics))
            .finish()
    }
}

impl std::fmt::Debug for ImageDataDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct HexU32(u32);
        impl std::fmt::Debug for HexU32 { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "0x{:08x}", self.0) } }
        f.debug_struct("ImageDataDirectory")
            .field("VirtualAddress", &HexU32(self.VirtualAddress))
            .field("Size", &HexU32(self.Size))
            .finish()
    }
}

impl std::fmt::Debug for ImageOptionalHeader64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct HexU16(u16);
        impl std::fmt::Debug for HexU16 { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "0x{:04x}", self.0) } }
        struct HexU32(u32);
        impl std::fmt::Debug for HexU32 { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "0x{:08x}", self.0) } }
        struct HexU64(u64);
        impl std::fmt::Debug for HexU64 { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "0x{:016x}", self.0) } }

        f.debug_struct("ImageOptionalHeader64")
            .field("Magic", &HexU16(self.Magic))
            .field("MajorLinkerVersion", &self.MajorLinkerVersion)
            .field("MinorLinkerVersion", &self.MinorLinkerVersion)
            .field("SizeOfCode", &HexU32(self.SizeOfCode))
            .field("SizeOfInitializedData", &HexU32(self.SizeOfInitializedData))
            .field("SizeOfUninitializedData", &HexU32(self.SizeOfUninitializedData))
            .field("AddressOfEntryPoint", &HexU32(self.AddressOfEntryPoint))
            .field("BaseOfCode", &HexU32(self.BaseOfCode))
            .field("ImageBase", &HexU64(self.ImageBase))
            .field("SectionAlignment", &HexU32(self.SectionAlignment))
            .field("FileAlignment", &HexU32(self.FileAlignment))
            .field("MajorOperatingSystemVersion", &HexU16(self.MajorOperatingSystemVersion))
            .field("MinorOperatingSystemVersion", &HexU16(self.MinorOperatingSystemVersion))
            .field("MajorImageVersion", &HexU16(self.MajorImageVersion))
            .field("MinorImageVersion", &HexU16(self.MinorImageVersion))
            .field("MajorSubsystemVersion", &HexU16(self.MajorSubsystemVersion))
            .field("MinorSubsystemVersion", &HexU16(self.MinorSubsystemVersion))
            .field("Win32VersionValue", &HexU32(self.Win32VersionValue))
            .field("SizeOfImage", &HexU32(self.SizeOfImage))
            .field("SizeOfHeaders", &HexU32(self.SizeOfHeaders))
            .field("CheckSum", &HexU32(self.CheckSum))
            .field("Subsystem", &HexU16(self.Subsystem))
            .field("DllCharacteristics", &HexU16(self.DllCharacteristics))
            .field("SizeOfStackReserve", &HexU64(self.SizeOfStackReserve))
            .field("SizeOfStackCommit", &HexU64(self.SizeOfStackCommit))
            .field("SizeOfHeapReserve", &HexU64(self.SizeOfHeapReserve))
            .field("SizeOfHeapCommit", &HexU64(self.SizeOfHeapCommit))
            .field("LoaderFlags", &HexU32(self.LoaderFlags))
            .field("NumberOfRvaAndSizes", &HexU32(self.NumberOfRvaAndSizes))
            .field("DataDirectory", &self.DataDirectory)
            .finish()
    }
}

impl std::fmt::Debug for NtHeaders64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct HexU32(u32);
        impl std::fmt::Debug for HexU32 { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "0x{:08x}", self.0) } }
        f.debug_struct("NtHeaders64")
            .field("Signature", &HexU32(self.Signature))
            .field("FileHeader", &self.FileHeader)
            .field("OptionalHeader", &self.OptionalHeader)
            .finish()
    }
}

// Pretty Display (multiline tree) implementations
impl std::fmt::Display for DosHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "DosHeader {{")?;
        writeln!(f, "  e_magic: 0x{:04x}", self.e_magic)?;
        writeln!(f, "  e_cblp: 0x{:04x}", self.e_cblp)?;
        writeln!(f, "  e_cp: 0x{:04x}", self.e_cp)?;
        writeln!(f, "  e_crlc: 0x{:04x}", self.e_crlc)?;
        writeln!(f, "  e_cparhdr: 0x{:04x}", self.e_cparhdr)?;
        writeln!(f, "  e_minalloc: 0x{:04x}", self.e_minalloc)?;
        writeln!(f, "  e_maxalloc: 0x{:04x}", self.e_maxalloc)?;
        writeln!(f, "  e_ss: 0x{:04x}", self.e_ss)?;
        writeln!(f, "  e_sp: 0x{:04x}", self.e_sp)?;
        writeln!(f, "  e_csum: 0x{:04x}", self.e_csum)?;
        writeln!(f, "  e_ip: 0x{:04x}", self.e_ip)?;
        writeln!(f, "  e_cs: 0x{:04x}", self.e_cs)?;
        writeln!(f, "  e_lfarlc: 0x{:04x}", self.e_lfarlc)?;
        writeln!(f, "  e_ovno: 0x{:04x}", self.e_ovno)?;
        writeln!(f, "  e_res: {:?}", self.e_res)?;
        writeln!(f, "  e_oemid: 0x{:04x}", self.e_oemid)?;
        writeln!(f, "  e_oeminfo: 0x{:04x}", self.e_oeminfo)?;
        writeln!(f, "  e_res2: {:?}", self.e_res2)?;
        writeln!(f, "  e_lfanew: 0x{:08x}", self.e_lfanew as u32)?;
        write!(f, "}}")
    }
}

impl std::fmt::Display for ImageFileHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ImageFileHeader {{")?;
        writeln!(f, "  Machine: 0x{:04x}", self.Machine)?;
        writeln!(f, "  NumberOfSections: 0x{:04x}", self.NumberOfSections)?;
        writeln!(f, "  TimeDateStamp: 0x{:08x}", self.TimeDateStamp)?;
        writeln!(f, "  PointerToSymbolTable: 0x{:08x}", self.PointerToSymbolTable)?;
        writeln!(f, "  NumberOfSymbols: 0x{:08x}", self.NumberOfSymbols)?;
        writeln!(f, "  SizeOfOptionalHeader: 0x{:04x}", self.SizeOfOptionalHeader)?;
        writeln!(f, "  Characteristics: 0x{:04x}", self.Characteristics)?;
        write!(f, "}}")
    }
}

impl std::fmt::Display for ImageDataDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ImageDataDirectory {{ VirtualAddress: 0x{:08x}, Size: 0x{:08x} }}", self.VirtualAddress, self.Size)
    }
}

impl std::fmt::Display for ImageOptionalHeader64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ImageOptionalHeader64 {{")?;
        writeln!(f, "  Magic: 0x{:04x}", self.Magic)?;
        writeln!(f, "  MajorLinkerVersion: {}", self.MajorLinkerVersion)?;
        writeln!(f, "  MinorLinkerVersion: {}", self.MinorLinkerVersion)?;
        writeln!(f, "  SizeOfCode: 0x{:08x}", self.SizeOfCode)?;
        writeln!(f, "  SizeOfInitializedData: 0x{:08x}", self.SizeOfInitializedData)?;
        writeln!(f, "  SizeOfUninitializedData: 0x{:08x}", self.SizeOfUninitializedData)?;
        writeln!(f, "  AddressOfEntryPoint: 0x{:08x}", self.AddressOfEntryPoint)?;
        writeln!(f, "  BaseOfCode: 0x{:08x}", self.BaseOfCode)?;
        writeln!(f, "  ImageBase: 0x{:016x}", self.ImageBase)?;
        writeln!(f, "  SectionAlignment: 0x{:08x}", self.SectionAlignment)?;
        writeln!(f, "  FileAlignment: 0x{:08x}", self.FileAlignment)?;
        writeln!(f, "  MajorOperatingSystemVersion: 0x{:04x}", self.MajorOperatingSystemVersion)?;
        writeln!(f, "  MinorOperatingSystemVersion: 0x{:04x}", self.MinorOperatingSystemVersion)?;
        writeln!(f, "  MajorImageVersion: 0x{:04x}", self.MajorImageVersion)?;
        writeln!(f, "  MinorImageVersion: 0x{:04x}", self.MinorImageVersion)?;
        writeln!(f, "  MajorSubsystemVersion: 0x{:04x}", self.MajorSubsystemVersion)?;
        writeln!(f, "  MinorSubsystemVersion: 0x{:04x}", self.MinorSubsystemVersion)?;
        writeln!(f, "  Win32VersionValue: 0x{:08x}", self.Win32VersionValue)?;
        writeln!(f, "  SizeOfImage: 0x{:08x}", self.SizeOfImage)?;
        writeln!(f, "  SizeOfHeaders: 0x{:08x}", self.SizeOfHeaders)?;
        writeln!(f, "  CheckSum: 0x{:08x}", self.CheckSum)?;
        writeln!(f, "  Subsystem: 0x{:04x}", self.Subsystem)?;
        writeln!(f, "  DllCharacteristics: 0x{:04x}", self.DllCharacteristics)?;
        writeln!(f, "  SizeOfStackReserve: 0x{:016x}", self.SizeOfStackReserve)?;
        writeln!(f, "  SizeOfStackCommit: 0x{:016x}", self.SizeOfStackCommit)?;
        writeln!(f, "  SizeOfHeapReserve: 0x{:016x}", self.SizeOfHeapReserve)?;
        writeln!(f, "  SizeOfHeapCommit: 0x{:016x}", self.SizeOfHeapCommit)?;
        writeln!(f, "  LoaderFlags: 0x{:08x}", self.LoaderFlags)?;
        writeln!(f, "  NumberOfRvaAndSizes: 0x{:08x}", self.NumberOfRvaAndSizes)?;
        writeln!(f, "  DataDirectory: [")?;
        for (i, dir) in self.DataDirectory.iter().enumerate() {
            if dir.VirtualAddress != 0 || dir.Size != 0 {
                writeln!(f, "    {}: {}", i, dir)?;
            }
        }
        writeln!(f, "  ]")?;
        write!(f, "}}")
    }
}

impl std::fmt::Display for NtHeaders64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "NtHeaders64 {{")?;
        writeln!(f, "  Signature: 0x{:08x}", self.Signature)?;
        writeln!(f, "  FileHeader: {}", self.FileHeader)?;
        writeln!(f, "  OptionalHeader: {}", self.OptionalHeader)?;
        write!(f, "}}")
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleExtraInfo {
    pub dos_header: DosHeader,
    pub nt_headers: NtHeaders64,
    pub sections: Vec<ImageSectionHeader>,
    pub imports: Vec<ImportDescriptorInfo>,
    pub exports: Option<ExportInfo>,
    pub runtime_functions: Option<Vec<RuntimeFunction>>,
    /// RVAs of the module's TLS callbacks (empty if the module has none).
    #[serde(default)]
    pub tls_callbacks: Vec<u32>,
}

// ---------------- Imports (for PE Import Directory) ----------------
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ImportItem {
    ByName { name: String, hint: usize },
    ByOrdinal { ordinal: u16 },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ImportKind {
    Item(ImportItem),
    Error(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImportEntry {
    pub iat_rva: u32,
    pub kind: ImportKind,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImportDescriptorInfo {
    pub dll_name: String,
    pub entries: Vec<ImportEntry>,
}

impl std::fmt::Display for ImportEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ImportKind::Item(ImportItem::ByName { name, hint }) => {
                write!(f, "ByName(name={}, hint=0x{:04x}) @ RVA=0x{:08x}", name, *hint as u16, self.iat_rva)
            }
            ImportKind::Item(ImportItem::ByOrdinal { ordinal }) => {
                write!(f, "ByOrdinal(ordinal=0x{:04x}) @ RVA=0x{:08x}", ordinal, self.iat_rva)
            }
            ImportKind::Error(err) => {
                write!(f, "Error({}) @ RVA=0x{:08x}", err, self.iat_rva)
            }
        }
    }
}

impl std::fmt::Display for ImportDescriptorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ImportDescriptor {{")?;
        writeln!(f, "  DLL: {}", self.dll_name)?;
        if self.entries.is_empty() {
            writeln!(f, "  <no entries>")?;
        } else {
            writeln!(f, "  Entries:")?;
            for e in &self.entries {
                writeln!(f, "    {}", e)?;
            }
        }
        write!(f, "}}")
    }
}

// ---------------- Exports (for PE Export Directory) ----------------
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ExportKind {
    Symbol { rva: u32 },
    Forward { target: String },
    Error(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportEntry {
    pub ordinal: u32,
    pub name: Option<String>,
    pub kind: ExportKind,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportInfo {
    pub dll_name: String,
    pub ordinal_base: u32,
    pub entries: Vec<ExportEntry>,
}

impl std::fmt::Display for ExportEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.name.as_deref().unwrap_or("<no name>");
        match &self.kind {
            ExportKind::Symbol { rva } => {
                write!(f, "Ordinal=0x{:04x}, RVA=0x{:08x}, Name={}", self.ordinal, rva, name)
            }
            ExportKind::Forward { target } => {
                write!(f, "Ordinal=0x{:04x}, Forward={} Name={}", self.ordinal, target, name)
            }
            ExportKind::Error(err) => {
                write!(f, "Ordinal=0x{:04x}, Error={}, Name={}", self.ordinal, err, name)
            }
        }
    }
}

impl std::fmt::Display for ExportInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ExportInfo {{")?;
        writeln!(f, "  DLL: {}", self.dll_name)?;
        writeln!(f, "  OrdinalBase: 0x{:04x}", self.ordinal_base)?;
        if self.entries.is_empty() {
            writeln!(f, "  <no entries>")?;
        } else {
            writeln!(f, "  Entries:")?;
            for e in &self.entries {
                writeln!(f, "    {}", e)?;
            }
        }
        write!(f, "}}")
    }
}

// ---------------- Runtime Functions (from Exception Directory) ----------------
#[allow(non_snake_case)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeFunction {
    pub BeginAddress: u32,
    pub EndAddress: u32,
    pub UnwindData: u32,
}

impl std::fmt::Display for RuntimeFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let size = self.EndAddress.saturating_sub(self.BeginAddress);
        write!(
            f,
            "Begin=0x{:08x}, End=0x{:08x}, Unwind=0x{:08x}, Size=0x{:08x}",
            self.BeginAddress, self.EndAddress, self.UnwindData, size
        )
    }
}
