use std::sync::RwLock;

use crate::interfaces::{Architecture, PlatformAPI, PlatformError};
use crate::protocol::{DebuggerResponse, ModuleInfo, NtBlockKind, TypeClass, TypeLayout, UdtKind};

pub(super) fn overlay<P: PlatformAPI>(
    platform: &RwLock<P>,
    pid: u32,
    tid: Option<u32>,
    kind: NtBlockKind,
) -> Result<DebuggerResponse, PlatformError> {
    let (address, arch, modules, symbols) = {
        let p = platform.read().unwrap();
        let Some((address, arch)) = p.nt_block_anchor(pid, tid, kind)? else {
            return Ok(DebuggerResponse::NtBlockOverlay { address: None, layout: None });
        };
        (address, arch, p.list_modules(pid)?, p.symbols_handle())
    };
    // A PDB type stream can take time to parse. Never do so under the platform lock.
    let layout = symbols.and_then(|symbols| {
        let module = matching_ntdll(&modules, arch)?;
        // Both names must see the same PDB, even if symbols load or are replaced mid-request.
        let types = symbols.get_type_info(&module.name).ok().flatten()?;
        resolve_layout(kind, arch, module.base, |name| types.resolve_by_name(name, module.base))
    });
    Ok(DebuggerResponse::NtBlockOverlay { address: Some(address), layout })
}

fn matching_ntdll(modules: &[ModuleInfo], arch: Architecture) -> Option<&ModuleInfo> {
    let guest = arch == Architecture::X86;
    let mut matches = modules.iter().filter(|module| {
        let mut parts = module.name.rsplit(['\\', '/']);
        let ntdll = parts.next().is_some_and(|file| file.eq_ignore_ascii_case("ntdll.dll"));
        ntdll && parts.next().is_some_and(|dir| {
            if guest {
                dir.eq_ignore_ascii_case("SysWOW64") || dir.eq_ignore_ascii_case("SyChpe32")
            } else {
                dir.eq_ignore_ascii_case("System32")
            }
        })
    });
    let module = matches.next()?;
    (!matches.any(|other| other.base != module.base)).then_some(module)
}

fn resolve_layout(
    kind: NtBlockKind,
    arch: Architecture,
    module_base: u64,
    mut lookup: impl FnMut(&str) -> Option<TypeLayout>,
) -> Option<TypeLayout> {
    let guest = arch == Architecture::X86;

    let (canonical, suffix, member, offset) = match (kind, guest) {
        (NtBlockKind::Teb, true) => ("_TEB", "_TEB32", "ProcessEnvironmentBlock", 0x30),
        (NtBlockKind::Teb, false) => ("_TEB", "_TEB64", "ProcessEnvironmentBlock", 0x60),
        (NtBlockKind::Peb, true) => ("_PEB", "_PEB32", "ImageBaseAddress", 0x08),
        (NtBlockKind::Peb, false) => ("_PEB", "_PEB64", "ImageBaseAddress", 0x10),
    };
    let width = if guest { 4 } else { 8 };
    // Prefer real pointers (expandable/navigable) in the canonical layout.
    // Width-explicit NT definitions sometimes store those addresses as integers.
    [(canonical, false), (suffix, true)].into_iter().find_map(|(name, allow_integer)| {
        lookup(name).filter(|layout| {
            layout.kind == UdtKind::Struct && layout.module_base == module_base
                && offset + width <= layout.size
                && layout.members.iter().any(|m| {
                    m.name == member && m.offset == offset && m.type_ref.size == width
                        && m.bit_length.is_none() && m.bit_position.is_none()
                        && (matches!(m.type_ref.class, TypeClass::Pointer { .. })
                            || (allow_integer && matches!(m.type_ref.class, TypeClass::Int | TypeClass::UInt)))
                })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{TypeMember, TypeRef};

    fn module(path: &str, base: u64) -> ModuleInfo {
        ModuleInfo { name: path.into(), base, size: None }
    }

    fn peb32(name: &str, module_base: u64, width: u32, class: TypeClass) -> TypeLayout {
        TypeLayout {
            name: name.into(),
            size: 0x100,
            kind: UdtKind::Struct,
            index: 0x1234,
            module_base,
            members: vec![TypeMember {
                name: "ImageBaseAddress".into(),
                offset: 8,
                type_ref: TypeRef { name: "image address".into(), size: width, class },
                bit_position: None,
                bit_length: None,
            }],
            enum_values: Vec::new(),
        }
    }

    fn pointer() -> TypeClass {
        TypeClass::Pointer {
            pointee: Box::new(TypeRef { name: "void".into(), size: 0, class: TypeClass::Void }),
        }
    }

    #[test]
    fn uses_same_module_suffix_when_canonical_is_absent() {
        let modules = [
            module(r"C:\Windows\System32\ntdll.dll", 0x10000),
            module("C:/Windows/sYchPE32/NtDll.DLL", 0x20000),
        ];
        let module = matching_ntdll(&modules, Architecture::X86).expect("find CHPE ntdll");
        assert_eq!(module.base, modules[1].base);
        let layout = resolve_layout(NtBlockKind::Peb, Architecture::X86, module.base, |name| {
            (name == "_PEB32").then(|| peb32(name, module.base, 4, TypeClass::UInt))
        }).expect("use the same-module width-explicit PEB");
        assert_eq!(layout.name, "_PEB32");
        assert_eq!(layout.module_base, modules[1].base);
        assert_eq!(layout.index, 0x1234);
    }

    #[test]
    fn rejects_incompatible_canonical_without_valid_suffix() {
        let base = 0x10000;
        let layout = resolve_layout(NtBlockKind::Peb, Architecture::X86, base, |name| {
            match name {
                "_PEB" => Some(peb32(name, base, 8, pointer())),
                "_PEB32" => Some(peb32(name, base + 0x10000, 4, TypeClass::UInt)),
                _ => panic!("must not try an unrelated type"),
            }
        });
        assert!(layout.is_none());
    }

    #[test]
    fn does_not_use_unrelated_or_ambiguous_modules_or_missing_pdb() {
        let unrelated = [
            module(r"C:\NotSysWOW64\ntdll.dll", 0x10000),
            module(r"C:\Windows\SysWOW64\ntdll.dll.backup", 0x20000),
            module(r"C:\Windows\System32\ntdll.dll", 0x30000),
        ];
        let ambiguous = [
            module(r"C:\Windows\SysWOW64\ntdll.dll", 0x10000),
            module(r"C:\Windows\SyChpe32\ntdll.dll", 0x20000),
        ];
        for modules in [&unrelated[..], &ambiguous[..]] {
            assert!(matching_ntdll(modules, Architecture::X86).is_none());
        }

        let layout = resolve_layout(NtBlockKind::Peb, Architecture::X86, ambiguous[0].base, |_| None);
        assert!(layout.is_none());
    }
}
