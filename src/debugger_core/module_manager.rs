use crate::protocol::ModuleInfo;
use crate::pe_types::ModuleExtraInfo;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// Unique across process lifetimes, including reuse of the PID and image base.
static NEXT_MAPPING_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Default)]
pub struct ModuleManager {
    modules: HashMap<u64, (ModuleInfo, Option<u64>)>, // base -> module, live mapping ID
    extra_info: HashMap<u64, ModuleExtraInfo>, // base_address -> cached extra info
}

impl ModuleManager {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            extra_info: HashMap::new(),
        }
    }

    pub fn add_module(&mut self, module: ModuleInfo) {
        let id = NEXT_MAPPING_ID.fetch_add(1, Ordering::Relaxed);
        self.modules.insert(module.base, (module, Some(id)));
    }

    /// For symbolization only: not a confirmed live mapping.
    #[cfg(windows)]
    pub(crate) fn add_inferred_module(&mut self, module: ModuleInfo) {
        self.modules.entry(module.base).or_insert((module, None));
    }

    pub(crate) fn mapping_at(&self, base: u64) -> Option<(&ModuleInfo, u64)> {
        let (module, id) = self.modules.get(&base)?;
        Some((module, (*id)?))
    }

    pub fn remove_module(&mut self, base_address: u64) -> Option<ModuleInfo> {
        self.extra_info.remove(&base_address);
        self.modules.remove(&base_address).map(|(module, _)| module)
    }

    pub fn list_modules(&self) -> Vec<ModuleInfo> {
        self.modules.values().map(|(module, _)| module.clone()).collect()
    }

    pub fn clear(&mut self) {
        self.modules.clear();
        self.extra_info.clear();
    }

    pub fn set_extra_info(&mut self, base_address: u64, info: ModuleExtraInfo) {
        self.extra_info.insert(base_address, info);
    }

    pub fn get_extra_info(&self, base_address: u64) -> Option<ModuleExtraInfo> {
        self.extra_info.get(&base_address).cloned()
    }

    /// Run `f` against the cached extra info by reference. Unlike
    /// `get_extra_info` this avoids deep-cloning the whole `ModuleExtraInfo`
    /// (export/import tables, runtime functions) — use it for hot lookups that
    /// only need to read a slice of the cached data.
    pub fn with_extra_info<R>(&self, base_address: u64, f: impl FnOnce(&ModuleExtraInfo) -> R) -> Option<R> {
        self.extra_info.get(&base_address).map(f)
    }
}