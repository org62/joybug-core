use crate::protocol::ModuleInfo;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct ModuleManager {
    modules: HashMap<u64, ModuleInfo>, // base_address -> ModuleInfo
}

impl ModuleManager {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    pub fn add_module(&mut self, module: ModuleInfo) {
        self.modules.insert(module.base, module);
    }

    pub fn remove_module(&mut self, base_address: u64) {
        self.modules.remove(&base_address);
    }

    pub fn list_modules(&self) -> Vec<ModuleInfo> {
        self.modules.values().cloned().collect()
    }

    pub fn clear(&mut self) {
        self.modules.clear();
    }
} 