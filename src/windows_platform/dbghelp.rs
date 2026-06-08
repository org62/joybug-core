use std::sync::Mutex;

/// Global lock for all DbgHelp.dll function calls as the library is single-threaded.
/// "All DbgHelp functions are single threaded. Therefore, calls from more than one thread 
/// to this function will likely result in unexpected behavior or memory corruption."
/// https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-syminitialize
pub static DBGHELP_LOCK: Mutex<()> = Mutex::new(());

