// Minimal program with a TLS callback, used to verify PE TLS-directory parsing
// (ModuleExtraInfo.tls_callbacks). The callback registration below forces the
// linker to emit an IMAGE_TLS_DIRECTORY with a non-empty AddressOfCallBacks array.
#include <windows.h>
#include <stdio.h>

// A thread-local variable ensures the TLS directory is generated.
__declspec(thread) int g_tls_value = 1;

void NTAPI tls_callback(PVOID handle, DWORD reason, PVOID reserved)
{
    (void)handle; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_tls_value = 42;
    }
}

// Register the callback in the .CRT$XLB section so the loader/CRT picks it up.
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:p_tls_callback")
#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK p_tls_callback = tls_callback;
#pragma const_seg()
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_p_tls_callback")
#pragma data_seg(".CRT$XLB")
EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback = tls_callback;
#pragma data_seg()
#endif

int main(void)
{
    printf("tls_value=%d\n", g_tls_value);
    return 0;
}
