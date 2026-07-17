#include <windows.h>

// EXCEPTION_SINGLE_STEP / STATUS_SINGLE_STEP
#define SINGLE_STEP_CODE 0x80000004

volatile int g_caught = 0;

// The program deliberately raises a single-step exception itself (as an
// anti-debug check or self-tracer would). Under a debugger this surfaces as a
// generic Exception event with code 0x80000004 (the server's "unexpected SS"
// path), NOT as a debugger-initiated step. Whether the program's own SEH
// handler runs depends on how the debugger continues it.
__declspec(noinline)
void raise_and_catch(void) {
    __try {
        RaiseException(SINGLE_STEP_CODE, 0, 0, NULL);
        // If DBG_CONTINUE swallows the exception, execution continues here
        // and the __except block is skipped.
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        g_caught = 1;
    }
}

int main(void) {
    raise_and_catch();
    // Exit 0 = exception passed to application (SEH handler ran)
    // Exit 1 = exception swallowed by debugger (bug)
    return g_caught == 1 ? 0 : 1;
}
