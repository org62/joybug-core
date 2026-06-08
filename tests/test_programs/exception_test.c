#include <windows.h>

volatile int g_caught = 0;

__declspec(noinline)
void raise_and_catch(void) {
    __try {
        RaiseException(0xE0000001, 0, 0, NULL);
        // If DBG_CONTINUE swallows the exception, execution continues here
        // and __except block is skipped
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        g_caught = 1;
    }
}

int main(void) {
    raise_and_catch();
    // Exit 0 = exception caught (correct behavior)
    // Exit 1 = exception swallowed by debugger (bug)
    return g_caught == 1 ? 0 : 1;
}
