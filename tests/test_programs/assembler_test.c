volatile int g_value_a = 42;
volatile int g_value_b = 99;

__declspec(noinline) void breakpoint_here(void) { volatile int x = 0; (void)x; }

/* Returns 1. Debugger will patch to return 2. */
__declspec(noinline) int get_value(void) { return 1; }

/* Reads g_value_a (42). Debugger will patch to read g_value_b (99) instead.
   Tests RIP-relative encoding on x86-64. */
__declspec(noinline) int get_global(void) { return g_value_a; }

int main(void) {
    breakpoint_here();

    /* Test 1: get_value should return 2 after patching */
    if (get_value() != 2) return 1;

    /* Test 2: get_global should return g_value_b (99) after patching (x86-64 only)
       On ARM64, get_global is not patched - still returns g_value_a (42) */
#if defined(_M_X64) || defined(__x86_64__)
    if (get_global() != 99) return 2;
#else
    if (get_global() != 42) return 2;
#endif

    return 0;
}
