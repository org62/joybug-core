#include <stdio.h>
#include <windows.h>

/* Simple test program for VEH debugging.
 * Loops calling a known function so we can set breakpoints on it. */

__declspec(noinline) void target_function(void) {
    volatile int x = 42;
    (void)x;
}

int main(void) {
    printf("veh_test: pid=%lu\n", GetCurrentProcessId());
    fflush(stdout);
    /* Loop so we have time to attach and set breakpoints */
    for (int i = 0; i < 100; i++) {
        target_function();
        Sleep(50);
    }
    printf("veh_test: done\n");
    return 0;
}
