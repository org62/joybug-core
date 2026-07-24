#include <stdio.h>
#include <windows.h>

/* A global the program keeps resetting to PROGRAM_VALUE on every loop. The
 * freeze test resolves &g_value by symbol, freezes it to a sentinel, and checks
 * that the server-side freeze thread holds the sentinel while the debuggee is
 * stopped, then releases it after unfreeze. */
volatile unsigned int g_value = 0;

#define PROGRAM_VALUE 1000u

__declspec(noinline) void pause_here(void) { volatile int x = 0; (void)x; }

int main(void) {
    printf("g_value addr: %p\n", (void*)&g_value);
    fflush(stdout);

    for (int i = 0; i < 10; i++) {
        g_value = PROGRAM_VALUE;   /* program keeps resetting the value */
        pause_here();              /* debugger breakpoint: inspect / freeze */
        Sleep(60);                 /* let the freeze thread tick a few times */
    }

    printf("final g_value = %u\n", g_value);
    fflush(stdout);
    return 0;
}
