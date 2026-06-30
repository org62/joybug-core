#include <stdio.h>
#include <windows.h>

/* Chain-following freeze victim.
 *
 * A static pointer `g_ptr` heads a one-hop chain to a value cell. The freeze test
 * freezes *through the pointer* (base = &g_ptr, offsets = [0]) to a sentinel.
 * Midway the program repoints `g_ptr` from cell A to cell B (a "level reload");
 * a chain-following freeze must then hold cell B, not the stale cell A. */
volatile unsigned int g_cell_a = 0;
volatile unsigned int g_cell_b = 0;
volatile unsigned int* g_ptr = 0;   /* static base of the 1-hop chain */

#define PROGRAM_VALUE 1000u

__declspec(noinline) void pause_here(void) { volatile int x = 0; (void)x; }

int main(void) {
    g_cell_a = PROGRAM_VALUE;
    g_cell_b = PROGRAM_VALUE;
    g_ptr = 0;                      /* null: chain not yet resolvable, as just after a restart */
    printf("g_ptr @ %p  cell_a @ %p  cell_b @ %p\n",
           (void*)&g_ptr, (void*)&g_cell_a, (void*)&g_cell_b);
    fflush(stdout);

    pause_here();                   /* iter 0: debugger registers the chain freeze while NULL */

    /* Object now "exists": the chain resolves to cell A. */
    g_ptr = &g_cell_a;
    for (int i = 0; i < 2; i++) {
        g_cell_a = PROGRAM_VALUE;   /* program keeps resetting its own value */
        pause_here();               /* iter 1,2: freeze must now hold cell A */
        Sleep(60);                  /* let the freeze thread tick */
    }

    /* "Level reload": repoint the chain to cell B. */
    g_ptr = &g_cell_b;
    pause_here();                   /* iter 3: debugger observes the repoint */

    /* Phase 2: chain points at cell B; the freeze must now hold cell B. */
    for (int i = 0; i < 2; i++) {
        g_cell_b = PROGRAM_VALUE;   /* program resets cell B */
        pause_here();               /* iter 4: freeze must have followed to cell B */
        Sleep(60);
    }

    printf("final cell_a=%u cell_b=%u\n", g_cell_a, g_cell_b);
    fflush(stdout);
    return 0;
}
