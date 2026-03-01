/*
 * Test program for emulator integration tests
 *
 * Contains various functions exercised by the emulator test suite.
 * Each function targets a specific emulation scenario.
 */

#include <stdint.h>

/*
 * When true (non-zero), infinite_increment() loops forever.
 * The timeout test sets this to 1 before emulation so the emulator's
 * safety timeout is the only thing that stops it.
 * Default is 0 (false) so the program exits normally.
 */
volatile uint64_t g_do_infinite_loop = 0;

/* Counter incremented by infinite_increment() */
volatile uint64_t g_counter = 0;

/*
 * Increment g_counter in a loop.
 *
 * If g_do_infinite_loop: loop forever (timeout test).
 * Otherwise: run a bounded number of iterations and return.
 */
__declspec(noinline)
void infinite_increment(void) {
    for (;;) {
        g_counter++;
        if (!g_do_infinite_loop && g_counter >= 100) {
            return;
        }
    }
}

int main(void) {
    infinite_increment();
    return 0;
}
