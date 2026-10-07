/* Faults with a NULL write, for exception reporting. */
#include "../portable.h"

NOINLINE void crash(void) {
    *(volatile int *)0 = 1;
}

int main(void) {
    crash();
    return 0;
}
