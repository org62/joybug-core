/* The Linux hello-world debuggee: a small, named call chain and a known
 * exit code. Built with -O0 -fno-omit-frame-pointer -g. */
#include <stdio.h>
#include "../portable.h"

volatile int g_counter = 0;
volatile int g_write_dword = 0;

/* Types for the DWARF type-information test. */
enum Color { RED = 0, GREEN = 1, BLUE = 2 };
struct Point { int x; int y; };
struct Shape {
    struct Point origin;
    unsigned flags : 3;
    unsigned filled : 1;
    enum Color color;
    const char *name;
    double scale[4];
};
union Word { unsigned int u; float f; };
volatile struct Shape g_shape = { { 1, 2 }, 5, 1, BLUE, "shape", { 1.0, 2.0, 3.0, 4.0 } };
volatile union Word g_word = { 7 };

NOINLINE int compute(int x) {
    g_counter += x;
    return g_counter * 2;
}

NOINLINE int hello_marker(int seed) {
    int v = compute(seed);
    g_write_dword = v;   /* a data write for hardware watchpoints */
    printf("hello from the debuggee: %d\n", v);
    return v;
}

int main(int argc, char **argv) {
    (void)argv;
    int v = hello_marker(argc + 20);
    return (v > 0) ? 42 : 1;
}
