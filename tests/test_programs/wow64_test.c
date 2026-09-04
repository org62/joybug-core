// 32-bit (WOW64) debuggee for the wow64_* integration tests. Built by build.rs
// with the cross x86 cl.exe as wow64_test32.exe; the same source is also a
// perfectly good 64-bit program, but nothing builds it that way today.
//
// Shape: a marker function with a real call inside it (step-over target), a
// loop with a Sleep so the process stays alive long enough to attach/pause,
// and a global pointer for the 4-byte dereference / pointer-scan tests.
#include <windows.h>
#include <stdio.h>

volatile int g_counter = 0;
int g_value = 0x1234;
int* g_value_ptr = &g_value;

__declspec(noinline)
int compute(int x) {
    int acc = 0;
    for (int i = 0; i < 10; i++) {
        acc += x * i;
    }
    return acc;
}

__declspec(noinline)
void wow64_marker(int n) {
    g_counter += compute(n);
    *g_value_ptr += n;
}

int main(void) {
    for (int i = 0; i < 20; i++) {
        wow64_marker(i);
        Sleep(50);
    }
    printf("wow64_test done %d %d\n", g_counter, g_value);
    return 0;
}
