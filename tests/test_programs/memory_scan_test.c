#include <stdio.h>

/* Globals with distinctive initial values — one per ScanValueType */
volatile unsigned char      g_u8  = 42;
volatile unsigned short     g_u16 = 0x1234;
volatile unsigned int       g_u32 = 0x12345678;
volatile unsigned long long g_u64 = 0x123456789ABCULL;
volatile float              g_f32 = 3.14f;
volatile double             g_f64 = 2.718281828;

/* Iteration counter */
volatile int g_iteration = 0;

__declspec(noinline) void pause_here(void) {
    volatile int x = 0;
    (void)x;
}

int main(void) {
    int i;

    /* Print addresses to prevent optimization and aid debugging */
    printf("g_u8  = %p (%u)\n",  (void*)&g_u8,  (unsigned)g_u8);
    printf("g_u16 = %p (%u)\n",  (void*)&g_u16, (unsigned)g_u16);
    printf("g_u32 = %p (0x%X)\n", (void*)&g_u32, g_u32);
    printf("g_u64 = %p (0x%llX)\n", (void*)&g_u64, g_u64);
    printf("g_f32 = %p (%f)\n",  (void*)&g_f32, (double)g_f32);
    printf("g_f64 = %p (%f)\n",  (void*)&g_f64, g_f64);
    fflush(stdout);

    /* Iteration 0: initial values */
    pause_here();

    /* Iterations 1..30: increment all globals by known deltas */
    for (i = 1; i <= 30; i++) {
        g_iteration = i;
        g_u8  += 1;
        g_u16 += 1;
        g_u32 += 1;
        g_u64 += 1;
        g_f32 += 1.5f;
        g_f64 += 0.5;

        pause_here();
    }

    printf("Final: u8=%u u16=%u u32=0x%X u64=0x%llX f32=%f f64=%f\n",
        (unsigned)g_u8, (unsigned)g_u16, g_u32, g_u64, (double)g_f32, g_f64);
    fflush(stdout);

    return 0;
}
