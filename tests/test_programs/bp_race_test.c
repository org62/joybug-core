// Multi-threaded software-breakpoint race reproduction target.
//
// Two worker threads call `target_func` a fixed number of times each. A debugger
// sets a single persistent software breakpoint (INT3) at `target_func`'s entry.
//
// The classic race: when thread A hits the breakpoint, the debugger removes the
// INT3, sets the trap flag, and single-steps A to step over the original
// instruction before re-arming the INT3. While the INT3 is temporarily absent,
// thread B can execute straight through `target_func` without ever hitting the
// breakpoint. Those executions are silently missed.
//
// Ground truth is deterministic: each thread calls `target_func` exactly ITER
// times, so the debugger must observe exactly (NUM_THREADS * ITER) hits. Fewer
// hits == breakpoints were missed due to the race.

#include <windows.h>
#include <stdio.h>

#ifndef ITER
#define ITER 10000
#endif

#define NUM_THREADS 2

// Number of times target_func actually executed, per the program itself.
// Used only as an in-program sanity check; the debugger relies on the constant.
volatile LONG g_calls = 0;

// A tiny standalone function. `noinline` guarantees a real, breakpointable entry
// point, and the InterlockedIncrement side effect keeps the optimizer from
// eliding calls even if optimization were enabled.
__declspec(noinline) void target_func(void)
{
    InterlockedIncrement(&g_calls);
}

// Gate so both workers start hammering target_func at roughly the same time,
// maximizing the window during which both threads are inside the hot loop.
volatile LONG g_go = 0;

static DWORD WINAPI worker(LPVOID param)
{
    (void)param;
    while (g_go == 0) { /* spin until released */ }
    for (int i = 0; i < ITER; i++) {
        target_func();
    }
    return 0;
}

int main(void)
{
    HANDLE threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        threads[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (threads[i] == NULL) {
            printf("CreateThread failed: %lu\n", GetLastError());
            return 2;
        }
    }

    // Release all workers at once.
    InterlockedExchange(&g_go, 1);

    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);
    for (int i = 0; i < NUM_THREADS; i++) {
        CloseHandle(threads[i]);
    }

    LONG expected = (LONG)NUM_THREADS * (LONG)ITER;
    printf("total_calls=%ld expected=%ld\n", g_calls, expected);
    // Exit code encodes whether the program itself ran to completion correctly.
    return (g_calls == expected) ? 0 : 1;
}
