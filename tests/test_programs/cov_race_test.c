// Stale coverage-breakpoint reproduction target.
//
// Code coverage arms a silent INT3 on every function entry and removes it once
// the hit limit is reached. `ContinueDebugEvent` resumes the *whole* process, so
// on a multi-core machine several threads can trap on the same INT3 before the
// debugger has processed the first event: the kernel queues the extra events and
// delivers them after the INT3 is already gone. Such a hit must be recognized as
// the debugger's own (IP rewound to re-execute the restored instruction), not
// reported as an unknown breakpoint with the IP left one byte past the INT3 —
// resuming from there runs the tail of an instruction, which access-violates.
//
// This program maximizes that window: every thread sweeps the same array of tiny
// functions in the same order, so when one thread's hit retires a function's
// breakpoint the other threads are executing that very entry. NUM_FUNCS
// retirements per run, each with NUM_THREADS-1 threads crowding the address.

#include <windows.h>
#include <stdio.h>

#define NUM_FUNCS 256
#define NUM_THREADS 8
#define SWEEPS 200

volatile LONG g_calls = 0;

// One tiny noinline function per slot: a real, breakpointable entry point with a
// side effect so nothing can be folded away. The functions are deliberately
// identical in body; only their addresses matter.
#define DEFINE_FN(n) __declspec(noinline) void fn_##n(void) { InterlockedIncrement(&g_calls); }
#define DEFINE_16(hi) \
    DEFINE_FN(hi##0) DEFINE_FN(hi##1) DEFINE_FN(hi##2) DEFINE_FN(hi##3) \
    DEFINE_FN(hi##4) DEFINE_FN(hi##5) DEFINE_FN(hi##6) DEFINE_FN(hi##7) \
    DEFINE_FN(hi##8) DEFINE_FN(hi##9) DEFINE_FN(hi##a) DEFINE_FN(hi##b) \
    DEFINE_FN(hi##c) DEFINE_FN(hi##d) DEFINE_FN(hi##e) DEFINE_FN(hi##f)
#define LIST_16(hi) \
    fn_##hi##0, fn_##hi##1, fn_##hi##2, fn_##hi##3, \
    fn_##hi##4, fn_##hi##5, fn_##hi##6, fn_##hi##7, \
    fn_##hi##8, fn_##hi##9, fn_##hi##a, fn_##hi##b, \
    fn_##hi##c, fn_##hi##d, fn_##hi##e, fn_##hi##f

DEFINE_16(0) DEFINE_16(1) DEFINE_16(2) DEFINE_16(3)
DEFINE_16(4) DEFINE_16(5) DEFINE_16(6) DEFINE_16(7)
DEFINE_16(8) DEFINE_16(9) DEFINE_16(a) DEFINE_16(b)
DEFINE_16(c) DEFINE_16(d) DEFINE_16(e) DEFINE_16(f)

typedef void (*fn_t)(void);

static const fn_t g_fns[NUM_FUNCS] = {
    LIST_16(0), LIST_16(1), LIST_16(2), LIST_16(3),
    LIST_16(4), LIST_16(5), LIST_16(6), LIST_16(7),
    LIST_16(8), LIST_16(9), LIST_16(a), LIST_16(b),
    LIST_16(c), LIST_16(d), LIST_16(e), LIST_16(f),
};

// Gate so every worker starts sweeping at the same moment.
volatile LONG g_go = 0;

static DWORD WINAPI worker(LPVOID param)
{
    (void)param;
    while (g_go == 0) { /* spin until released */ }
    for (int s = 0; s < SWEEPS; s++) {
        for (int i = 0; i < NUM_FUNCS; i++) {
            g_fns[i]();
        }
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

    InterlockedExchange(&g_go, 1);

    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);
    for (int i = 0; i < NUM_THREADS; i++) {
        CloseHandle(threads[i]);
    }

    LONG expected = (LONG)NUM_THREADS * (LONG)SWEEPS * (LONG)NUM_FUNCS;
    printf("total_calls=%ld expected=%ld\n", g_calls, expected);
    // Any surviving corruption from a mishandled breakpoint shows up as a crash
    // exit code; a clean run returns 0.
    return (g_calls == expected) ? 0 : 1;
}
