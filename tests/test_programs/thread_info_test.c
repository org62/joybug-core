#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <intrin.h>

#define NAME_EXCEPTION 0x406D1388
#define TIMEOUT_MS 30000
volatile LONG g_phase;
volatile DWORD g_worker_tid;
volatile unsigned __int64 g_sink;
static HANDLE work_event, done_event, worker_ready, running_event, release_event;
static volatile LONG worker_result;

__declspec(noinline) void thread_info_marker(void) { _ReadWriteBarrier(); __debugbreak(); }
static void checkpoint(LONG phase) {
    g_phase = phase;
    SetLastError(0x1234ABCD);
    thread_info_marker();
}

/* The native form is the actual three-slot packed structure, with deliberately
   nonzero padding above dwType, not three separately supplied field values. */
#pragma pack(push, 8)
typedef struct THREADNAME_INFO {
    DWORD type;
#ifdef _WIN64
    DWORD padding;
#endif
    const char *name;
    DWORD tid;
    DWORD flags;
} THREADNAME_INFO;
#pragma pack(pop)

static void legacy(const char *name, DWORD tid, DWORD flags) {
    THREADNAME_INFO info;
    memset(&info, 0, sizeof(info));
    info.type = 0x1000;
#ifdef _WIN64
    info.padding = 0xBAADF00D;
#endif
    info.name = name; info.tid = tid; info.flags = flags;
    __try { RaiseException(NAME_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR *)&info); }
    __except(GetExceptionCode() == NAME_EXCEPTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { }
}

static void fields(ULONG_PTR type, const char *name, DWORD tid, DWORD flags, DWORD count) {
    ULONG_PTR args[4] = {type, (ULONG_PTR)name, tid, flags};
    __try { RaiseException(NAME_EXCEPTION, 0, count, args); }
    __except(GetExceptionCode() == NAME_EXCEPTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { }
}

static DWORD WINAPI worker(void *unused) {
    unsigned __int64 i, value = 1;
    (void)unused;
    SetEvent(worker_ready);
    if (WaitForSingleObject(work_event, TIMEOUT_MS) != WAIT_OBJECT_0) return 91;
    for (i = 0; i < 30000000; ++i) { value = value * 6364136223846793005ULL + i; g_sink = value; }
    SetLastError(0x87654321);
    InterlockedExchange(&worker_result, 1);
    SetEvent(done_event);
    if (WaitForSingleObject(release_event, TIMEOUT_MS) != WAIT_OBJECT_0) return 92;
    return 0;
}

int main(void) {
    HANDLE thread;
    DWORD tid, exit_code = 0;
    SYSTEM_INFO si;
    char event_name[128];
    char *pages, *guard_name;
    DWORD old_protect;
    work_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    done_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    worker_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    sprintf_s(event_name, sizeof(event_name), "Local\\joybug-thread-info-%lu-running", GetCurrentProcessId());
    running_event = CreateEventA(NULL, TRUE, FALSE, event_name);
    sprintf_s(event_name, sizeof(event_name), "Local\\joybug-thread-info-%lu-release", GetCurrentProcessId());
    release_event = CreateEventA(NULL, TRUE, FALSE, event_name);
    if (!work_event || !done_event || !worker_ready || !running_event || !release_event) return 80;
    thread = CreateThread(NULL, 0, worker, NULL, 0, &tid);
    if (!thread) return 81;
    g_worker_tid = tid;
    if (!SetThreadPriority(thread, THREAD_PRIORITY_BELOW_NORMAL)) return 82;
    if (WaitForSingleObject(worker_ready, TIMEOUT_MS) != WAIT_OBJECT_0) return 83;

    legacy(" legacy main ", (DWORD)-1, 0);
    legacy("legacy worker", tid, 0);
    /* Valid unknown target, deliberately unreadable pointer: consumed without a read. */
    legacy((const char *)1, 0xFFFFFFFE, 0);
    checkpoint(1);
    legacy("renamed main", (DWORD)-1, 0); checkpoint(2);
    GetSystemInfo(&si);
    pages = (char *)VirtualAlloc(NULL, si.dwPageSize * 3, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pages) return 84;
    if (!VirtualProtect(pages + si.dwPageSize, si.dwPageSize, PAGE_NOACCESS, &old_protect)) return 85;
    guard_name = pages + si.dwPageSize - 5;
    memcpy(guard_name, "edge", 5);
    legacy(guard_name, (DWORD)-1, 0); checkpoint(3);
    legacy("caf\xE9", (DWORD)-1, 0); checkpoint(4);
    if (FAILED(SetThreadDescription(GetCurrentThread(), L"modern main \x03BB"))) return 86;
    if (FAILED(SetThreadDescription(thread, L"\x73B0\x4EE3 worker \x03A9"))) return 87;
    checkpoint(5);
    SetThreadDescription(GetCurrentThread(), L"modern renamed \xD83D\xDC1E"); checkpoint(6);
    legacy("latest legacy", (DWORD)-1, 0); checkpoint(7);
    SetThreadDescription(GetCurrentThread(), L""); checkpoint(8);
    legacy("", (DWORD)-1, 0); checkpoint(9);
    fields(0x1000, "native four", (DWORD)-1, 0, 4); checkpoint(10);

    /* Each must reach ordinary first-chance policy, then our SEH handler. */
    legacy("invalid flags", (DWORD)-1, 1);
    legacy((const char *)1, (DWORD)-1, 0);
    legacy(NULL, (DWORD)-1, 0);
    fields(0x2000, "invalid type", (DWORD)-1, 0, 4);
    fields(0x1000, "invalid count", (DWORD)-1, 0, 2);
    memset(pages + 2 * si.dwPageSize, 'x', si.dwPageSize);
    legacy(pages + 2 * si.dwPageSize, (DWORD)-1, 0);
    memset(pages + si.dwPageSize - 2, 'x', 2);
    legacy(pages + si.dwPageSize - 2, (DWORD)-1, 0);
    checkpoint(11);
    checkpoint(12);
    SetEvent(work_event);
    if (WaitForSingleObject(done_event, TIMEOUT_MS) != WAIT_OBJECT_0 || worker_result != 1) return 88;
    checkpoint(13);
    checkpoint(14);
    SetEvent(running_event);
    if (WaitForSingleObject(release_event, TIMEOUT_MS) != WAIT_OBJECT_0) return 89;
    if (WaitForSingleObject(thread, TIMEOUT_MS) != WAIT_OBJECT_0) return 90;
    GetExitCodeThread(thread, &exit_code);
    checkpoint(15);
    CloseHandle(thread); CloseHandle(work_event); CloseHandle(done_event);
    CloseHandle(worker_ready); CloseHandle(running_event); CloseHandle(release_event);
    VirtualFree(pages, 0, MEM_RELEASE);
    return (int)exit_code;
}
