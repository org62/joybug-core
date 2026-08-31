/*
 * open_remote.exe <marker-dir>
 * open_remote.exe --victim <marker-dir>
 *
 * Cross-process memory access, the thing an analyst wants to see: the parent
 * spawns a victim, opens it with PROCESS_VM_READ|VM_WRITE|VM_OPERATION, reads
 * and then writes the victim's memory, and opens one of its threads with
 * context rights.
 *
 * Unlike a plain read/write of one's own memory (which executes no kernel code
 * and is therefore invisible to any tracing that isn't hardware-assisted),
 * every step here is a syscall: NtOpenProcess, NtReadVirtualMemory,
 * NtWriteVirtualMemory, NtOpenThread. Kernel-Audit-API-Calls reports the two
 * *Open* calls with their DesiredAccess mask, which is what this program exists
 * to generate.
 *
 * The address trick: parent and victim are the SAME image, and Windows picks one
 * ASLR base per image per boot, so `&g_marker` in the parent is the victim's
 * `g_marker` too -- no address discovery needed. The victim writes whatever
 * g_marker holds when it wakes into <marker-dir>\victim.txt, so the file content
 * is ground truth for "the cross-process write actually landed".
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define VICTIM_SLEEP_MS 3000
#define SETTLE_MS 500
#define MARKER_SIZE 64

static const char PAYLOAD[] = "written-across-processes";

/* volatile + non-const so it lands in writable .data at a fixed image offset. */
static volatile char g_marker[MARKER_SIZE] = "untouched";

static void write_marker_file(const char *dir) {
    char path[MAX_PATH];
    HANDLE h;
    DWORD written = 0;

    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\victim.txt", dir);
    h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("victim: CreateFile(%s) failed: %lu\n", path, GetLastError());
        return;
    }
    WriteFile(h, (const void *)g_marker, (DWORD)strlen((const char *)g_marker), &written, NULL);
    CloseHandle(h);
    printf("victim: wrote %s containing '%s'\n", path, (const char *)g_marker);
}

static int run_victim(const char *dir) {
    printf("victim: pid=%lu sleeping %dms with g_marker at %p\n",
           GetCurrentProcessId(), VICTIM_SLEEP_MS, (void *)g_marker);
    Sleep(VICTIM_SLEEP_MS);
    write_marker_file(dir);
    return 0;
}

static int run_parent(const char *self, const char *dir) {
    char cmd[MAX_PATH * 2];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE hproc, hthread;
    char readback[MARKER_SIZE];
    SIZE_T moved = 0;
    int failures = 0;

    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, "\"%s\" --victim \"%s\"", self, dir);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("parent: CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("parent: pid=%lu spawned victim pid=%lu tid=%lu\n",
           GetCurrentProcessId(), pi.dwProcessId, pi.dwThreadId);
    Sleep(SETTLE_MS); /* let the victim finish loading before we poke it */

    /* THE event of interest: OpenProcess with VM read/write/operation rights. */
    hproc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                            PROCESS_QUERY_INFORMATION,
                        FALSE, pi.dwProcessId);
    if (hproc == NULL) {
        printf("parent: OpenProcess failed: %lu\n", GetLastError());
        failures++;
    } else {
        if (ReadProcessMemory(hproc, (LPCVOID)g_marker, readback, sizeof(readback), &moved)) {
            readback[MARKER_SIZE - 1] = '\0';
            printf("parent: read victim g_marker = '%s' (%zu bytes)\n", readback, moved);
        } else {
            printf("parent: ReadProcessMemory failed: %lu\n", GetLastError());
            failures++;
        }
        if (WriteProcessMemory(hproc, (LPVOID)g_marker, PAYLOAD, sizeof(PAYLOAD), &moved)) {
            printf("parent: wrote '%s' into the victim (%zu bytes)\n", PAYLOAD, moved);
        } else {
            printf("parent: WriteProcessMemory failed: %lu\n", GetLastError());
            failures++;
        }
        CloseHandle(hproc);
    }

    /* A second audited open, on a thread rather than a process. */
    hthread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                         FALSE, pi.dwThreadId);
    if (hthread == NULL) {
        printf("parent: OpenThread failed: %lu\n", GetLastError());
        failures++;
    } else {
        printf("parent: opened victim thread %lu\n", pi.dwThreadId);
        CloseHandle(hthread);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("parent: done (%d failure(s))\n", failures);
    return failures;
}

int main(int argc, char *argv[]) {
    char self[MAX_PATH];

    if (argc >= 3 && strcmp(argv[1], "--victim") == 0) {
        return run_victim(argv[2]);
    }
    if (argc < 2) {
        printf("usage: open_remote.exe [--victim] <marker-dir>\n");
        return 1;
    }
    if (GetModuleFileNameA(NULL, self, MAX_PATH) == 0) {
        printf("parent: GetModuleFileName failed: %lu\n", GetLastError());
        return 1;
    }
    return run_parent(self, argv[1]);
}
