/*
 * spawn_chain.exe <generations-left> <marker-dir>
 *
 * A multi-generation process chain where every ancestor is ALREADY DEAD by the
 * time its descendant does any work:
 *
 *     gen 4  ->  spawns gen 3, exits
 *                gen 3  ->  spawns gen 2, exits
 *                           gen 2  ->  spawns gen 1, exits
 *                                      gen 1  ->  exits
 *
 * Unlike parent_child_test.c, the parent does NOT WaitForSingleObject on the
 * child -- it CreateProcess's and returns immediately. That is the whole point:
 * it is the shape an ETW tracer that only waits for its root pid cannot observe
 * (and, when the tracer runs inside a `wsb exec` job object, actively kills).
 *
 * Each generation sleeps briefly before doing anything, which guarantees the
 * parent has exited first, then writes <marker-dir>\gen-<n>.txt -- a file event
 * from a process whose whole ancestry is gone, plus host-visible ground truth
 * when <marker-dir> is a shared folder.
 *
 * Exit code is the generation number, so the root's ProcessStop carries a
 * recognizable value.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/* Long enough that (a) the parent is reliably gone before the child acts, and
 * (b) the chain outlasts the tracer's 1500 ms trailing-event drain by a clear
 * margin -- otherwise a tracer that merely drained after its root exited would
 * capture the whole chain by accident and the test would prove nothing. */
#define GENERATION_DELAY_MS 2000

static void write_marker(const char *dir, int generation) {
    char path[MAX_PATH];
    char body[128];
    HANDLE h;
    DWORD written = 0;

    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\gen-%d.txt", dir, generation);
    h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("gen %d: CreateFile(%s) failed: %lu\n", generation, path, GetLastError());
        return;
    }
    _snprintf_s(body, sizeof(body), _TRUNCATE, "generation %d pid %lu\n",
                generation, GetCurrentProcessId());
    WriteFile(h, body, (DWORD)strlen(body), &written, NULL);
    CloseHandle(h);
    printf("gen %d: wrote %s\n", generation, path);
}

/* Spawn "<this exe> <generation-1> <dir>" and return WITHOUT waiting for it. */
static int spawn_successor(int generation, const char *dir) {
    char self[MAX_PATH];
    char cmd[MAX_PATH * 2];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    if (GetModuleFileNameA(NULL, self, MAX_PATH) == 0) {
        printf("gen %d: GetModuleFileName failed: %lu\n", generation, GetLastError());
        return 0;
    }
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, "\"%s\" %d \"%s\"", self, generation - 1, dir);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("gen %d: CreateProcess failed: %lu\n", generation, GetLastError());
        return 0;
    }
    printf("gen %d (pid=%lu) spawned gen %d as pid=%lu\n",
           generation, GetCurrentProcessId(), generation - 1, pi.dwProcessId);
    /* Deliberately no WaitForSingleObject: we exit while the child runs on. */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
}

int main(int argc, char *argv[]) {
    int generation;
    const char *dir;

    if (argc < 3) {
        printf("usage: spawn_chain.exe <generations-left> <marker-dir>\n");
        return 1;
    }
    generation = atoi(argv[1]);
    dir = argv[2];

    Sleep(GENERATION_DELAY_MS);
    printf("gen %d running (pid=%lu)\n", generation, GetCurrentProcessId());

    write_marker(dir, generation);

    if (generation > 1) {
        spawn_successor(generation, dir);
    }

    printf("gen %d exiting\n", generation);
    return generation;
}
