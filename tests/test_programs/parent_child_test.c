#include <windows.h>
#include <stdio.h>
#include <string.h>

__declspec(noinline) int child_work(void) {
    volatile int x = 42;
    volatile int y = x * 2;
    return (int)y;
}

__declspec(noinline) int parent_work(void) {
    volatile int a = 100;
    volatile int b = a + 50;
    return (int)b;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        printf("Child process running (pid=%lu)\n", GetCurrentProcessId());
        int result = child_work();
        printf("Child done: %d\n", result);
        return result;
    }

    // Parent: spawn self with --child
    printf("Parent process running (pid=%lu)\n", GetCurrentProcessId());

    char cmd[MAX_PATH + 16];
    // Build command: "<this_exe> --child"
    GetModuleFileNameA(NULL, cmd, MAX_PATH);
    strcat_s(cmd, sizeof(cmd), " --child");

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    printf("Parent spawned child pid=%lu\n", pi.dwProcessId);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    int result = parent_work();
    printf("Parent done: %d\n", result);
    return result;
}
