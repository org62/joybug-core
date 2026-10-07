/* A parent and a child, both ways Linux makes one.
 *
 *   forker              fork(): the child runs child_work() and exits 7;
 *                       the parent exits 41 when it saw that, else 40.
 *   forker spawn PROG   posix_spawn() (a vfork + exec): the parent exits 51
 *                       when PROG exited 42, else 50.
 */
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../portable.h"

extern char **environ;

volatile int g_child_value = 0;

NOINLINE int child_work(int x) {
    g_child_value = x * 2;
    return g_child_value + 1;
}

static int run_fork(void) {
    pid_t child = fork();
    if (child < 0) {
        return 2;
    }
    if (child == 0) {
        _exit(child_work(3)); /* 7 */
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        return 3;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 7) ? 41 : 40;
}

static int run_spawn(char *program) {
    char *argv[] = { program, NULL };
    pid_t child = 0;
    if (posix_spawn(&child, program, NULL, NULL, argv, environ) != 0) {
        return 2;
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        return 3;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 42) ? 51 : 50;
}

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "spawn") == 0) {
        return run_spawn(argv[2]);
    }
    return run_fork();
}
