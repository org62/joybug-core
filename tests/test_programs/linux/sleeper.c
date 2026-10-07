/* A long-lived attach target. Allows any process to ptrace it, since the
 * test runner is not an ancestor of the debugger under Yama scope 1. */
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

int main(void) {
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    printf("sleeper %d\n", (int)getpid());
    fflush(stdout);
    for (;;) {
        sleep(1);
    }
    return 0;
}
