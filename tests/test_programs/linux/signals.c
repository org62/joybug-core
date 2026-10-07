/* Signals that are the program's own business.
 *
 *   signals             handles SIGUSR1 and raises it: exits 10 when the
 *                       handler ran, 11 when the signal never arrived.
 *   signals unhandled   raises SIGUSR2 with nobody listening: dies of it
 *                       (exits 3 if the signal never arrived).
 */
#include <signal.h>
#include <string.h>
#include "../portable.h"

static volatile sig_atomic_t g_got_usr1 = 0;

static void on_usr1(int signo) {
    (void)signo;
    g_got_usr1 = 1;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "unhandled") == 0) {
        raise(SIGUSR2);
        return 3;
    }
    signal(SIGUSR1, on_usr1);
    raise(SIGUSR1);
    return g_got_usr1 ? 10 : 11;
}
