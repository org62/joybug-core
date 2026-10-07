/* Opens one of each kind of descriptor, then calls checkpoint(file, socket):
 * the debugger lists them there and closes `file` behind the program's back.
 * Exits 21 when `file` was closed by the time checkpoint returned, else 20. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../portable.h"

volatile int g_sink = 0;

NOINLINE void checkpoint(int file, int sock) {
    g_sink = file + sock;
}

int main(void) {
    int file = open("/proc/self/maps", O_RDONLY);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    int pipefd[2] = { -1, -1 };
    if (file < 0 || sock < 0 || bind(sock, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(sock, 1) != 0 || pipe(pipefd) != 0) {
        return 2;
    }
    checkpoint(file, sock);
    return (fcntl(file, F_GETFD) == -1 && errno == EBADF) ? 21 : 20;
}
