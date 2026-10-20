#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

/* Read only: no bind, connect, namespace switch, or network configuration. */
int main(void) {
    uint64_t cookie = 0;
    socklen_t length = sizeof(cookie);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    int result = getsockopt(fd, SOL_SOCKET, SO_NETNS_COOKIE, &cookie, &length);
    int closed = close(fd);
    if (result != 0 || closed != 0 || length != sizeof(cookie) || cookie == 0)
        return 1;
    return printf("%" PRIu64 "\n", cookie) > 0 && fflush(stdout) == 0 ? 0 : 1;
}
