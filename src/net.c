#include "net.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

static int set_reuseaddr(int fd)
{
    int opt = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

int net_set_timeouts(int fd, int recv_timeout_ms, int send_timeout_ms)
{
    // SO_RCVTIMEO / SO_SNDTIMEO use struct timeval.
    struct timeval tv;

    if (recv_timeout_ms > 0) {
        tv.tv_sec  = recv_timeout_ms / 1000;
        tv.tv_usec = (recv_timeout_ms % 1000) * 1000;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
            fprintf(stderr, "net_set_timeouts: setsockopt SO_RCVTIMEO failed: %s\n", strerror(errno));
            return -1;
        }
    }

    if (send_timeout_ms > 0) {
        tv.tv_sec  = send_timeout_ms / 1000;
        tv.tv_usec = (send_timeout_ms % 1000) * 1000;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
            fprintf(stderr, "net_set_timeouts: setsockopt SO_SNDTIMEO failed: %s\n", strerror(errno));
            return -1;
        }
    }

    return 0;
}

int net_listen_tcp(const char *host, uint16_t port, int backlog)
{
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;     // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;    // for bind

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "net_listen_tcp: getaddrinfo failed: %s\n", gai_strerror(rc));
        return -1;
    }

    int listen_fd = -1;

    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        listen_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listen_fd < 0) continue;

        (void)set_reuseaddr(listen_fd);

        if (bind(listen_fd, p->ai_addr, (socklen_t)p->ai_addrlen) == 0) {
            if (listen(listen_fd, backlog) == 0) {
                // Success
                break;
            }
        }

        net_close(&listen_fd);
    }

    freeaddrinfo(res);
    return listen_fd;  // -1 if failed
}

int net_accept(int listen_fd)
{
    while (1) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd >= 0) return fd;
        if (errno == EINTR) continue;
        fprintf(stderr, "net_accept: accept failed: %s\n", strerror(errno));
        return -1;
    }
}

int net_connect_tcp(const char *host, uint16_t port)
{
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "net_connect_tcp: getaddrinfo failed: %s\n", gai_strerror(rc));
        return -1;
    }

    int fd = -1;

    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;

        if (connect(fd, p->ai_addr, (socklen_t)p->ai_addrlen) == 0) {
            // success
            break;
        }

        net_close(&fd);
    }

    freeaddrinfo(res);
    return fd;  // -1 if failed
}

int net_send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (n == 0) {
            // Shouldn't happen for send(), but treat as failure.
            fprintf(stderr, "net_send_all: send returned 0\n");
            return -1;
        }
        if (errno == EINTR) continue;
        fprintf(stderr, "net_send_all: send failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int net_recv_exact(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n > 0) {
            got += (size_t)n;
            continue;
        }
        if (n == 0) {
            // Clean EOF (peer closed) before we got everything
            fprintf(stderr, "net_recv_exact: peer closed connection before we received all data\n");
            return 1;
        }
        if (errno == EINTR) continue;
        fprintf(stderr, "net_recv_exact: recv failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

void net_close(int *fd)
{
    if (!fd) return;
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}
