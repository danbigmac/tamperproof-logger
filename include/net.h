#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Create a TCP listening socket bound to host:port.
// host can be "127.0.0.1" or NULL/"0.0.0.0" to bind all.
int net_listen_tcp(const char *host, uint16_t port, int backlog);

// Accept a connection on a listening socket.
int net_accept(int listen_fd);

// Connect to a TCP host:port.
int net_connect_tcp(const char *host, uint16_t port);

// Send exactly len bytes.
int net_send_all(int fd, const uint8_t *buf, size_t len);

// Receive exactly len bytes.
// Returns:
//   0  success (read len bytes)
//   1  clean EOF before len bytes (peer closed)
//  -1  error
int net_recv_exact(int fd, uint8_t *buf, size_t len);

// Set send/recv timeouts (milliseconds). Pass 0 to disable.
int net_set_timeouts(int fd, int recv_timeout_ms, int send_timeout_ms);

// Close fd if valid.
void net_close(int *fd);

#ifdef __cplusplus
}
#endif

#endif
