
#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include <event.h>
#include <dispatch/dispatch.h>


union sockaddr_all {
  struct sockaddr_storage ss;
  struct sockaddr sa;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
};

#define SOCKADDR_LEN(x) ((x.ss.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#define NCONN_ADDRSTRLEN (INET6_ADDRSTRLEN + IF_NAMESIZE + 2)

struct nconn;

typedef void (*nconn_write_cb)(struct nconn *n, void *data);
typedef void (*nconn_read_cb)(struct nconn *n, int fd, size_t estimated, void *data);
typedef void (*nconn_fail_cb)(void *data);


void
nconn_free(struct nconn *n);

void
nconn_close_and_free(struct nconn *n);

int
nconn_running(struct nconn *n);

int
nconn_get_local_addrstr(struct nconn *n, char *buf);

int
nconn_get_remote_addrstr(struct nconn *n, char *buf);

struct nconn *
nconn_outgoing_new(int ldomain, dispatch_group_t user_group, dispatch_queue_t user_queue, const char *address, unsigned short port);

struct nconn *
nconn_listen_new(int ldomain, dispatch_group_t user_group, dispatch_queue_t user_queue, const char *address, unsigned short port);

struct nconn *
nconn_incoming_new(struct nconn *passive, dispatch_group_t group, dispatch_queue_t queue);

int
nconn_start(struct nconn *n, void *data, nconn_read_cb read_cb, nconn_write_cb write_cb, nconn_fail_cb fail_cb);

int
nconn_write(struct nconn *n, struct evbuffer *evbuf);

#endif /* !__NETWORK_H__ */
