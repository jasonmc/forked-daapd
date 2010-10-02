/*
 * Copyright (C) 2010 Julien BLACHE <jb@jblache.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>

#include <dispatch/dispatch.h>

#include "evbuffer/evbuffer.h"
#include "logger.h"
#include "network.h"


#if 0
# define NCONN_TRACE(args...) fprintf(stderr, ##args)
#else
# define NCONN_TRACE(args...)
#endif


enum nconn_type {
  NCONN_ERROR = 0,
  NCONN_PASSIVE, /* listen socket */
  NCONN_INCOMING, /* incoming connection accept()ed from a listen socket */
  NCONN_OUTGOING,
};

struct nconn {
  enum nconn_type type;

  int fd;

  dispatch_source_t rsrc;
  dispatch_source_t wsrc;

  /* Writer queue and group */
  dispatch_queue_t wq;
  dispatch_group_t wg;

  /* Write buffer, access only from the writer queue */
  struct evbuffer *wbuf;

  union sockaddr_all sa_local;
  union sockaddr_all sa_remote;

  /* User-provided data */
  int ldomain;
  dispatch_queue_t user_queue;
  dispatch_group_t user_group;

  void *data;
  nconn_write_cb write_cb;
  nconn_read_cb read_cb;
  nconn_fail_cb fail_cb;
};


static struct nconn *
nconn_alloc(int ldomain, dispatch_group_t user_group, dispatch_queue_t user_queue)
{
  char qid[80];
  struct nconn *n;

  NCONN_TRACE("*** nconn_alloc\n");

  n = (struct nconn *)malloc(sizeof(struct nconn));
  if (!n)
    {
      DPRINTF(E_LOG, ldomain, "Out of memory for struct nconn\n");

      return NULL;
    }

  memset(n, 0, sizeof(struct nconn));

  n->wbuf = evbuffer_new();
  if (!n->wbuf)
    {
      DPRINTF(E_LOG, ldomain, "Out of memory for write buffer\n");

      goto wbuf_fail;
    }

  snprintf(qid, sizeof(qid), "org.forked-daapd.nconn.write.%p", n);
  n->wq = dispatch_queue_create(qid, NULL);
  if (!n->wq)
    {
      DPRINTF(E_LOG, ldomain, "Could not create dispatch queue for nconn write ops\n");

      goto wq_fail;
    }

  n->wg = dispatch_group_create();
  if (!n->wg)
    {
      DPRINTF(E_LOG, ldomain, "Could not create dispatch group for nconn write ops\n");

      goto wg_fail;
    }

  dispatch_retain(user_group);
  n->user_group = user_group;

  dispatch_retain(user_queue);
  n->user_queue = user_queue;

  n->fd = -1;

  return n;

 wg_fail:
  dispatch_release(n->wq);
 wq_fail:
  evbuffer_free(n->wbuf);
 wbuf_fail:
  free(n);

  return NULL;
}

void
nconn_free(struct nconn *n)
{
  NCONN_TRACE("*** nconn_free\n");

  dispatch_release(n->wq);
  dispatch_release(n->wg);

  dispatch_release(n->user_queue);
  dispatch_release(n->user_group);

  evbuffer_free(n->wbuf);

  free(n);
}

void
nconn_close_and_free(struct nconn *n)
{
  NCONN_TRACE("*** nconn_close_and_free\n");

  /* The connection was not started */
  if (!n->rsrc)
    {
      nconn_free(n);

      return;
    }

  if (!dispatch_source_testcancel(n->rsrc))
      dispatch_source_cancel(n->rsrc);
}

int
nconn_running(struct nconn *n)
{
  NCONN_TRACE("*** nconn_running\n");

  if (!n)
    return 0;

  return !dispatch_source_testcancel(n->rsrc);
}

static void
nconn_fail(struct nconn *n)
{
  NCONN_TRACE("*** nconn_fail\n");

  /* User must close connection */
  n->fail_cb(n->data);
}

static void
nconn_write_disable(struct nconn *n)
{
  NCONN_TRACE("*** nconn_write_disable\n");

  if (!n->wsrc)
    return;

  /* The write source may have been cancelled from the read queue for
   * a reason or another while the write source handler was running.
   */
  if (!dispatch_source_testcancel(n->wsrc))
    dispatch_source_cancel(n->wsrc);

  n->wsrc = NULL;
}

static int
nconn_write_enable(struct nconn *n)
{
  dispatch_source_t wsrc;

  NCONN_TRACE("*** nconn_write_enable\n");

  if (n->wsrc)
    return 0;

  wsrc = dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE, n->fd, 0, n->wq);
  if (!wsrc)
    {
      DPRINTF(E_LOG, n->ldomain, "Could not create dispatch source (write)\n");

      return -1;
    }

  n->wsrc = wsrc;

  dispatch_source_set_cancel_handler(wsrc, ^{
      NCONN_TRACE("*** wsrc cancel handler\n");

      dispatch_release(wsrc);

      dispatch_group_leave(n->wg);
    });

  dispatch_source_set_event_handler(wsrc, ^{
      int ret;

      NCONN_TRACE("**** wsrc event handler\n");

      ret = evbuffer_write(n->wbuf, n->fd);
      if (ret < 0)
	{
	  DPRINTF(E_WARN, n->ldomain, "Write error (fd %d)\n", n->fd);

	  /* The read source will handle any error */
	  return;
	}

      if (EVBUFFER_LENGTH(n->wbuf) == 0)
	{
	  if (n->write_cb)
	    n->write_cb(n, n->data);

	  NCONN_TRACE("***** returned from write_cb\n");

	  /* If still empty after write_cb, disable */
	  if (EVBUFFER_LENGTH(n->wbuf) == 0)
	    nconn_write_disable(n);
	}
    });

  dispatch_set_context(wsrc, n);

  /* The cancel handler leaves the group */
  dispatch_group_enter(n->wg);

  dispatch_resume(wsrc);

  return 0;
}

static void
nconn_passive_rsrc_cb(void *arg)
{
  struct nconn *n;
  size_t estimated;

  NCONN_TRACE("*** nconn_passive_rsrc_cb\n");

  n = (struct nconn *)arg;

  estimated = dispatch_source_get_data(n->rsrc);

  if (estimated == 0)
    goto failed;

  /* The failure may be specific to this one connection we tried
   * to accept() (eg. the other side aborted) so don't fail the
   * listening connection. The read source will handle errors on
   * the listening connection itself if there are any.
   */

  n->read_cb(n, n->fd, 0, n->data);

  return;

 failed:
  DPRINTF(E_INFO, n->ldomain, "Passive connection failed (fd %d)\n", n->fd);

  nconn_fail(n);
}

static void
nconn_rsrc_cb(void *arg)
{
  struct nconn *n;
  size_t estimated;

  NCONN_TRACE("*** nconn_rsrc_cb\n");

  n = (struct nconn *)arg;

  estimated = dispatch_source_get_data(n->rsrc);
  if (estimated == 0)
    goto failed;

  n->read_cb(n, n->fd, estimated, n->data);

  return;

 failed:
  DPRINTF(E_INFO, n->ldomain, "Connection failed (fd %d)\n", n->fd);

  nconn_fail(n);
}

int
nconn_get_local_addrstr(struct nconn *n, char *buf)
{
  const char *cret;
  int ret;

  switch (n->sa_local.ss.ss_family)
    {
      case AF_INET:
	cret = inet_ntop(AF_INET, &n->sa_local.sin.sin_addr.s_addr, buf, NCONN_ADDRSTRLEN);
	if (!cret)
	  {
	    DPRINTF(E_LOG, n->ldomain, "Could not print local IPv4 address: %s\n", strerror(errno));

	    return -1;
	  }
	break;

      case AF_INET6:
	ret = getnameinfo(&n->sa_local.sa, sizeof(struct sockaddr_in6),
			  buf, NCONN_ADDRSTRLEN, NULL, 0,
			  NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret != 0)
	  {
	    if (ret == EAI_SYSTEM)
	      DPRINTF(E_LOG, n->ldomain, "Could not print local IPv6 address: %s\n", strerror(errno));
	    else
	      DPRINTF(E_LOG, n->ldomain, "Could not print local IPv6 address: %s\n", gai_strerror(ret));

	    return -1;
	  }
	break;
    }

  return 0;
}

static int
nconn_get_local_addr(struct nconn *n)
{
  socklen_t slen;
  int ret;

  NCONN_TRACE("*** nconn_get_local_addr\n");

  slen = sizeof(struct sockaddr_storage);
  ret = getsockname(n->fd, &n->sa_local.sa, &slen);
  if (ret < 0)
    {
      DPRINTF(E_LOG, n->ldomain, "Could not obtain local address: %s\n", strerror(errno));

      return -1;
    }

  return 0;
}

int
nconn_get_remote_addrstr(struct nconn *n, char *buf)
{
  const char *ret;

  switch (n->sa_remote.ss.ss_family)
    {
      case AF_INET:
	ret = inet_ntop(AF_INET, &n->sa_remote.sin.sin_addr.s_addr, buf, NCONN_ADDRSTRLEN);
	break;

      case AF_INET6:
	ret = inet_ntop(AF_INET6, &n->sa_remote.sin6.sin6_addr.s6_addr, buf, NCONN_ADDRSTRLEN);
	break;
    }

  if (!ret)
    {
      DPRINTF(E_LOG, n->ldomain, "Could not print remote address: %s\n", strerror(errno));

      return -1;
    }

  return 0;
}

static int
nconn_make_addr(struct nconn *n, struct sockaddr_storage *ss, const char *address, unsigned short port)
{
  struct addrinfo ai_hints;
  struct addrinfo *ai_res;
  const char *errstr;
  char sport[8];
  int ret;

  NCONN_TRACE("*** nconn_make_addr\n");

  memset(&ai_hints, 0, sizeof(struct addrinfo));

  ai_hints.ai_family = AF_UNSPEC;
  ai_hints.ai_socktype = SOCK_STREAM;
  ai_hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;

  sprintf(sport, "%u", port);

  ret = getaddrinfo(address, sport, &ai_hints, &ai_res);
  if (ret != 0)
    {
      if (ret == EAI_SYSTEM)
	errstr = strerror(errno);
      else
	errstr = gai_strerror(ret);

      DPRINTF(E_LOG, n->ldomain, "getaddrinfo() error: %s\n", errstr);

      return -1;
    }

  memcpy(ss, ai_res->ai_addr, ai_res->ai_addrlen);

  freeaddrinfo(ai_res);

  return 0;
}

struct nconn *
nconn_outgoing_new(int ldomain, dispatch_group_t user_group, dispatch_queue_t user_queue, const char *address, unsigned short port)
{
  struct nconn *n;
  int ret;

  NCONN_TRACE("*** nconn_outgoing_new\n");

  n = nconn_alloc(ldomain, user_group, user_queue);
  if (!n)
    return NULL;

  n->type = NCONN_OUTGOING;
  n->ldomain = ldomain;

  ret = nconn_make_addr(n, &n->sa_remote.ss, address, port);
  if (ret < 0)
    {
      nconn_free(n);
      return NULL;
    }

  return n;
}

struct nconn *
nconn_listen_new(int ldomain, dispatch_group_t user_group, dispatch_queue_t user_queue, const char *address, unsigned short port)
{
  struct nconn *n;
  int ret;

  NCONN_TRACE("*** nconn_listen_new\n");

  n = nconn_alloc(ldomain, user_group, user_queue);
  if (!n)
    return NULL;

  n->type = NCONN_PASSIVE;
  n->ldomain = ldomain;

  ret = nconn_make_addr(n, &n->sa_local.ss, address, port);
  if (ret < 0)
    {
      nconn_free(n);
      return NULL;
    }

  return n;
}

struct nconn *
nconn_incoming_new(struct nconn *passive, dispatch_group_t group, dispatch_queue_t queue)
{
  struct nconn *n;
  socklen_t slen;

  NCONN_TRACE("*** nconn_incoming_new\n");

  n = nconn_alloc(passive->ldomain, group, queue);
  if (!n)
    return NULL;

  n->type = NCONN_INCOMING;
  n->ldomain = passive->ldomain;

  slen = sizeof(struct sockaddr_storage);
  n->fd = accept(passive->fd, &n->sa_remote.sa, &slen);
  if (n->fd < 0)
    {
      DPRINTF(E_LOG, n->ldomain, "Could not accept() connection: %s\n", strerror(errno));

      nconn_free(n);
      return NULL;
    }

  return n;
}

static int
nconn_listen_start(struct nconn *n)
{
  int opt;
  int ret;

  NCONN_TRACE("*** nconn_listen_start\n");

  n->fd = socket(n->sa_local.ss.ss_family, SOCK_STREAM, 0);
  if (n->fd < 0)
    {
      DPRINTF(E_LOG, n->ldomain, "Could not create socket: %s\n", strerror(errno));

      return -1;
    }

  opt = 1;
  ret = setsockopt(n->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  if (ret < 0)
    DPRINTF(E_WARN, n->ldomain, "Could not set SO_REUSEADDR: %s\n", strerror(errno));

  if (n->sa_local.ss.ss_family == AF_INET6)
    {
      opt = 1;
      ret = setsockopt(n->fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
      if (ret < 0)
	DPRINTF(E_WARN, n->ldomain, "Could not set SO_REUSEADDR: %s\n", strerror(errno));
    }

  ret = bind(n->fd, &n->sa_local.sa, SOCKADDR_LEN(n->sa_local));
  if (ret < 0)
    {
      DPRINTF(E_LOG, n->ldomain, "Could not bind socket: %s\n", strerror(errno));

      goto out_fail;
    }

  ret = listen(n->fd, 128);
  if (ret < 0)
    {
      DPRINTF(E_LOG, n->ldomain, "Could not listen: %s\n", strerror(errno));

      goto out_fail;
    }

  return 0;

 out_fail:
  close(n->fd);

  return -1;
}

static int
nconn_incoming_start(struct nconn *n)
{
  int ret;

  NCONN_TRACE("*** nconn_incoming_start\n");

  ret = nconn_get_local_addr(n);
  if (ret < 0)
    {
      close(n->fd);
      return -1;
    }

  return 0;
}

static int
nconn_outgoing_start(struct nconn *n)
{
  int ret;

  NCONN_TRACE("*** nconn_outgoing_start\n");

  n->fd = socket(n->sa_remote.ss.ss_family, SOCK_STREAM, 0);
  if (n->fd < 0)
    {
      DPRINTF(E_LOG, n->ldomain, "Could not create socket: %s\n", strerror(errno));

      return -1;
    }

  ret = connect(n->fd, &n->sa_remote.sa, SOCKADDR_LEN(n->sa_remote));
  if (ret < 0)
    {
      DPRINTF(E_LOG, n->ldomain, "Could not connect: %s\n", strerror(errno));

      goto out_fail;
    }

  ret = nconn_get_local_addr(n);
  if (ret < 0)
    goto out_fail;

  return 0;

 out_fail:
  close(n->fd);

  return -1;
}

int
nconn_start(struct nconn *n, void *data, nconn_read_cb read_cb, nconn_write_cb write_cb, nconn_fail_cb fail_cb)
{
  dispatch_function_t hdl;
  int ret;

  NCONN_TRACE("*** nconn_start\n");

  /* The rsrc cancel handler will leave the group */
  dispatch_group_enter(n->user_group);

  n->read_cb = read_cb;
  n->write_cb = write_cb;
  n->fail_cb = fail_cb;
  n->data = data;

  switch (n->type)
    {
      case NCONN_PASSIVE:
	hdl = nconn_passive_rsrc_cb;
	ret = nconn_listen_start(n);
	break;

      case NCONN_INCOMING:
	hdl = nconn_rsrc_cb;
	ret = nconn_incoming_start(n);
	break;

      case NCONN_OUTGOING:
	hdl = nconn_rsrc_cb;
	ret = nconn_outgoing_start(n);
	break;

      case NCONN_ERROR:
	DPRINTF(E_LOG, n->ldomain, "Attempt to start connection in NCONN_ERROR state!\n");
	ret = -1;
	break;
    }

  if (ret < 0)
    goto start_fail;

  ret = fcntl(n->fd, F_SETFL, O_NONBLOCK);
  if (ret < 0)
    {
      DPRINTF(E_LOG, n->ldomain, "Could not switch socket to non-blocking mode: %s\n", strerror(errno));

      goto nonblock_fail;
    }

  n->rsrc = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, n->fd, 0, n->user_queue);
  if (!n->rsrc)
    {
      DPRINTF(E_LOG, n->ldomain, "Could not create dispatch source (read)\n");

      goto sources_fail;
    }

  dispatch_source_set_cancel_handler(n->rsrc, ^{
      int gret;

      NCONN_TRACE("*** rsrc cancel handler\n");

      if (n->wsrc)
	dispatch_source_cancel(n->wsrc);

      /* Wait on writer */
      gret = dispatch_group_wait(n->wg, DISPATCH_TIME_FOREVER);
      if (gret != 0)
	DPRINTF(E_LOG, n->ldomain, "Error waiting for writer dispatch group\n");

      dispatch_release(n->rsrc);
      close(n->fd);

      dispatch_group_leave(n->user_group);

      nconn_free(n);
    });

  dispatch_source_set_event_handler_f(n->rsrc, hdl);
  dispatch_set_context(n->rsrc, n);
  dispatch_resume(n->rsrc);

  return 0;

 sources_fail:
 nonblock_fail:
  close(n->fd);
 start_fail:
  dispatch_group_leave(n->user_group);

  /* User must free connection */

  return -1;
}

int
nconn_write(struct nconn *n, struct evbuffer *evbuf)
{
  __block int b_ret;
  dispatch_block_t do_write = ^{
    int ret;

    NCONN_TRACE("*** nconn_write BLOCK\n");

    ret = evbuffer_add_buffer(n->wbuf, evbuf);
    if (ret < 0)
      b_ret = -1;
    else
      {
	ret = nconn_write_enable(n);
	if (ret < 0)
	  b_ret = -1;
      }

    dispatch_group_leave(n->wg);
  };

  NCONN_TRACE("*** nconn_write\n");

  dispatch_group_enter(n->wg);

  if (EVBUFFER_LENGTH(evbuf) == 0)
    {
      dispatch_group_leave(n->wg);
      return 0;
    }

  b_ret = 0;

  if (dispatch_get_current_queue() == n->wq)
    do_write();
  else
    dispatch_sync(n->wq, do_write);

  /* dispatch group left in the block */

  return b_ret;
}
