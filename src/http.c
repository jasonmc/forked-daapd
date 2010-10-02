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
#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>

#include <dispatch/dispatch.h>

#include "evbuffer/evbuffer.h"
#include "logger.h"
#include "misc.h"
#include "network.h"
#include "http.h"


#if 0
# define HTTP_TRACE(args...) fprintf(stderr, ##args)
#else
# define HTTP_TRACE(args...)
#endif

#define USER_AGENT PACKAGE "/" VERSION


enum xfer_status {
  R_NEW,
  R_FROZEN,
  R_RUNNABLE,
  R_FIRSTLINE,
  R_HEADERS,
  R_BODY,
  R_DONE,
};

#define REQ_F_CLOSE   (1 << 0)

struct http_request {
  enum xfer_status status;
  enum p_version proto_ver;
  enum request_method method;

  int flags;

  char *uri;

  struct keyval headers;

  struct evbuffer *body;

  struct http_response *response;

  /* Server-specific */
  int64_t content_length;

  struct http_request *next;
  /* --- */

  /* Client-specific */
  http_cb cb;
  /* --- */
};

struct http_response {
  enum xfer_status status;
  enum p_version proto_ver;

  int status_code;
  char *reason;

  struct keyval headers;

  int64_t content_length;
  struct evbuffer *body;

  struct http_request *request;

  /* Server-specific */
  void *data;

  http_chunk_cb chunk_cb;
  http_free_cb free_cb;
  /* --- */
};

#define CONN_F_CLOSE        (1 << 0)
#define CONN_F_LAST_CHUNK   (1 << 1)

struct http_connection {
  struct nconn *conn;
  struct evbuffer *readbuf;

  int flags;

  dispatch_queue_t queue;
  dispatch_group_t group;

  /* Request queue */
  struct http_request *req_head;
  struct http_request *req_tail;

  void *data;

  http_close_cb close_cb;
  http_free_cb free_cb;

  /* Server-specific */
  http_cb cb;

  /* Chunked response in progress or frozen request */
  struct http_response *response;

  struct http_connection *next;
  /* --- */
};

struct http_server {
  struct nconn *lconn;

  dispatch_queue_t queue;
  dispatch_group_t group;

  dispatch_group_t user_group;

  struct http_connection *hconn_head;
  struct http_connection *hconn_tail;

  http_cb cb;
  http_server_close_cb close_cb;
};


/* Keep in sync with enum p_version */
static const char *p_versions[] = {
  "1.0",
  "1.1",
};


#define METHOD_STR(x) (methods[(x & ~METHOD_MASK)])
/* Keep in sync with enum request_method */
static const char *methods[] = {
  /* HTTP */
  "GET",
  "POST",

  /* RTSP */
  "ANNOUNCE",
  "OPTIONS",
  "SETUP",
  "RECORD",
  "PAUSE",
  "GET_PARAMETER",
  "SET_PARAMETER",
  "FLUSH",
  "TEARDOWN",
};


/* Utilities */
void
http_decode_uri(char *uri, enum uri_decode_mode mode)
{
  char *e;
  char *d;
  int decode_plus;

  switch (mode)
    {
      case URI_DECODE_NORMAL:
      case URI_DECODE_PLUS_NEVER:
	decode_plus = 0;
	break;

      case URI_DECODE_PLUS_ALWAYS:
	decode_plus = 1;
	break;
    }

  e = uri;
  d = e;

  while (*e != '\0')
    {
      if ((*e == '?') && (mode == URI_DECODE_NORMAL))
	decode_plus = 1;
      else if ((*e == '+') && decode_plus)
	*d = ' ';
      else if ((e[0] == '%') && isxdigit(e[1]) && isxdigit(e[2]))
	{
	  e[1] = tolower(e[1]);
	  e[2] = tolower(e[2]);

	  e[1] -= (e[1] > '9') ? ('a' - 10) : '0';
	  e[2] -= (e[2] > '9') ? ('a' - 10) : '0';

	  *d = (e[1] << 4) | (e[2] & 0x0f);

	  e += 2;
	}
      else if (d != e)
	*d = *e;

      d++;
      e++;
    }

  *d = '\0';
}

int
http_parse_query_string(const char *uri, struct keyval *kv)
{
  char *query;
  char *p;
  char *name;
  char *value;
  int count;
  int ret;

  kv->head = NULL;
  kv->tail = NULL;

  /* No query in URI */
  uri = strchr(uri, '?');
  if (!uri)
    return 0;

  query = strdup(uri + 1);
  if (!query)
    {
      DPRINTF(E_LOG, L_HTTP, "Out of memory for query string copy\n");

      return -1;
    }

  count = 0;

  p = query;
  ret = 0;
  while (p && (*p != '\0'))
    {
      value = strsep(&p, "&");
      name = strsep(&value, "=");
      if (!value)
	break;

      http_decode_uri(value, URI_DECODE_PLUS_ALWAYS);

      ret = keyval_add(kv, name, value);
      if (ret < 0)
	break;

      count++;
    }

  free(query);
  return (ret < 0) ? ret : count;
}

const char *
http_method(enum request_method method)
{
  return METHOD_STR(method);
}


/* Helpers */
static int
header_parse_line(char *line, struct onekeyval *okv, char **name, char **value)
{
  char *p;

  /* Reached end of headers */
  if (*line == '\0')
    return 1;

  /* Multiline header continuation */
  if ((*line == ' ') || (*line == '\t'))
    {
      if (!okv)
	{
	  DPRINTF(E_LOG, L_HTTP, "Malformed request, continuation header line with no previous header\n");

	  return -1;
	}

      p = realloc(okv->value, strlen(okv->value) + strlen(line) + 1);
      if (!p)
	{
	  DPRINTF(E_LOG, L_HTTP, "Out of memory for multiline header\n");

	  return -1;
	}

      strcat(p, line);
      okv->value = p;

      return 2;
    }

  p = strchr(line, ':');
  if (!p)
    {
      DPRINTF(E_LOG, L_HTTP, "Malformed header: %s\n", line);

      return -1;
    }

  *p = '\0';
  p++;
  p += strspn(p, " \t");

  *name = line;
  *value = p;

  return 0;
}

static int
headers_read(struct keyval *hdr, struct evbuffer *buf)
{
  char *line;
  char *name;
  char *value;
  int ret;

  while ((line = evbuffer_readline(buf)))
    {
      ret = header_parse_line(line, hdr->tail, &name, &value);
      if (ret == 2)
	continue; /* Multi-line header */
      else if (ret != 0)
	break;

      ret = keyval_add(hdr, name, value);
      if (ret < 0)
	{
	  ret = -2;
	  break;
	}
    }

  /* More to come */
  if (!line)
    return 1;

  /* End of headers or error */
  return (ret == 1) ? 0 : -1;
}

static int
headers_write(struct onekeyval *hh, struct evbuffer *buf)
{
  struct onekeyval *h;
  int ret;

  for (h = hh; h; h = h->next)
    {
      ret = evbuffer_add_printf(buf, "%s: %s\r\n", h->name, h->value);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_HTTP, "Out of memory while writing HTTP headers\n");

	  return -1;
	}
    }

  ret = evbuffer_add(buf, "\r\n", 2);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Out of memory for HTTP headers separator\n");

      return -1;
    }

  return 0;
}


/* HTTP connection */
int
http_connection_get_local_addr(struct http_connection *c, char *buf)
{
  if (!c->conn)
    return -1;

  return nconn_get_local_addrstr(c->conn, buf);
}

int
http_connection_get_remote_addr(struct http_connection *c, char *buf)
{
  if (!c->conn)
    return -1;

  return nconn_get_remote_addrstr(c->conn, buf);
}

static void
connection_free_task(void *arg)
{
  struct nconn *n;
  struct http_connection *c;

  c = (struct http_connection *)arg;

  dispatch_group_enter(c->group);

  dispatch_group_notify(c->group, c->queue, ^{
      struct http_request *req;
      struct http_request *reqs;

      dispatch_release(c->group);
      dispatch_release(c->queue);

      evbuffer_free(c->readbuf);

      /* Chunked response or frozen request */
      if (c->response)
	{
	  c->response->free_cb(c->response->data);

	  http_response_free(c->response);
	  c->response = NULL;
	}

      reqs = c->req_head;
      for (req = reqs; reqs; req = reqs)
	{
	  reqs = req->next;

	  http_request_free(req);
	}

      c->free_cb(c->data);
      free(c);
    });

  if (c->conn)
    {
      n = c->conn;
      c->conn = NULL;
      nconn_close_and_free(n);
    }

  dispatch_group_leave(c->group);
}

static void
connection_free(struct http_connection *c)
{
  if (dispatch_get_current_queue() != c->queue)
    dispatch_sync_f(c->queue, c, connection_free_task);
  else
    connection_free_task(c);
}

/* HTTP request */
void
http_request_free(struct http_request *req)
{
  if (req->uri)
    free(req->uri);

  keyval_clear(&req->headers);

  if (req->body)
    evbuffer_free(req->body);

  if (req->response)
    {
      req->response->request = NULL;
      http_response_free(req->response);
    }

  free(req);
}

const char *
http_request_get_uri(struct http_request *req)
{
  return req->uri;
}

int
http_request_set_body(struct http_request *req, struct evbuffer *evbuf)
{
  if (!(req->method & METHOD_HAS_BODY))
    return -1;

  if (req->body)
    evbuffer_free(req->body);

  req->body = evbuf;

  return 0;
}

void
http_request_remove_header(struct http_request *req, const char *name)
{
  keyval_remove(&req->headers, name);
}

int
http_request_add_header(struct http_request *req, const char *name, const char *value)
{
  return keyval_add(&req->headers, name, value);
}

const char *
http_request_get_header(struct http_request *req, const char *name)
{
  return keyval_get(&req->headers, name);
}


/* HTTP response */
void
http_response_free(struct http_response *r)
{
  keyval_clear(&r->headers);

  if (r->reason)
    free(r->reason);

  if (r->body)
    evbuffer_free(r->body);

  if (r->request)
    {
      r->request->response = NULL;
      http_request_free(r->request);
    }

  free(r);
}

struct evbuffer *
http_response_get_body(struct http_response *r)
{
  return r->body;
}

void
http_response_set_body(struct http_response *r, struct evbuffer *evbuf)
{
  if (r->body)
    evbuffer_free(r->body);

  r->body = evbuf;
}

void
http_response_remove_header(struct http_response *r, const char *name)
{
  keyval_remove(&r->headers, name);
}

int
http_response_add_header(struct http_response *r, const char *name, const char *value)
{
  return keyval_add(&r->headers, name, value);
}

const char *
http_response_get_header(struct http_response *r, const char *name)
{
  return keyval_get(&r->headers, name);
}

int
http_response_get_status(struct http_response *r, const char **reason)
{
  if (*reason)
    *reason = r->reason;

  return r->status_code;
}

int
http_response_set_status(struct http_response *r, int status_code, const char *reason)
{
  if (!reason)
    return -1;

  if (r->reason)
    free(r->reason);

  r->reason = strdup(reason);
  if (!r->reason)
    {
      DPRINTF(E_LOG, L_HTTP, "Out of memory for HTTP response reason\n");

      return -1;
    }

  r->status_code = status_code;

  return 0;
}


/*
 * GCD-based HTTP client - Theory of operation
 *
 * The HTTP client is actually a struct http_connection object and a set of
 * methods to manipulate struct http_request and struct http_response,
 * including submitting (running) a struct http_request to the struct
 * http_connection.
 *
 * The HTTP connection uses a struct nconn for all network operations.
 *
 * As such, write operations happen on the struct nconn write queue. Read
 * operations happen on the struct http_connection queue; this includes the
 * user processing of the response via the user-supplied http_cb. All
 * http_client_*() operations must happen on the struct http_connection queue.
 *
 * The HTTP client uses the current queue at the time it is created as the
 * struct http_connection queue.
 *
 * The "write queue" references the struct nconn write queue.
 * The "read queue" references the struct http_connection queue.
 *
 * A private dispatch_group is used by the struct http_connection to
 * synchronize with the struct nconn at shutdown.
 *
 * The HTTP client also handles RTSP methods.
 */

/* HTTP/RTSP client */
static int
response_parse_status_line(struct http_response *r, char *line)
{
  char *version;
  char *code;
  char *reason;
  int i;
  int ret;

  version = strchr(line, '/');
  if (!version)
    goto malformed;

  version++;

  code = strchr(version, ' ');
  if (!code)
    goto malformed;

  *code = '\0';
  code++;

  reason = strchr(code, ' ');
  if (!reason)
    {
      *(code - 1) = ' ';
      goto malformed;
    }

  *reason = '\0';
  reason++;

  for (i = 0; i < (sizeof(p_versions) / sizeof(p_versions[0])); i++)
    {
      if (strcmp(version, p_versions[i]) == 0)
	{
	  r->proto_ver = i;
	  break;
	}
    }

  if (i == (sizeof(p_versions) / sizeof(p_versions[0])))
    {
      DPRINTF(E_LOG, L_HTTP, "Unknown HTTP version %s\n", version);

      return -1;
    }

  /* RTSP: check version is 1.0 */
  if ((r->request->method & RTSP_METHOD) && (r->proto_ver != P_VER_1_0))
    {
      DPRINTF(E_LOG, L_HTTP, "Bad version %s for RTSP response\n", version);

      return -1;
    }

  ret = safe_atoi32(code, &r->status_code);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not convert status code to integer: %s\n", code);

      return -1;
    }

  r->reason = strdup(reason);
  if (!r->reason)
    {
      DPRINTF(E_LOG, L_HTTP, "Out of memory for HTTP reason\n");

      return -1;
    }

  return 0;

 malformed:
  DPRINTF(E_LOG, L_HTTP, "Malformed status line in response: %s\n", line);

  return -1;
}

static void
client_read_cb(struct nconn *n, int fd, size_t estimated, void *data)
{
  struct http_connection *c;
  struct http_request *req;
  struct http_response *r;
  const char *hdr;
  char *line;
  size_t len;
  int ret;

  c = (struct http_connection *)data;

  req = c->req_head;
  if (!req)
    {
      DPRINTF(E_LOG, L_HTTP, "HTTP client error: data received with no pending requests\n");

      goto fail;
    }

  if (req->response)
    r = req->response;
  else
    {
      r = (struct http_response *)malloc(sizeof(struct http_response));
      if (!r)
	{
	  DPRINTF(E_LOG, L_HTTP, "Out of memory for HTTP reponse\n");

	  goto fail;
	}

      memset(r, 0, sizeof(struct http_response));

      r->body = evbuffer_new();
      if (!r->body)
	{
	  DPRINTF(E_LOG, L_HTTP, "Out of memory for HTTP response body\n");

	  free(r);
	  goto fail;
	}

      r->status = R_FIRSTLINE;
      r->request = req;

      req->response = r;
    }

  ret = evbuffer_read(c->readbuf, fd, -1);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "HTTP client failure while reading response\n");

      goto fail;
    }

  do
    {
      if (r->status == R_FIRSTLINE)
	{
	  line = evbuffer_readline(c->readbuf);
	  if (!line)
	    {
	      ret = 1; /* Not enough data */
	      break;
	    }

	  ret = response_parse_status_line(r, line);
	  if (ret == 0)
	    {
	      DPRINTF(E_DBG, L_HTTP, "Response status: %d %s (ver %s)\n", r->status_code, r->reason, p_versions[r->proto_ver]);

	      r->status = R_HEADERS;
	    }
	}
      else if (r->status == R_HEADERS)
	{
	  ret = headers_read(&r->headers, c->readbuf);
	  if (ret == 1)
	    DPRINTF(E_DBG, L_HTTP, "More headers expected in response\n");
	  else if (ret == 0)
	    {
	      DPRINTF(E_DBG, L_HTTP, "End of headers in response\n");

	      r->status = R_BODY;

	      hdr = keyval_get(&r->headers, "Content-Length");
	      if (hdr)
		{
		  ret = safe_atoi64(hdr, &r->content_length);
		  if (ret < 0)
		    {
		      DPRINTF(E_LOG, L_HTTP, "Invalid Content-Length: %s\n", hdr);

		      break;
		    }
		}
	      else
		{
		  if (req->flags & REQ_F_CLOSE)
		    r->content_length = -1;
		  else if (req->method & RTSP_METHOD)
		    r->content_length = 0;
		  else
		    {
		      DPRINTF(E_LOG, L_HTTP, "Cannot determine response length!\n");

		      ret = -1;
		      break;
		    }
		}

	      if (r->content_length == 0)
		{
		  r->status = R_DONE;
		  ret = 1;
		  break;
		}

	      if (EVBUFFER_LENGTH(c->readbuf) == 0)
		{
		  ret = 1;
		  break;
		}
	    }
	}
      else
	{
	  DPRINTF(E_DBG, L_HTTP, "Reading body, content-length %" PRId64 "\n", r->content_length);

	  if (r->content_length == -1)
	    {
	      ret = evbuffer_add_buffer(r->body, c->readbuf);
	      if (ret < 0)
		DPRINTF(E_LOG, L_HTTP, "Out of memory for response body\n");

	      /* Nothing more to do here */
	      break;
	    }
	  else
	    {
	      len = r->content_length - EVBUFFER_LENGTH(r->body);

	      DPRINTF(E_DBG, L_HTTP, "Reading body, %lu bytes to go\n", (unsigned long)len);

	      if (len >= EVBUFFER_LENGTH(c->readbuf))
		ret = evbuffer_add_buffer(r->body, c->readbuf);
	      else
		{
		  ret = evbuffer_add(r->body, EVBUFFER_DATA(c->readbuf), len);
		  evbuffer_drain(c->readbuf, len);
		}

	      if (ret < 0)
		{
		  DPRINTF(E_LOG, L_HTTP, "Out of memory for response body\n");
		  break;
		}

	      if ((r->content_length - EVBUFFER_LENGTH(r->body)) == 0)
		{
		  r->status = R_DONE;
		  ret = 1;
		}

	      /* Nothing more to do here */
	      break;
	    }

	  /* For chunked replies, would need to try to read trailer
	   * after body is complete
	   */
	}
    }
  while (ret == 0);

  if (ret < 0)
    goto fail;

  if (r->status == R_DONE)
    {
      c->req_head = req->next;
      req->next = NULL;

      if (c->req_tail == req)
	c->req_tail = NULL;

      req->cb(c, req, r, c->data);
    }

  return;

 fail:
  c->conn = NULL;
  nconn_close_and_free(n);

  c->close_cb(c, c->data);
}

static void
client_fail_cb(void *data)
{
  struct nconn *n;
  struct http_connection *c;
  struct http_request *req;
  struct http_response *r;

  c = (struct http_connection *)data;

  n = c->conn;
  c->conn = NULL;
  nconn_close_and_free(n);

  req = c->req_head;
  if (!req)
    goto fail;

  if (!req->response)
    goto fail;

  r = req->response;

  if ((r->status != R_BODY) || (r->content_length != -1))
    goto fail;

  /* Reply to a Connection: close request without Content-Length */

  r->status = R_DONE;

  c->req_head = req->next;
  req->next = NULL;

  if (c->req_tail == req)
    c->req_tail = NULL;

  req->cb(c, req, r, c->data);

  return;

 fail:
  c->close_cb(c, c->data);
}

struct http_connection *
http_client_new(int ldomain, const char *address, short port, http_close_cb close_cb, http_free_cb free_cb, void *data)
{
  struct http_connection *c;
  int ret;

  c = (struct http_connection *)malloc(sizeof(struct http_connection));
  if (!c)
    {
      DPRINTF(E_LOG, L_HTTP, "Out of memory for HTTP client\n");

      return NULL;
    }

  memset(c, 0, sizeof(struct http_connection));

  c->readbuf = evbuffer_new();
  if (!c->readbuf)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not create HTTP client buffer\n");

      goto buffer_fail;
    }

  c->group = dispatch_group_create();
  if (!c->group)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not create HTTP client group\n");

      goto group_fail;
    }

  /* Client executes on the same queue; don't use a global concurrent queue! */
  c->queue = dispatch_get_current_queue();
  dispatch_retain(c->queue);

  c->conn = nconn_outgoing_new(ldomain, c->group, c->queue, address, port);
  if (!c->conn)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not create HTTP client network connection\n");

      goto nconn_fail;
    }

  c->close_cb = close_cb;
  c->free_cb = free_cb;
  c->data = data;

  ret = nconn_start(c->conn, c, client_read_cb, NULL, client_fail_cb);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not start HTTP client network connection\n");

      goto start_fail;
    }

  return c;

 start_fail:
  nconn_free(c->conn);
 nconn_fail:
  dispatch_release(c->group);
  dispatch_release(c->queue);
 group_fail:
  evbuffer_free(c->readbuf);
 buffer_fail:
  free(c);

  return NULL;
}

void
http_client_free(struct http_connection *c)
{
  connection_free(c);
}

struct http_request *
http_client_request_new(enum request_method method, enum p_version version, const char *uri, http_cb cb)
{
  struct http_request *req;

  req = (struct http_request *)malloc(sizeof(struct http_request));
  if (!req)
    {
      DPRINTF(E_LOG, L_HTTP, "Out of memory for new HTTP request\n");

      return NULL;
    }

  memset(req, 0, sizeof(struct http_request));

  req->method = method;
  req->proto_ver = version;

  req->uri = strdup(uri);
  if (!req->uri)
    {
      DPRINTF(E_LOG, L_HTTP, "Couldn't make new request: out of memory for URI\n");

      free(req);
      return NULL;
    }

  req->cb = cb;

  return req;
}

int
http_client_request_run(struct http_connection *c, struct http_request *req)
{
  char buf[16];
  struct nconn *n;
  struct http_request *old_tail;
  struct evbuffer *evbuf;
  const char *hdr;
  const char *method;
  const char *protocol;
  size_t bodylen;
  int ret;

  if (!c->conn)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run request: HTTP client failed\n");

      return -1;
    }

  if (c->req_tail && (c->req_tail->flags & REQ_F_CLOSE))
    {
      DPRINTF(E_LOG, L_HTTP, "Not running request: previous request closes connection\n");

      return -1;
    }

  evbuf = evbuffer_new();
  if (!evbuf)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run request: out of memory for buffer\n");

      return -1;
    }

  /* Handle connection depending on protocol version & options */
  if (req->method & HTTP_METHOD)
    {
      if (req->proto_ver == P_VER_1_0)
	req->flags |= REQ_F_CLOSE;
      else
	{
	  hdr = keyval_get(&req->headers, "Connection");
	  if (hdr && (strcmp(hdr, "close") == 0))
	    {
	      DPRINTF(E_DBG, L_HTTP, "Request is HTTP/1.1 with Connection: close\n");

	      req->flags |= REQ_F_CLOSE;
	    }
	}
    }

  /* Content-Length */
  keyval_remove(&req->headers, "Content-Length");

  bodylen = (req->body) ? EVBUFFER_LENGTH(req->body) : 0;
  if (bodylen > 0)
    {
      buf[0] = '\0';
      snprintf(buf, sizeof(buf), "%ld", (long)bodylen);

      keyval_add(&req->headers, "Content-Length", buf);
    }

  /* User-Agent */
  keyval_add(&req->headers, "User-Agent", USER_AGENT);

  /* Assemble request */
  if (req->method & RTSP_METHOD)
    protocol = "RTSP";
  else
    protocol = "HTTP";

  method = METHOD_STR(req->method);

  ret = evbuffer_add_printf(evbuf, "%s %s %s/%s\r\n", method, req->uri, protocol, p_versions[req->proto_ver]);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run request: out of memory for request line\n");

      goto buffer_fail;
    }

  ret = headers_write(req->headers.head, evbuf);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run request: out of memory for headers\n");

      goto buffer_fail;
    }

  if (req->body)
    {
      ret = evbuffer_add_buffer(evbuf, req->body);

      evbuffer_free(req->body);
      req->body = NULL;

      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_HTTP, "Could not run request: out of memory for body\n");

	  goto buffer_fail;
	}
    }

  /* Store request */
  req->next = NULL;

  old_tail = c->req_tail;

  if (c->req_tail)
    c->req_tail->next = req;

  c->req_tail = req;

  if (!c->req_head)
    c->req_head = c->req_tail;

  ret = nconn_write(c->conn, evbuf);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run request: connection write error\n");

      n = c->conn;
      c->conn = NULL;
      nconn_close_and_free(n);

      if (c->req_head == c->req_tail)
	c->req_head = NULL;

      if (old_tail)
	old_tail->next = NULL;

      c->req_tail = old_tail;

      goto buffer_fail;
    }

  evbuffer_free(evbuf);

  return 0;

 buffer_fail:
  evbuffer_free(evbuf);

  return -1;
}


/*
 * GCD-based HTTP server - Theory of operation
 *
 * The HTTP server is a struct http_server object maintaining a pasive socket
 * for incoming connections and a list of active struct http_connection. The
 * struct http_server uses its own private queue to manage the list of active
 * connections.
 *
 * The server uses two dispatch_groups:
 *  - a private dispatch_group to synchronize with the active struct
 *    http_connections at shutdown;
 *  - a user-provided dispatch_group that the user can use to synchronize with
 *    her active struct http_servers when shutting down.
 *
 * The HTTP server uses struct nconn for all network operations.
 *
 * As such, write operations happen on the struct nconn write queue; this
 * includes the user-supplied chunk_cb when running a chunked response. Read
 * operations happen on the struct http_connection queue; this includes the
 * user processing of the requests via the user-supplied http_cb. With a few
 * specific exceptions, all http_server_*() operations must happen on the
 * struct http_connection queue.
 *
 * The exceptions are:
 *  - http_server_response_end_chunked(), called by the user-supplied chunk_cb
 *    from the write queue;
 *  - http_server_response_thaw_and_run(), called by the user from any queue;
 *  - http_server_kill_connection(), called by the user from any queue.
 *
 * Contrary to the HTTP client, struct http_connections used by the HTTP server
 * run in their own private queue.
 *
 * The "write queue" references the struct nconn write queue.
 * The "read queue" references the struct http_connection queue.
 *
 * The HTTP server supports Transfer-Encoding: chunked responses to HTTP/1.1
 * requests; the user must supply:
 *  - a chunk_cb to be called from the write queue to get the next chunk or
 *    end the reply when EOD is reached;
 *  - a free_cb that will be called whenever the associated struct
 *    http_response is freed (error or EOD);
 *  - a data pointer, passed to the chunk_cb and the free_cb.
 *
 * The chunk_cb must return:
 *  - an evbuffer filled with chunk data if data is available;
 *  - an empty evbuffer if EOD is reached (after ending the response). Ownership
 *    of the evbuffer is transferred to the server which will free it;
 *  - NULL if an error occurs, instructing the server to kill the connection.
 *    The chunk_cb must free the data pointer before killing the connection.
 *
 * The HTTP server supports freezing a response, for the cases where the
 * response cannot be emitted immediately. Freezing a response is done with a
 * call to http_server_response_freeze() in the http_cb; the user must supply:
 *  - a free_cb to be called if the response gets freed while frozen (error);
 *  - a data pointer, passed to the free_cb.
 *
 * Once ready, the response can be thawed and run with a call to
 * http_server_response_thaw_and_run(); if an error occurs, the connection must
 * be killed with a call to http_server_kill_connection().
 *
 * If an error occurs while initiating a response, be it a standard response
 * or a chunked response, the response must be freed and an attempt at sending
 * back an error code must be made using http_server_error_run(). Should that
 * fail, the http_cb must return -1 to instruct the server to kill the
 * connection.
 */

/* HTTP server */
static int
request_parse_request_line(struct http_request *req, char *line)
{
  char *method;
  char *uri;
  char *protocol;
  char *version;
  int i;

  HTTP_TRACE("*** request_parse_request_line\n");

  method = line;

  uri = strchr(method, ' ');
  if (!uri)
    goto malformed;

  *uri = '\0';
  uri++;

  protocol = strrchr(uri, ' ');
  if (!protocol)
    {
      *(uri - 1) = ' ';
      goto malformed;
    }

  *protocol = '\0';
  protocol++;

  version = strchr(protocol, '/');
  if (!version)
    {
      *(uri - 1) = ' ';
      *(protocol - 1) = ' ';
      goto malformed;
    }

  *version = '\0';
  version++;

  /* Protocol check */
  if (strcmp(protocol, "HTTP") != 0)
    goto bad_request;

  /* Version check */
  for (i = 0; i < (sizeof(p_versions) / sizeof(p_versions[0])); i++)
    {
      if (strcmp(version, p_versions[i]) == 0)
	{
	  req->proto_ver = i;
	  break;
	}
    }

  if (i == (sizeof(p_versions) / sizeof(p_versions[0])))
    {
      DPRINTF(E_LOG, L_HTTP, "Unknown HTTP version %s\n", version);

      goto bad_request;
    }

  /* Method check */
  for (i = 0; i < (sizeof(methods) / sizeof(methods[0])); i++)
    {
      if (strcmp(method, methods[i]) == 0)
	{
	  req->method = i;
	  break;
	}
    }

  if (i == (sizeof(methods) / sizeof(methods[0])))
    {
      DPRINTF(E_LOG, L_HTTP, "Unknown HTTP method %s\n", method);

      goto bad_request;
    }

  /* HTTP methods only - RTSP not supported */
  switch (req->method)
    {
      case (HTTP_GET & ~METHOD_MASK):
	req->method = HTTP_GET;
	break;

      case (HTTP_POST & ~METHOD_MASK):
	req->method = HTTP_POST;
	break;

      default:
	DPRINTF(E_LOG, L_HTTP, "Method %s not supported for HTTP\n", method);

	goto bad_request;
    }

  req->uri = strdup(uri);
  if (!req->uri)
    {
      DPRINTF(E_LOG, L_HTTP, "Out of memory for request URI!\n");

      return -1;
    }

  return 0;

 malformed:
  DPRINTF(E_LOG, L_HTTP, "Malformed request: %s\n", line);

  return -1;

 bad_request:
  *(uri - 1) = ' ';
  *(protocol - 1) = ' ';
  *(version - 1) = '/';

  DPRINTF(E_LOG, L_HTTP, "Bad request: %s\n", line);

  /* Caller closes connection */
  return -1;
}

static int
server_make_chunk(struct evbuffer *evbuf, struct evbuffer *chunk)
{
  int ret;

  HTTP_TRACE("*** server_make_chunk\n");

  ret = evbuffer_add_printf(evbuf, "%lx\r\n", (unsigned long)EVBUFFER_LENGTH(chunk));
  if (ret < 0)
    goto out_err;

  ret = evbuffer_add_buffer(evbuf, chunk);
  if (ret < 0)
    goto out_err;

  ret = evbuffer_add(evbuf, "\r\n", 2);
  if (ret < 0)
    goto out_err;

  return 0;

 out_err:
  DPRINTF(E_LOG, L_HTTP, "Out of memory for response chunk\n");

  return -1;
}

static int
server_make_end_chunk(struct evbuffer *evbuf)
{
  int ret;

  HTTP_TRACE("*** server_make_end_chunk\n");

  ret = evbuffer_add(evbuf, "0\r\n\r\n", 5);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Out of memory for response end chunk\n");

      return -1;
    }

  return 0;
}

static int
server_response_chunk_write(struct http_connection *c, struct evbuffer *chunk)
{
  struct evbuffer *evbuf;
  int ret;

  HTTP_TRACE("*** server_response_chunk_write\n");

  if (c->response->proto_ver != P_VER_1_0)
    {
      evbuf = evbuffer_new();
      if (!evbuf)
	{
	  DPRINTF(E_LOG, L_HTTP, "Out of memory for chunk buffer\n");

	  return -1;
	}

      ret = server_make_chunk(evbuf, chunk);
      if (ret < 0)
	goto fail;
    }
  else
    evbuf = chunk;

  if (c->conn)
    {
      ret = nconn_write(c->conn, evbuf);
      if (ret < 0)
	goto fail;
    }

  if (c->response->proto_ver != P_VER_1_0)
    evbuffer_free(evbuf);

  return 0;

 fail:
  evbuffer_free(evbuf);

  return -1;
}


/* Helpers */
/* Queue: server queue */
static void
server_fail(struct http_server *srv)
{
  struct nconn *n;

  HTTP_TRACE("*** server_fail\n");

  n = srv->lconn;
  srv->lconn = NULL;
  nconn_close_and_free(n);

  /* User must free server */
  srv->close_cb(srv, NULL);
}

/* Queue: server queue */
static void
server_remove_connection(struct http_server *srv, struct http_connection *c)
{
  struct http_connection *hc;
  struct http_connection *pc;

  HTTP_TRACE("*** server_remove_connection\n");

  for (pc = NULL, hc = srv->hconn_head; hc; pc = hc, hc = hc->next)
    {
      if (hc == c)
	break;
    }

  if (!hc)
    {
      DPRINTF(E_DBG, L_HTTP, "Cannot remove connection: not found in list!\n");
      return;
    }

  if (hc == srv->hconn_head)
    srv->hconn_head = c->next;

  if (hc == srv->hconn_tail)
    srv->hconn_tail = pc;

  if (pc)
    pc->next = c->next;
}

/* Queue: connection queue (aka read queue) */
static void
server_exec_request(struct http_connection *c)
{
  struct nconn *n;
  struct http_request *req;
  struct http_response *r;
  int ret;

  HTTP_TRACE("*** server_exec_request\n");

  if (!c->conn)
    return;

  /* No pending requests */
  if (!c->req_head)
    return;

  /* Chunked response in progress, or frozen request */
  if (c->response)
    return;

  /* Request is not ready */
  if (c->req_head->status != R_DONE)
    return;

  req = c->req_head;

  r = (struct http_response *)malloc(sizeof(struct http_response));
  if (!r)
    {
      DPRINTF(E_LOG, L_HTTP, "Out of memory for HTTP reponse\n");

      goto fail;
    }

  memset(r, 0, sizeof(struct http_response));

  r->proto_ver = req->proto_ver;

  r->request = req;
  req->response = r;

  c->req_head = req->next;

  if (c->req_tail == req)
    c->req_tail = NULL;

  req->next = NULL;

  ret = c->cb(c, req, r, c->data);
  if (ret < 0)
    {
      DPRINTF(E_INFO, L_HTTP, "User callback retval < 0, killing connection\n");

      goto fail;
    }

  return;

 fail:
  if (c->conn)
    {
      n = c->conn;
      c->conn = NULL;
      nconn_close_and_free(n);

      c->close_cb(c, c->data);
    }
}

/* HTTP connections callbacks - network connection */
/* Queue: connection queue (aka read queue) */
static void
server_connection_read_cb(struct nconn *n, int fd, size_t estimated, void *data)
{
  struct http_connection *c;
  struct http_request *req;
  const char *hdr;
  char *line;
  size_t len;
  int ret;

  HTTP_TRACE("*** server_connection_read_cb\n");

  c = (struct http_connection *)data;

  /* The connection has been closed by a job scheduled on the connection
   * queue that ran just before us. The next job on the queue will be the
   * read source cancel handler. The nconn is still valid for us at that
   * point, however, but there's no point anymore as this connection is
   * shutting down.
   */
  if (!c->conn)
    return;

  for (req = c->req_head; req; req = req->next)
    {
      if (req->status != R_DONE)
	break;
    }

  if (!req)
    {
      req = (struct http_request *)malloc(sizeof(struct http_request));
      if (!req)
	{
	  DPRINTF(E_LOG, L_HTTP, "Out of memory for incoming HTTP request\n");

	  goto fail;
	}

      memset(req, 0, sizeof(struct http_request));

      req->body = evbuffer_new();
      if (!req->body)
	{
	  DPRINTF(E_LOG, L_HTTP, "Out of memory for incoming HTTP request body\n");

	  free(req);
	  goto fail;
	}

      req->status = R_FIRSTLINE;

      /* Add to list */
      if (c->req_tail)
	c->req_tail->next = req;

      c->req_tail = req;

      if (!c->req_head)
	c->req_head = c->req_tail;
    }

  ret = evbuffer_read(c->readbuf, fd, -1);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "HTTP server failure while reading request\n");

      goto fail;
    }

  do
    {
      if (req->status == R_FIRSTLINE)
	{
	  line = evbuffer_readline(c->readbuf);
	  if (!line)
	    {
	      ret = 1; /* Not enough data */
	      break;
	    }

	  ret = request_parse_request_line(req, line);
	  if (ret == 0)
	    {
	      DPRINTF(E_DBG, L_HTTP, "Request: %s %s (ver %s)\n", METHOD_STR(req->method), req->uri, p_versions[req->proto_ver]);

	      req->status = R_HEADERS;
	    }
	}
      else if (req->status == R_HEADERS)
	{
	  ret = headers_read(&req->headers, c->readbuf);
	  if (ret == 1)
	    DPRINTF(E_DBG, L_HTTP, "More headers expected in request\n");
	  else if (ret == 0)
	    {
	      DPRINTF(E_DBG, L_HTTP, "End of headers in request\n");

	      req->status = R_BODY;

	      /* Check if connection must be closed after this request */
	      if (req->proto_ver == P_VER_1_0)
		req->flags |= REQ_F_CLOSE;
	      else
		{
		  hdr = keyval_get(&req->headers, "Connection");
		  if (hdr)
		    {
		      if (strcasecmp(hdr, "close") == 0)
			req->flags |= REQ_F_CLOSE;
		    }
		}

	      /* Grab request body length */
	      req->content_length = -1;
	      hdr = keyval_get(&req->headers, "Content-Length");
	      if (hdr)
		{
		  ret = safe_atoi64(hdr, &req->content_length);
		  if (ret < 0)
		    {
		      DPRINTF(E_LOG, L_HTTP, "Invalid Content-Length in request: %s\n", hdr);

		      break;
		    }
		}

	      /* Check that body length is correctly supplied */
	      if ((req->method & METHOD_HAS_BODY) && (req->content_length < 0))
		{
		  DPRINTF(E_LOG, L_HTTP, "Received HTTP request with no Content-Length for method with body\n");

		  ret = -1;
		  break;
		}
	      else if (req->content_length > 0)
		{
		  DPRINTF(E_LOG, L_HTTP, "Received HTTP request with Content-Length > 0 for method with no body\n");

		  ret = -1;
		  break;
		}
	      else
		req->content_length = 0;

	      if (req->content_length == 0)
		{
		  req->status = R_DONE;
		  ret = 1;
		  break;
		}

	      if (EVBUFFER_LENGTH(c->readbuf) == 0)
		{
		  ret = 1;
		  break;
		}
	    }
	}
      else
	{
	  len = req->content_length - EVBUFFER_LENGTH(req->body);

	  DPRINTF(E_DBG, L_HTTP, "Reading request body, content-length %" PRId64 ", %lu bytes to go\n", req->content_length, (unsigned long)len);

	  if (len >= EVBUFFER_LENGTH(c->readbuf))
	    ret = evbuffer_add_buffer(req->body, c->readbuf);
	  else
	    {
	      ret = evbuffer_add(req->body, EVBUFFER_DATA(c->readbuf), len);
	      evbuffer_drain(c->readbuf, len);
	    }

	  if (ret < 0)
	    {
	      DPRINTF(E_LOG, L_HTTP, "Out of memory for request body\n");
	      break;
	    }

	  if ((req->content_length - EVBUFFER_LENGTH(req->body)) == 0)
	    {
	      req->status = R_DONE;
	      ret = 1;
	    }

	  /* Nothing more we can do here */
	  break;
	}
    }
  while (ret == 0);

  if (ret < 0)
    goto fail;

  /* For the cases where Bad Request could be sent out, accept the request
   * and use a new R_BAD status; exec_request() can then send out the
   * Bad Request response when appropriate
   */

  /* See if the head request can be executed */
  server_exec_request(c);

  return;

 fail:
  c->conn = NULL;
  nconn_close_and_free(n);

  c->close_cb(c, c->data);
}

/* Queue: nconn queue (aka write queue) */
static void
server_connection_write_cb(struct nconn *n, void *data)
{
  struct http_connection *c;
  struct evbuffer *chunk;
  int ret;

  HTTP_TRACE("*** server_connection_write_cb\n");

  c = (struct http_connection *)data;

  /* The connection has been closed and the write source has been cancelled
   * already, however we were already scheduled to run when that happened.
   * The nconn is still valid for us at that point, however, but there's no
   * point anymore as this connection is shutting down.
   */
  if (!c->conn)
    return;

  HTTP_TRACE("***** checking frozen/chunked response\n");

  /* Frozen request or chunked response in progress */
  if (c->response)
    {
      HTTP_TRACE("***** frozen or chunked response!\n");

      /* Frozen request, do nothing */
      if (!c->response->chunk_cb)
	return;

      /* Chunked response in progress */
      HTTP_TRACE("***** chunked response!\n");

      if (c->flags & CONN_F_LAST_CHUNK)
	{
	  c->flags &= ~CONN_F_LAST_CHUNK;
	  c->response->chunk_cb = NULL;

	  goto write_done;
	}

      chunk = c->response->chunk_cb(c, c->response, c->response->data);

      /* An error occured in the user callback */
      if (!chunk)
	goto fail;

      if (EVBUFFER_LENGTH(chunk) > 0)
	{
	  ret = server_response_chunk_write(c, chunk);
	  if (ret < 0)
	    goto fail;

	  return;
	}

      /* EOD handling */

      /* Ownership of the buffer transferred by the client */
      evbuffer_free(chunk);

      switch (c->response->proto_ver)
	{
	  case P_VER_1_0:
	    /* EOD - Connection can be closed */
	    break;

	  case P_VER_1_1:
	    /* Last chunk is being sent, close after */
	    c->flags |= CONN_F_LAST_CHUNK;
	    return;
	}
    }

 write_done:
  /* All data has been written */

  /* The connection is shutting down, we cannot schedule jobs on the connection
   * queue anymore at that point as the read source cancel handler is waiting
   * for the write source (us) to terminate. The nconn would not exist anymore
   * (not an issue) and the connection_free task would be scheduled next.
   */
  if (!nconn_running(n))
    return;

  dispatch_async(c->queue, ^{
      struct nconn *conn;
      struct http_response *r;

      HTTP_TRACE("*** server_connection_write_cb BLOCK (close/handle next)\n");

      /* Ending a chunked response */
      if (c->response)
	{
	  HTTP_TRACE("***** cleaning up chunked response\n");

	  r = c->response;
	  c->response = NULL;

	  r->free_cb(r->data);
	  http_response_free(r);
	}

      if (c->flags & CONN_F_CLOSE)
	{
	  if (c->conn)
	    {
	      conn = c->conn;
	      c->conn = NULL;
	      nconn_close_and_free(conn);

	      c->close_cb(c, c->data);
	    }
	}
      else
	server_exec_request(c);
    });

  HTTP_TRACE("***** write_cb is done!\n");

  return;

 fail:
  /* Connection is already shutting down - don't do it twice */
  if (!nconn_running(n))
    return;

  dispatch_async(c->queue, ^{
      HTTP_TRACE("*** server_connection_write_cb BLOCK (close on failure)\n");

      if (c->conn)
	{
	  c->conn = NULL;
	  nconn_close_and_free(n);

	  c->close_cb(c, c->data);
	}
    });
}

/* Queue: connection queue (aka read queue) */
static void
server_connection_fail_cb(void *data)
{
  struct nconn *n;
  struct http_connection *c;

  HTTP_TRACE("*** server_connection_fail_cb\n");

  c = (struct http_connection *)data;

  n = c->conn;
  c->conn = NULL;
  nconn_close_and_free(n);

  /* This actually calls server_connection_close_cb() */
  c->close_cb(c, c->data);
}

/* HTTP connections callbacks */
/* Queue: connection queue (aka read queue) */
static void
server_connection_close_cb(struct http_connection *c, void *data)
{
  struct http_server *srv;

  HTTP_TRACE("*** server_connection_close_cb\n");

  srv = (struct http_server *)data;

  dispatch_sync(srv->queue, ^{
      HTTP_TRACE("*** server_connection_close_cb BLOCK (remove connection)\n");

      server_remove_connection(srv, c);
    });

  connection_free(c);
}

/* Queue: connection queue (aka read queue) */
static void
server_connection_free_cb(void *data)
{
  struct http_server *srv;

  HTTP_TRACE("*** server_connection_free_cb\n");

  srv = (struct http_server *)data;

  dispatch_group_leave(srv->group);
}

/* Listening socket callbacks */
/* Queue: server queue */
static void
server_read_cb(struct nconn *passive, int fd, size_t estimated, void *data)
{
  char qid[80];
  struct http_server *srv;
  struct http_connection *old_tail;
  struct http_connection *c;
  int ret;

  HTTP_TRACE("*** server_read_cb\n");

  srv = (struct http_server *)data;

  /* Server is shutting down, listen socket has been/is being closed */
  if (!srv->lconn)
    return;

  c = (struct http_connection *)malloc(sizeof(struct http_connection));
  if (!c)
    {
      DPRINTF(E_LOG, L_HTTP, "Out of memory for incoming HTTP connection\n");

      goto out_fail;
    }

  memset(c, 0, sizeof(struct http_connection));

  c->readbuf = evbuffer_new();
  if (!c->readbuf)
    {
      DPRINTF(E_LOG, L_HTTP, "Out of memory for incoming HTTP connection buffer\n");

      goto free_conn;
    }

  c->group = dispatch_group_create();
  if (!c->group)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not create incoming HTTP connection group\n");

      goto free_buf;
    }

  snprintf(qid, sizeof(qid), "org.forked-daapd.http_connection.read.%p", c);
  c->queue = dispatch_queue_create(qid, NULL);
  if (!c->queue)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not create incoming HTTP connection queue\n");

      goto rel_group;
    }

  c->conn = nconn_incoming_new(passive, c->group, c->queue);
  if (!c->conn)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not create incoming HTTP connection\n");

      goto rel_queue;
    }

  DPRINTF(E_DBG, L_HTTP, "Server %p: incoming http_connection %p with nconn %p\n", srv, c, c->conn);

  c->data = srv;
  c->close_cb = server_connection_close_cb;
  c->free_cb = server_connection_free_cb;
  c->cb = srv->cb;

  /* Enter server group, connection will exit when freed, via free_cb */
  dispatch_group_enter(srv->group);

  old_tail = srv->hconn_tail;

  if (srv->hconn_tail)
    srv->hconn_tail->next = c;

  srv->hconn_tail = c;

  if (!srv->hconn_head)
    srv->hconn_head = c;

  ret = nconn_start(c->conn, c, server_connection_read_cb, server_connection_write_cb, server_connection_fail_cb);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not start new incoming HTTP connection\n");

      if (srv->hconn_head == srv->hconn_tail)
	srv->hconn_head = NULL;

      if (old_tail)
	old_tail->next = NULL;

      srv->hconn_tail = old_tail;

      nconn_free(c->conn);
      evbuffer_free(c->readbuf);
      dispatch_release(c->group);
      dispatch_release(c->queue);

      free(c);

      dispatch_group_leave(srv->group);

      /* Do not fail the whole server because one connection failed to start */
    }

  return;

 rel_queue:
  dispatch_release(c->queue);
 rel_group:
  dispatch_release(c->group);
 free_buf:
  evbuffer_free(c->readbuf);
 free_conn:
  free(c);
 out_fail:
  server_fail(srv);
}

/* Queue: server queue */
static void
server_fail_cb(void *data)
{
  struct http_server *srv;

  HTTP_TRACE("*** server_fail_cb\n");

  srv = (struct http_server *)data;

  server_fail(srv);
}

struct http_server *
http_server_new(int ldomain, dispatch_group_t user_group, const char *address, short port, http_cb cb, http_server_close_cb close_cb)
{
  char qid[80];
  struct http_server *srv;

  HTTP_TRACE("*** http_server_new\n");

  srv = (struct http_server *)malloc(sizeof(struct http_server));
  if (!srv)
    {
      DPRINTF(E_LOG, L_HTTP, "Out of memory for HTTP server\n");

      return NULL;
    }

  memset(srv, 0, sizeof(struct http_server));

  srv->group = dispatch_group_create();
  if (!srv->group)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not create HTTP server group\n");

      goto group_fail;
    }

  snprintf(qid, sizeof(qid), "org.forked-daapd.http_server.%p", srv);
  srv->queue = dispatch_queue_create(qid, NULL);
  if (!srv->queue)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not create HTTP server queue\n");

      goto queue_fail;
    }

  srv->lconn = nconn_listen_new(ldomain, srv->group, srv->queue, address, port);
  if (!srv->lconn)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not create HTTP server socket\n");

      goto lconn_fail;
    }

  DPRINTF(E_DBG, L_HTTP, "Server %p: listen nconn %p\n", srv, srv->lconn);

  srv->cb = cb;
  srv->close_cb = close_cb;

  srv->user_group = user_group;
  dispatch_retain(srv->user_group);

  /* http_server_free() will leave the group once the server is terminated */
  dispatch_group_enter(srv->user_group);

  return srv;

 lconn_fail:
  dispatch_release(srv->queue);
 queue_fail:
  dispatch_release(srv->group);
 group_fail:
  free(srv);

  return NULL;
}

/* Queue: server queue */
static void
http_server_free_task(void *arg)
{
  struct nconn *n;
  struct http_server *srv;
  struct http_connection *hc;
  struct http_connection *c;

  HTTP_TRACE("*** http_server_free_task\n");

  srv = (struct http_server *)arg;

  dispatch_group_enter(srv->group);

  dispatch_group_notify(srv->group, srv->queue, ^{
			  dispatch_release(srv->group);
			  dispatch_release(srv->queue);

			  dispatch_group_leave(srv->user_group);
			  dispatch_release(srv->user_group);

			  free(srv);
			});

  if (srv->lconn)
    {
      n = srv->lconn;
      srv->lconn = NULL;
      nconn_close_and_free(n);
    }

  hc = srv->hconn_head;

  srv->hconn_head = NULL;
  srv->hconn_tail = NULL;

  for (c = hc; hc; c = hc)
    {
      hc = c->next;

      connection_free(c);
    }

  dispatch_group_leave(srv->group);
}

void
http_server_free(struct http_server *srv)
{
  HTTP_TRACE("*** http_server_free\n");

  if (dispatch_get_current_queue() != srv->queue)
    dispatch_sync_f(srv->queue, srv, http_server_free_task);
  else
    http_server_free_task(srv);
}

int
http_server_start(struct http_server *srv)
{
  int ret;

  HTTP_TRACE("*** http_server_start\n");

  ret = nconn_start(srv->lconn, srv, server_read_cb, NULL, server_fail_cb);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not start HTTP server socket\n");

      nconn_free(srv->lconn);
      srv->lconn = NULL;

      /* User must free server */
      return -1;
    }

  return 0;
}


/* Upon error on initiating a response, the user must free the response.
 * If the error was from run() or run_chunked(), the user can attempt to send
 * an HTTP error; if the error was from thaw_and_run(), the user must kill the
 * connection.
 */

/* Queue: connection queue (aka read queue) */
int
http_server_response_run(struct http_connection *c, struct http_response *r)
{
  char buf[16];
  struct evbuffer *evbuf;
  size_t bodylen;
  int ret;

  HTTP_TRACE("*** http_server_response_run\n");

  if (!c->conn)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: HTTP connection failed\n");

      return -1;
    }

  evbuf = evbuffer_new();
  if (!evbuf)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: out of memory for buffer\n");

      return -1;
    }

  /* Manage connection closing */
  if ((r->proto_ver == P_VER_1_0) || (r->request->flags & REQ_F_CLOSE))
    {
      c->flags |= CONN_F_CLOSE;

      if (r->proto_ver == P_VER_1_1)
	keyval_add(&r->headers, "Connection", "close");
    }

  /* Content-Length */
  keyval_remove(&r->headers, "Content-Length");

  bodylen = (r->body) ? EVBUFFER_LENGTH(r->body) : 0;
  buf[0] = '\0';
  snprintf(buf, sizeof(buf), "%ld", (long)bodylen);

  keyval_add(&r->headers, "Content-Length", buf);

  /* Server */
  keyval_add(&r->headers, "Server", USER_AGENT);

  /* Assemble response */
  ret = evbuffer_add_printf(evbuf, "HTTP/%s %d %s\r\n", p_versions[r->proto_ver], r->status_code, r->reason);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: out of memory for status line\n");

      goto buffer_fail;
    }

  ret = headers_write(r->headers.head, evbuf);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: out of memory for headers\n");

      goto buffer_fail;
    }

  if (r->body)
    {
      ret = evbuffer_add_buffer(evbuf, r->body);

      evbuffer_free(r->body);
      r->body = NULL;

      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_HTTP, "Could not run response: out of memory for body\n");

	  goto buffer_fail;
	}

      evbuffer_add(evbuf, "\r\n", 2);
    }

  ret = nconn_write(c->conn, evbuf);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: connection write error\n");

      goto buffer_fail;
    }

  evbuffer_free(evbuf);

  http_response_free(r);

  return 0;

 buffer_fail:
  evbuffer_free(evbuf);

  return -1;
}


/* Response freezing */
/* Queue: connection queue (aka read queue) */
void
http_server_response_freeze(struct http_connection *c, struct http_response *r, http_free_cb free_cb, void *data)
{
  HTTP_TRACE("*** http_server_response_freeze\n");

  r->status = R_FROZEN;

  r->data = data;
  r->free_cb = free_cb;

  c->response = r;
}

/* Queue: unknown - external user queue */
/* Synchronized with r->free_cb via the external user queue managing frozen connections */
int
http_server_response_thaw_and_run(struct http_connection *c, struct http_response *r)
{
  __block int b_ret;
  dispatch_block_t thaw_and_run = ^{
    HTTP_TRACE("*** http_server_response_thaw_and_run BLOCK\n");

    if (c->response != r)
      {
	b_ret = -1;
	return;
      }

    r->status = R_RUNNABLE;

    r->data = NULL;
    r->free_cb = NULL;

    c->response = NULL;

    b_ret = http_server_response_run(c, r);
  };

  HTTP_TRACE("*** http_server_response_thaw_and_run\n");

  if (dispatch_get_current_queue() == c->queue)
    thaw_and_run();
  else
    dispatch_sync(c->queue, thaw_and_run);

  return b_ret;
}

/* Chunked responses */
/* Queue: connection queue (aka read queue) */
int
http_server_response_run_chunked(struct http_connection *c, struct http_response *r, struct evbuffer *chunk, http_chunk_cb chunk_cb, http_free_cb free_cb, void *data)
{
  struct evbuffer *evbuf;
  int ret;

  HTTP_TRACE("*** http_server_response_run_chunked\n");

  if (!c->conn)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: HTTP connection failed\n");

      return -1;
    }

  evbuf = evbuffer_new();
  if (!evbuf)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: out of memory for buffer\n");

      return -1;
    }

  /* Manage connection closing */
  if ((r->proto_ver == P_VER_1_0) || (r->request->flags & REQ_F_CLOSE))
    {
      c->flags |= CONN_F_CLOSE;

      if (r->proto_ver == P_VER_1_1)
	keyval_add(&r->headers, "Connection", "close");
    }

  /* Server */
  keyval_add(&r->headers, "Server", USER_AGENT);

  if (r->proto_ver != P_VER_1_0)
    {
      /* Remove Content-Length header, add Transfer-Encoding: chunked */
      keyval_remove(&r->headers, "Content-Length");
      keyval_add(&r->headers, "Transfer-Encoding", "chunked");
    }

  /* Assemble response & first chunk */
  ret = evbuffer_add_printf(evbuf, "HTTP/%s %d %s\r\n", p_versions[r->proto_ver], r->status_code, r->reason);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: out of memory for status line\n");

      goto buffer_fail;
    }

  ret = headers_write(r->headers.head, evbuf);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: out of memory for headers\n");

      goto buffer_fail;
    }

  if (r->proto_ver != P_VER_1_0)
    ret = server_make_chunk(evbuf, chunk);
  else
    ret = evbuffer_add_buffer(evbuf, chunk);

  if (ret < 0)
    goto buffer_fail;

  r->data = data;
  r->chunk_cb = chunk_cb;
  r->free_cb = free_cb;

  c->response = r;

  ret = nconn_write(c->conn, evbuf);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: connection write error\n");

      c->response = NULL;

      goto buffer_fail;
    }

  evbuffer_free(evbuf);

  return 0;

 buffer_fail:
  evbuffer_free(evbuf);

  return -1;
}

/* Queue: nconn queue (aka write queue) */
/* Upon an error here, the user chunk callback is expected to return NULL */
int
http_server_response_end_chunked(struct http_connection *c, struct http_response *r)
{
  struct evbuffer *evbuf;
  int ret;

  HTTP_TRACE("*** http_server_response_end_chunked\n");

  if (!c->conn)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: HTTP connection failed\n");

      return -1;
    }

  /* Nothing to do for HTTP/1.0 */
  if (r->proto_ver == P_VER_1_0)
    return 0;

  evbuf = evbuffer_new();
  if (!evbuf)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: out of memory for buffer\n");

      return -1;
    }

  ret = server_make_end_chunk(evbuf);
  if (ret < 0)
    goto buffer_fail;

  ret = nconn_write(c->conn, evbuf);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run response: connection write error\n");

      goto buffer_fail;
    }

  return 0;

 buffer_fail:
  evbuffer_free(evbuf);

  return -1;
}

/* Queue: connection queue (aka read queue) */
/* On error, the user http_cb must return -1 to tell the server to kill
 * the connection.
 */
int
http_server_error_run(struct http_connection *c, struct http_response *r, int status_code, char *reason)
{
#define ERR_TMPL "<html><head><title>%d - %s</title></head><body><h1>%d - %s</h1>" \
    "<p>An error was encountered while processing the request.</p>" \
    "<hr></hr><p>" USER_AGENT "</p></body></html>"

  const char *hdr;
  int do_close;
  int ret;
  __block int b_ret;
  dispatch_block_t error_run = ^{
    HTTP_TRACE("*** http_server_error_run BLOCK\n");

    b_ret = http_server_response_run(c, r);
  };

  HTTP_TRACE("*** http_server_error_run\n");

  /* If the response had a Connection: close header, keep it for the error */
  hdr = http_response_get_header(r, "Connection");
  if (hdr && (strcmp(hdr, "close") == 0))
    do_close = 1;
  else
    do_close = 0;

  /* The response might be reused from a failed response_run attempt */
  keyval_clear(&r->headers);

  if (do_close)
    http_response_add_header(r, "Connection", "close");

  ret = http_response_set_status(r, status_code, reason);
  if (ret < 0)
    return -1;

  if (r->body)
    evbuffer_drain(r->body, EVBUFFER_LENGTH(r->body));
  else
    {
      r->body = evbuffer_new();
      if (!r->body)
	{
	  DPRINTF(E_LOG, L_HTTP, "Could not run error: out of memory for body buffer\n");

	  return -1;
	}
    }

  ret = evbuffer_add_printf(r->body, ERR_TMPL, status_code, reason, status_code, reason);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTP, "Could not run error: out of memory for error body\n");

      return -1;
    }

  if (dispatch_get_current_queue() == c->queue)
    error_run();
  else
    dispatch_sync(c->queue, error_run);

  if (b_ret < 0)
    http_response_free(r);

  return b_ret;

#undef ERR_TMPL
}

/* Queue: any */
/* Use only after error from thaw_and_run() */
void
http_server_kill_connection(struct http_connection *c)
{
  HTTP_TRACE("*** http_server_kill_connection\n");

  dispatch_async(c->queue, ^{
      struct nconn *n;

      HTTP_TRACE("*** http_server_kill_connection BLOCK\n");

      if (c->conn)
	{
	  n = c->conn;
	  c->conn = NULL;
	  nconn_close_and_free(n);

	  c->close_cb(c, c->data);
	}
    });
}
