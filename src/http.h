
#ifndef __HTTP_H__
#define __HTTP_H__

#include <dispatch/dispatch.h>

#include "evbuffer/evbuffer.h"
#include "misc.h"


/* Some HTTP codes */
#define HTTP_CONTINUE          100
#define HTTP_OK                200
#define HTTP_NO_CONTENT        204
#define HTTP_PARTIAL_CONTENT   206
#define HTTP_MOVE_TEMP         302
#define HTTP_BAD_REQUEST       400
#define HTTP_UNAUTHORIZED      401
#define HTTP_FORBIDDEN         403
#define HTTP_NOT_FOUND         404
#define HTTP_INTERNAL_ERROR    500
#define HTTP_UNAVAILABLE       503


enum p_version {
  P_VER_1_0,
  P_VER_1_1,
};

#define METHOD_HAS_BODY  (1 << 5)
#define HTTP_METHOD      (1 << 6)
#define RTSP_METHOD      (1 << 7)
#define METHOD_MASK      0xe0

enum request_method {
  HTTP_GET           = 0  | HTTP_METHOD,
  HTTP_POST          = 1  | HTTP_METHOD | METHOD_HAS_BODY,

  RTSP_ANNOUNCE      = 2  | RTSP_METHOD | METHOD_HAS_BODY,
  RTSP_OPTIONS       = 3  | RTSP_METHOD,
  RTSP_SETUP         = 4  | RTSP_METHOD,
  RTSP_RECORD        = 5  | RTSP_METHOD,
  RTSP_PAUSE         = 6  | RTSP_METHOD,
  RTSP_GET_PARAMETER = 7  | RTSP_METHOD | METHOD_HAS_BODY,
  RTSP_SET_PARAMETER = 8  | RTSP_METHOD | METHOD_HAS_BODY,
  RTSP_FLUSH         = 9  | RTSP_METHOD,
  RTSP_TEARDOWN      = 10 | RTSP_METHOD,
};

enum uri_decode_mode {
  URI_DECODE_NORMAL,
  URI_DECODE_PLUS_ALWAYS,
  URI_DECODE_PLUS_NEVER,
};

struct http_request;
struct http_response;

struct http_connection;

struct http_server;

typedef int (*http_cb)(struct http_connection *c, struct http_request *req, struct http_response *resp, void *data);
typedef struct evbuffer *(*http_chunk_cb)(struct http_connection *c, struct http_response *resp, void *data);
typedef void (*http_server_close_cb)(struct http_server *srv, void *data);
typedef void (*http_close_cb)(struct http_connection *c, void *data);
typedef void (*http_free_cb)(void *data);


/* Utilities */
void
http_decode_uri(char *uri, enum uri_decode_mode mode);

int
http_parse_query_string(const char *uri, struct keyval *kv);

const char *
http_method(enum request_method method);


/* HTTP connection */
int
http_connection_get_local_addr(struct http_connection *c, char *buf);

int
http_connection_get_remote_addr(struct http_connection *c, char *buf);


/* HTTP request */
void
http_request_free(struct http_request *req);

const char *
http_request_get_uri(struct http_request *req);

int
http_request_set_body(struct http_request *req, struct evbuffer *evbuf);

void
http_request_remove_header(struct http_request *req, const char *name);

int
http_request_add_header(struct http_request *req, const char *name, const char *value);

const char *
http_request_get_header(struct http_request *req, const char *name);


/* HTTP response */
void
http_response_free(struct http_response *r);

struct evbuffer *
http_response_get_body(struct http_response *r);

void
http_response_set_body(struct http_response *r, struct evbuffer *evbuf);

void
http_response_remove_header(struct http_response *r, const char *name);

int
http_response_add_header(struct http_response *r, const char *name, const char *value);

const char *
http_response_get_header(struct http_response *r, const char *name);

int
http_response_get_status(struct http_response *r, const char **reason);

int
http_response_set_status(struct http_response *r, int status_code, const char *reason);


/* HTTP client */
struct http_connection *
http_client_new(int ldomain, const char *address, short port, http_close_cb close_cb, http_free_cb free_cb, void *data);

void
http_client_free(struct http_connection *c);

struct http_request *
http_client_request_new(enum request_method method, enum p_version version, const char *uri, http_cb cb);

int
http_client_request_run(struct http_connection *c, struct http_request *req);


/* HTTP server */
struct http_server *
http_server_new(int ldomain, dispatch_group_t user_group, const char *address, short port, http_cb cb, http_server_close_cb close_cb);

void
http_server_free(struct http_server *srv);

int
http_server_start(struct http_server *srv);

int
http_server_response_run(struct http_connection *c, struct http_response *r);

void
http_server_response_freeze(struct http_connection *c, struct http_response *r, http_free_cb free_cb, void *data);

int
http_server_response_thaw_and_run(struct http_connection *c, struct http_response *r);

int
http_server_response_run_chunked(struct http_connection *c, struct http_response *r, struct evbuffer *chunk, http_chunk_cb chunk_cb, http_free_cb free_cb, void *data);

int
http_server_response_end_chunked(struct http_connection *c, struct http_response *r);

int
http_server_error_run(struct http_connection *c, struct http_response *r, int status_code, char *reason);

void
http_server_kill_connection(struct http_connection *c);

#endif /* !__HTTP_H__ */
