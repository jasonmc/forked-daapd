
#ifndef __HTTPD_H__
#define __HTTPD_H__

#include "evbuffer/evbuffer.h"
#include "http.h"


struct httpd_hdl {
  struct http_connection *c;
  struct http_request *req;
  struct http_response *r;

  struct keyval *query;
};


int
httpd_stream_file(struct http_connection *c, struct http_request *req, struct http_response *r, int id);

int
httpd_send_reply(struct http_connection *c, struct http_request *req, struct http_response *r, struct evbuffer *evbuf);

int
httpd_send_error(struct http_connection *c, struct http_response *r, int code, char *reason);

char *
httpd_fixup_uri(struct http_request *req);

int
httpd_basic_auth(struct http_connection *c, struct http_request *req, struct http_response *r, char *user, char *passwd, char *realm);

int
httpd_init(void);

void
httpd_deinit(void);

#endif /* !__HTTPD_H__ */
