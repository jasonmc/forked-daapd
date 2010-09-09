
#ifndef __HTTPD_RSP_H__
#define __HTTPD_RSP_H__

#include "http.h"

int
rsp_init(void);

void
rsp_deinit(void);

int
rsp_request(struct http_connection *c, struct http_request *req, struct http_response *r);

int
rsp_is_request(char *uri);

#endif /* !__HTTPD_RSP_H__ */
