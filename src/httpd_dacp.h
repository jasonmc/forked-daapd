
#ifndef __HTTPD_DACP_H__
#define __HTTPD_DACP_H__

#include <event.h>

#include "http.h"

int
dacp_init(void);

void
dacp_deinit(void);

int
dacp_request(struct http_connection *c, struct http_request *req, struct http_response *r);

int
dacp_is_request(char *uri);

#endif /* !__HTTPD_DACP_H__ */
