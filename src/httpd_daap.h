
#ifndef __HTTPD_DAAP_H__
#define __HTTPD_DAAP_H__

#include "http.h"

int
daap_init(void);

void
daap_deinit(void);

int
daap_request(struct http_connection *c, struct http_request *req, struct http_response *r);

int
daap_is_request(char *uri);

#endif /* !__HTTPD_DAAP_H__ */
