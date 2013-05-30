/*
 * Copyright (C) 2009-2011 Julien BLACHE <jb@jblache.org>
 * Copyright (C) 2010 Kai Elwert <elwertk@googlemail.com>
 *
 * Adapted from mt-daapd:
 * Copyright (C) 2003-2007 Ron Pedde <ron@pedde.com>
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include <uninorm.h>

#include <dispatch/dispatch.h>

#include <tre/tre.h>
#include <avl.h>

#include <gcrypt.h>

#include "evbuffer/evbuffer.h"
#include "logger.h"
#include "db.h"
#include "conffile.h"
#include "misc.h"
#include "http.h"
#include "httpd.h"
#include "transcode.h"
#include "artwork.h"
#include "httpd_daap.h"
#include "daap_query.h"
#include "dmap_common.h"


/* Session timeout in seconds */
#define DAAP_SESSION_TIMEOUT 1800
/* Update requests refresh interval in seconds */
#define DAAP_UPDATE_REFRESH  300


struct uri_map {
  regex_t preg;
  char *regexp;
  int (*handler)(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri);
};

struct daap_session {
  int id;

  dispatch_source_t timeout;
};

struct daap_update_request {
  struct http_connection *c;
  struct http_request *req;
  struct http_response *r;

  /* Refresh tiemout */
  dispatch_source_t timeout;

  struct daap_update_request *next;
};

struct sort_ctx {
  struct evbuffer *headerlist;
  int16_t mshc;
  uint32_t mshi;
  uint32_t mshn;
  uint32_t misc_mshn;
};


/* Default meta tags if not provided in the query */
static char *default_meta_plsongs = "dmap.itemkind,dmap.itemid,dmap.itemname,dmap.containeritemid,dmap.parentcontainerid";
static char *default_meta_pl = "dmap.itemid,dmap.itemname,dmap.persistentid,com.apple.itunes.smart-playlist";
static char *default_meta_group = "dmap.itemname,dmap.persistentid,daap.songalbumartist";

/* DAAP session tracking */
static dispatch_queue_t sessions_sq;
static avl_tree_t *daap_sessions;

/* Update requests */
static int current_rev;
static dispatch_queue_t updates_sq;
static struct daap_update_request *update_requests;


/* Session handling */
static int
daap_session_compare(const void *aa, const void *bb)
{
  struct daap_session *a = (struct daap_session *)aa;
  struct daap_session *b = (struct daap_session *)bb;

  if (a->id < b->id)
    return -1;

  if (a->id > b->id)
    return 1;

  return 0;
}

/* Queue: sessions_sq */
static void
daap_session_free(void *item)
{
  struct daap_session *s;

  s = (struct daap_session *)item;

  dispatch_source_cancel(s->timeout);
  dispatch_release(s->timeout);
  free(s);
}

/* Queue: sessions_sq or HTTP read queue */
static void
daap_session_kill(struct daap_session *s)
{
  if (dispatch_get_current_queue() == sessions_sq)
    avl_delete(daap_sessions, s);
  else
    dispatch_sync(sessions_sq, ^{
	avl_delete(daap_sessions, s);
      });
}

/* Queue: sessions_sq */
static void
daap_session_timeout_cb(void *arg)
{
  struct daap_session *s;

  s = (struct daap_session *)arg;

  DPRINTF(E_DBG, L_DAAP, "Session %d timed out\n", s->id);

  daap_session_kill(s);
}

/* Queue: HTTP read queue */
static struct daap_session *
daap_session_register(void)
{
  struct daap_session *s;
  __block int b_ret;

  s = (struct daap_session *)malloc(sizeof(struct daap_session));
  if (!s)
    {
      DPRINTF(E_LOG, L_DAAP, "Out of memory for DAAP session\n");

      return NULL;
    }

  memset(s, 0, sizeof(struct daap_session));

  s->timeout = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, sessions_sq);
  if (!s->timeout)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not create dispatch source for session timeout\n");

      free(s);
      return NULL;
    }

  dispatch_set_context(s->timeout, s);
  dispatch_source_set_event_handler_f(s->timeout, daap_session_timeout_cb);

  dispatch_source_set_timer(s->timeout,
			    dispatch_time(DISPATCH_TIME_NOW, DAAP_SESSION_TIMEOUT * NSEC_PER_SEC),
			    DISPATCH_TIME_FOREVER /* one-shot */, 30 * NSEC_PER_SEC);

  dispatch_sync(sessions_sq, ^{
      avl_node_t *node;
      struct daap_session existing;

      /* Find a random session id that is not in use. */
      do
        {
	  gcry_create_nonce((unsigned char *)&existing.id, sizeof(existing.id));
	  if (existing.id < 0)
            existing.id += INT_MAX + 1; /* Convert negative two's complement to positive. */
        }
      while (avl_search(daap_sessions, &existing) != NULL);

      s->id = existing.id;
      node = avl_insert(daap_sessions, s);
      if (!node)
	{
	  DPRINTF(E_LOG, L_DAAP, "Could not register DAAP session: %s\n", strerror(errno));

	  b_ret = -1;
	  return;
	}

      dispatch_resume(s->timeout);

      b_ret = 0;
    });

  if (b_ret < 0)
    {
      free(s);
      return NULL;
    }

  return s;
}

/* Queue: HTTP read queue */
int
daap_session_find(struct httpd_hdl *h, struct daap_session **s)
{
  const char *param;
  int id;
  int ret;

  param = keyval_get(h->query, "session-id");
  if (!param)
    {
      DPRINTF(E_WARN, L_DAAP, "No session-id specified in request\n");
      goto invalid;
    }

  ret = safe_atoi32(param, &id);
  if (ret < 0)
    goto invalid;

  dispatch_sync(sessions_sq, ^{
      struct daap_session needle;
      avl_node_t *node;

      needle.id = id;

      node = avl_search(daap_sessions, &needle);
      if (!node)
	{
	  DPRINTF(E_WARN, L_DAAP, "DAAP session id %d not found\n", needle.id);

	  *s = NULL;
	  return;
	}

      *s = (struct daap_session *)node->item;

      dispatch_source_set_timer((*s)->timeout,
				dispatch_time(DISPATCH_TIME_NOW, DAAP_SESSION_TIMEOUT * NSEC_PER_SEC),
				DISPATCH_TIME_FOREVER /* one-shot */, 30 * NSEC_PER_SEC);
    });

  if (!*s)
    goto invalid;

  return 0;

 invalid:
  return http_server_error_run(h->c, h->r, HTTP_FORBIDDEN, "Forbidden");
}


/* Update requests helpers */
/* Queue: updates_sq */
static void
update_remove(struct daap_update_request *ur)
{
  struct daap_update_request *p;

  if (ur == update_requests)
    update_requests = ur->next;
  else
    {
      for (p = update_requests; p && (p->next != ur); p = p->next)
	;

      if (!p)
	{
	  DPRINTF(E_LOG, L_DAAP, "WARNING: struct daap_update_request not found in list; BUG!\n");
	  return;
	}

      p->next = ur->next;
    }
}

static void
update_free(struct daap_update_request *ur)
{
  dispatch_source_cancel(ur->timeout);
  dispatch_release(ur->timeout);

  free(ur);
}

/* Queue: updates_sq */
static void
update_refresh_cb(void *arg)
{
  struct daap_update_request *ur;
  struct evbuffer *evbuf;
  int ret;

  ur = (struct daap_update_request *)arg;

  evbuf = evbuffer_new();
  if (!evbuf)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not allocate evbuffer for DAAP update data\n");

      return;
    }

  ret = evbuffer_expand(evbuf, 32);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DAAP update data\n");

      return;
    }

  /* Send back current revision */
  dmap_add_container(evbuf, "mupd", 24);
  dmap_add_int(evbuf, "mstt", 200);         /* 12 */
  dmap_add_int(evbuf, "musr", current_rev); /* 12 */

  ret = http_response_set_status(ur->r, HTTP_OK, "OK");
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not set response status for DAAP update\n");

      evbuffer_free(evbuf);
      return;
    }

  http_response_set_body(ur->r, evbuf);

  ret = http_server_response_thaw_and_run(ur->c, ur->r);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not thaw and run response to DAAP update request\n");

      http_server_kill_connection(ur->c);
    }

  update_remove(ur);
  update_free(ur);
}

/* Queue: updates_sq */
static void
update_free_cb_task(void *arg)
{
  struct daap_update_request *ur;

  ur = (struct daap_update_request *)arg;

  update_remove(ur);
  update_free(ur);
}

static void
update_free_cb(void *data)
{
  DPRINTF(E_DBG, L_DAAP, "Update request: connection closed\n");

  dispatch_sync_f(updates_sq, data, update_free_cb_task);
}


/* DAAP sort headers helpers */
static struct sort_ctx *
daap_sort_context_new(void)
{
  struct sort_ctx *ctx;
  int ret;

  ctx = (struct sort_ctx *)malloc(sizeof(struct sort_ctx));
  if (!ctx)
    {
      DPRINTF(E_LOG, L_DAAP, "Out of memory for sorting context\n");

      return NULL;
    }

  memset(ctx, 0, sizeof(struct sort_ctx));

  ctx->headerlist = evbuffer_new();
  if (!ctx->headerlist)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not create evbuffer for DAAP sort headers list\n");

      free(ctx);
      return NULL;
    }

  ret = evbuffer_expand(ctx->headerlist, 512);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DAAP sort headers list\n");

      evbuffer_free(ctx->headerlist);
      free(ctx);
      return NULL;
    }

  ctx->mshc = -1;

  return ctx;
}

static void
daap_sort_context_free(struct sort_ctx *ctx)
{
  evbuffer_free(ctx->headerlist);
  free(ctx);
}

static int
daap_sort_build(struct sort_ctx *ctx, char *str)
{
  uint8_t *ret;
  size_t len;
  char fl;

  len = strlen(str);
  ret = u8_normalize(UNINORM_NFD, (uint8_t *)str, len, NULL, &len);
  if (!ret)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not normalize string for sort header\n");

      return -1;
    }

  fl = ret[0];
  free(ret);

  if (isascii(fl) && isalpha(fl))
    {
      fl = toupper(fl);

      /* Init */
      if (ctx->mshc == -1)
	ctx->mshc = fl;

      if (fl == ctx->mshc)
	ctx->mshn++;
      else
        {
	  dmap_add_container(ctx->headerlist, "mlit", 34);
	  dmap_add_short(ctx->headerlist, "mshc", ctx->mshc); /* 10 */
	  dmap_add_int(ctx->headerlist, "mshi", ctx->mshi);   /* 12 */
	  dmap_add_int(ctx->headerlist, "mshn", ctx->mshn);   /* 12 */

	  DPRINTF(E_DBG, L_DAAP, "Added sort header: mshc = %c, mshi = %u, mshn = %u fl %c\n", ctx->mshc, ctx->mshi, ctx->mshn, fl);

	  ctx->mshi = ctx->mshi + ctx->mshn;
	  ctx->mshn = 1;
	  ctx->mshc = fl;
	}
    }
  else
    {
      /* Non-ASCII, goes to misc category */
      ctx->misc_mshn++;
    }

  return 0;
}

static int
daap_sort_finalize(struct sort_ctx *ctx, struct evbuffer *evbuf)
{
  int ret;

  /* Add current entry, if any */
  if (ctx->mshc != -1)
    {
      dmap_add_container(ctx->headerlist, "mlit", 34);
      dmap_add_short(ctx->headerlist, "mshc", ctx->mshc); /* 10 */
      dmap_add_int(ctx->headerlist, "mshi", ctx->mshi);   /* 12 */
      dmap_add_int(ctx->headerlist, "mshn", ctx->mshn);   /* 12 */

      ctx->mshi = ctx->mshi + ctx->mshn;

      DPRINTF(E_DBG, L_DAAP, "Added sort header: mshc = %c, mshi = %u, mshn = %u (final)\n", ctx->mshc, ctx->mshi, ctx->mshn);
    }

  /* Add misc category */
  dmap_add_container(ctx->headerlist, "mlit", 34);
  dmap_add_short(ctx->headerlist, "mshc", '0');          /* 10 */
  dmap_add_int(ctx->headerlist, "mshi", ctx->mshi);      /* 12 */
  dmap_add_int(ctx->headerlist, "mshn", ctx->misc_mshn); /* 12 */

  dmap_add_container(evbuf, "mshl", EVBUFFER_LENGTH(ctx->headerlist));
  ret = evbuffer_add_buffer(evbuf, ctx->headerlist);
  if (ret < 0)
    return -1;

  return 0;
}


static void
get_query_params(struct keyval *query, int *sort_headers, struct query_params *qp)
{
  const char *param;
  char *ptr;
  int low;
  int high;
  int ret;

  low = 0;
  high = -1; /* No limit */

  param = keyval_get(query, "index");
  if (param)
    {
      if (param[0] == '-') /* -n, last n entries */
	DPRINTF(E_LOG, L_DAAP, "Unsupported index range: %s\n", param);
      else
	{
	  ret = safe_atoi32(param, &low);
	  if (ret < 0)
	    DPRINTF(E_LOG, L_DAAP, "Could not parse index range: %s\n", param);
	  else
	    {
	      ptr = strchr(param, '-');
	      if (!ptr) /* single item */
		high = low;
	      else
		{
		  ptr++;
		  if (*ptr != '\0') /* low-high */
		    {
		      ret = safe_atoi32(ptr, &high);
		      if (ret < 0)
			  DPRINTF(E_LOG, L_DAAP, "Could not parse high index in range: %s\n", param);
		    }
		}
	    }
	}

      DPRINTF(E_DBG, L_DAAP, "Index range %s: low %d, high %d (offset %d, limit %d)\n", param, low, high, qp->offset, qp->limit);
    }

  if (high < low)
    high = -1; /* No limit */

  qp->offset = low;
  if (high < 0)
    qp->limit = -1; /* No limit */
  else
    qp->limit = (high - low) + 1;

  qp->idx_type = I_SUB;

  qp->sort = S_NONE;
  param = keyval_get(query, "sort");
  if (param)
    {
      if (strcmp(param, "name") == 0)
	qp->sort = S_NAME;
      else if (strcmp(param, "album") == 0)
	qp->sort = S_ALBUM;
      else if (strcmp(param, "artist") == 0)
	qp->sort = S_ARTIST;
      else
	DPRINTF(E_DBG, L_DAAP, "Unknown sort param: %s\n", param);

      if (qp->sort != S_NONE)
	DPRINTF(E_DBG, L_DAAP, "Sorting songlist by %s\n", param);
    }

  if (sort_headers)
    {
      *sort_headers = 0;
      param = keyval_get(query, "include-sort-headers");
      if (param)
	{
	  if (strcmp(param, "1") == 0)
	    {
	      *sort_headers = 1;
	      DPRINTF(E_DBG, L_DAAP, "Sort headers requested\n");
	    }
	  else
	    DPRINTF(E_DBG, L_DAAP, "Unknown include-sort-headers param: %s\n", param);
	}
    }

  param = keyval_get(query, "query");
  if (!param)
    param = keyval_get(query, "filter");

  if (param)
    {
      DPRINTF(E_DBG, L_DAAP, "DAAP browse query filter: %s\n", param);

      qp->filter = daap_query_parse_sql(param);
      if (!qp->filter)
	DPRINTF(E_LOG, L_DAAP, "Ignoring improper DAAP query\n");
    }
}

static int
parse_meta(struct httpd_hdl *h, char *tag, const char *param, const struct dmap_field ***out_meta, int *out_nmeta)
{
  const struct dmap_field **meta;
  char *ptr;
  char *field;
  char *metastr;

  int nmeta;
  int i;

  *out_nmeta = -1;

  metastr = strdup(param);
  if (!metastr)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not duplicate meta parameter; out of memory\n");

      return dmap_send_error(h, tag, "Out of memory");
    }

  nmeta = 1;
  ptr = metastr;
  while ((ptr = strchr(ptr + 1, ',')))
    nmeta++;

  DPRINTF(E_DBG, L_DAAP, "Asking for %d meta tags\n", nmeta);

  meta = (const struct dmap_field **)malloc(nmeta * sizeof(const struct dmap_field *));
  if (!meta)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not allocate meta array; out of memory\n");

      free(metastr);

      return dmap_send_error(h, tag, "Out of memory");
    }
  memset(meta, 0, nmeta * sizeof(struct dmap_field *));

  field = strtok_r(metastr, ",", &ptr);
  for (i = 0; i < nmeta; i++)
    {
      meta[i] = dmap_find_field(field, strlen(field));

      if (!meta[i])
	{
	  DPRINTF(E_WARN, L_DAAP, "Could not find requested meta field '%s'\n", field);

	  i--;
	  nmeta--;
	}

      field = strtok_r(NULL, ",", &ptr);
      if (!field)
	break;
    }

  DPRINTF(E_DBG, L_DAAP, "Found %d meta tags\n", nmeta);

  *out_meta = meta;
  *out_nmeta = nmeta;

  free(metastr);

  return 0;
}


static int
daap_reply_server_info(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  cfg_t *lib;
  char *name;
  char *passwd;
  const char *clientver;
  int mpro;
  int apro;
  int len;
  int ret;

  lib = cfg_getsec(cfg, "library");
  passwd = cfg_getstr(lib, "password");
  name = cfg_getstr(lib, "name");

  len = 157 + strlen(name);

  ret = evbuffer_expand(evbuf, len);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DAAP server-info reply\n");

      evbuffer_free(evbuf);
      return dmap_send_error(h, "msrv", "Out of memory");
    }

  mpro = 2 << 16;
  apro = 3 << 16;

  clientver = http_request_get_header(h->req, "Client-DAAP-Version");
  if (clientver)
    {
      if (strcmp(clientver, "1.0") == 0)
	{
	  mpro = 1 << 16;
	  apro = 1 << 16;
	}
      else if (strcmp(clientver, "2.0") == 0)
	{
	  mpro = 1 << 16;
	  apro = 2 << 16;
	}
    }

  dmap_add_container(evbuf, "msrv", len - 8);
  dmap_add_int(evbuf, "mstt", 200);  /* 12 */
  dmap_add_int(evbuf, "mpro", mpro); /* 12 */
  dmap_add_int(evbuf, "apro", apro); /* 12 */
  dmap_add_string(evbuf, "minm", name); /* 8 + strlen(name) */

  dmap_add_int(evbuf, "mstm", DAAP_SESSION_TIMEOUT); /* 12 */
  dmap_add_char(evbuf, "msal", 1);   /* 9 */

  dmap_add_char(evbuf, "mslr", 1);   /* 9 */
  dmap_add_char(evbuf, "msau", (passwd) ? 2 : 0); /* 9 */
  dmap_add_char(evbuf, "msex", 1);   /* 9 */
  dmap_add_char(evbuf, "msix", 1);   /* 9 */
  dmap_add_char(evbuf, "msbr", 1);   /* 9 */
  dmap_add_char(evbuf, "msqy", 1);   /* 9 */

  dmap_add_char(evbuf, "mspi", 1);   /* 9 */
  dmap_add_int(evbuf, "msdc", 1);    /* 12 */

  /* Advertise updates support even though we don't send updates */
  dmap_add_char(evbuf, "msup", 1);   /* 9 */

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    {
      evbuffer_free(evbuf);
      return dmap_send_error(h, "msrv", "Server Error");
    }

  return httpd_send_reply(h->c, h->req, h->r, evbuf);
}

static int
daap_reply_content_codes(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  const struct dmap_field *dmap_fields;
  int nfields;
  int i;
  int len;
  int ret;

  dmap_fields = dmap_get_fields_table(&nfields);

  len = 12;
  for (i = 0; i < nfields; i++)
    len += 8 + 12 + 10 + 8 + strlen(dmap_fields[i].desc);

  ret = evbuffer_expand(evbuf, len + 8);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DAAP content-codes reply\n");

      evbuffer_free(evbuf);
      return dmap_send_error(h, "mccr", "Out of memory");
    } 

  dmap_add_container(evbuf, "mccr", len);
  dmap_add_int(evbuf, "mstt", 200);

  for (i = 0; i < nfields; i++)
    {
      len = 12 + 10 + 8 + strlen(dmap_fields[i].desc);

      dmap_add_container(evbuf, "mdcl", len);
      dmap_add_string(evbuf, "mcnm", dmap_fields[i].tag);  /* 12 */
      dmap_add_string(evbuf, "mcna", dmap_fields[i].desc); /* 8 + strlen(desc) */
      dmap_add_short(evbuf, "mcty", dmap_fields[i].type);  /* 10 */
    }

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    {
      evbuffer_free(evbuf);
      return dmap_send_error(h, "mccr", "Server Error");
    }

  return httpd_send_reply(h->c, h->req, h->r, evbuf);
}

static int
daap_reply_login(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct pairing_info pi;
  struct daap_session *s;
  const char *ua;
  const char *guid;
  int ret;

  ret = evbuffer_expand(evbuf, 32);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DAAP login reply\n");

      evbuffer_free(evbuf);
      return dmap_send_error(h, "mlog", "Out of memory");
    }

  ua = http_request_get_header(h->req, "User-Agent");
  if (!ua)
    {
      DPRINTF(E_LOG, L_DAAP, "No User-Agent header, rejecting login request\n");

      evbuffer_free(evbuf);
      return http_server_error_run(h->c, h->r, HTTP_FORBIDDEN, "Forbidden");
    }

  if (strncmp(ua, "Remote", strlen("Remote")) == 0)
    {
      guid = keyval_get(h->query, "pairing-guid");
      if (!guid)
	{
	  DPRINTF(E_LOG, L_DAAP, "Login attempt with U-A: Remote and no pairing-guid\n");

	  evbuffer_free(evbuf);
	  return http_server_error_run(h->c, h->r, HTTP_FORBIDDEN, "Forbidden");
	}

      memset(&pi, 0, sizeof(struct pairing_info));
      pi.guid = strdup(guid + 2); /* Skip leading 0X */

      ret = db_pairing_fetch_byguid(&pi);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DAAP, "Login attempt with invalid pairing-guid\n");

	  free_pi(&pi, 1);

	  evbuffer_free(evbuf);
	  return http_server_error_run(h->c, h->r, HTTP_FORBIDDEN, "Forbidden");
	}

      DPRINTF(E_INFO, L_DAAP, "Remote '%s' logging in with GUID %s\n", pi.name, pi.guid);
      free_pi(&pi, 1);
    }

  s = daap_session_register();
  if (!s)
    {
      evbuffer_free(evbuf);
      return dmap_send_error(h, "mlog", "Could not start session");
    }

  dmap_add_container(evbuf, "mlog", 24);
  dmap_add_int(evbuf, "mstt", 200);        /* 12 */
  dmap_add_int(evbuf, "mlid", s->id); /* 12 */

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    {
      evbuffer_free(evbuf);
      return dmap_send_error(h, "mlog", "Server Error");
    }

  return httpd_send_reply(h->c, h->req, h->r, evbuf);
}

static int
daap_reply_logout(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  int ret;

  evbuffer_free(evbuf);

  ret = daap_session_find(h, &s);
  if (!s)
    return ret;

  daap_session_kill(s);

  ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "Logout Successful");
  if (ret < 0)
    goto out_error;

  ret = http_server_response_run(h->c, h->r);
  if (ret < 0)
    goto out_error;

  return 0;

 out_error:
  return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");
}

static int
daap_reply_update(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  struct daap_update_request *ur;
  const char *param;
  int reqd_rev;
  int ret;

  ret = daap_session_find(h, &s);
  if (!s)
    {
      evbuffer_free(evbuf);
      return ret;
    }

  param = keyval_get(h->query, "revision-number");
  if (!param)
    {
      DPRINTF(E_LOG, L_DAAP, "Missing revision-number in update request\n");

      evbuffer_free(evbuf);
      return dmap_send_error(h, "mupd", "Invalid request");
    }

  ret = safe_atoi32(param, &reqd_rev);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Parameter revision-number not an integer\n");

      evbuffer_free(evbuf);
      return dmap_send_error(h, "mupd", "Invalid request");
    }

  if (reqd_rev == 1) /* Or revision is not valid */
    {
      ret = evbuffer_expand(evbuf, 32);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DAAP update reply\n");

	  evbuffer_free(evbuf);
	  return dmap_send_error(h, "mupd", "Out of memory");
	}

      /* Send back current revision */
      dmap_add_container(evbuf, "mupd", 24);
      dmap_add_int(evbuf, "mstt", 200);         /* 12 */
      dmap_add_int(evbuf, "musr", current_rev); /* 12 */

      ret = http_response_set_status(h->r, HTTP_OK, "OK");
      if (ret < 0)
	{
	  evbuffer_free(evbuf);
	  return dmap_send_error(h, "mupd", "Internal error");
	}

      return httpd_send_reply(h->c, h->req, h->r, evbuf);
    }

  evbuffer_free(evbuf);

  ur = (struct daap_update_request *)malloc(sizeof(struct daap_update_request));
  if (!ur)
    {
      DPRINTF(E_LOG, L_DAAP, "Out of memory for update request\n");

      return dmap_send_error(h, "mupd", "Out of memory");
    }
  memset(ur, 0, sizeof(struct daap_update_request));

  ur->timeout = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, updates_sq);
  if (!ur->timeout)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not create dispatch source for update timeout\n");

      free(ur);
      return dmap_send_error(h, "mupd", "Could not create timer");
    }

  dispatch_set_context(ur->timeout, ur);
  dispatch_source_set_event_handler_f(ur->timeout, update_refresh_cb);

  dispatch_source_set_timer(ur->timeout,
			    dispatch_time(DISPATCH_TIME_NOW, DAAP_UPDATE_REFRESH * NSEC_PER_SEC),
			    DISPATCH_TIME_FOREVER /* one-shot */, 30 * NSEC_PER_SEC);

  /* Freeze the request */
  http_server_response_freeze(h->c, h->r, update_free_cb, ur);

  /* NOTE: we may need to keep reqd_rev in there too */
  ur->c = h->c;
  ur->req = h->req;
  ur->r = h->r;

  dispatch_sync(updates_sq, ^{
      ur->next = update_requests;
      update_requests = ur;

      dispatch_resume(ur->timeout);
    });

  return 0;
}

static int
daap_reply_activity(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  int ret;

  evbuffer_free(evbuf);

  /* That's so nice, thanks for letting us know */
  ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "No Content");
  if (ret < 0)
    return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");

  ret = http_server_response_run(h->c, h->r);
  if (ret < 0)
    return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");

  return 0;
}

static int
daap_reply_dblist(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  cfg_t *lib;
  char *name;
  int namelen;
  int count;
  int ret;

  ret = daap_session_find(h, &s);
  if (!s)
    {
      evbuffer_free(evbuf);
      return ret;
    }

  lib = cfg_getsec(cfg, "library");
  name = cfg_getstr(lib, "name");
  namelen = strlen(name);

  ret = evbuffer_expand(evbuf, 129 + namelen);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DAAP dblist reply\n");

      evbuffer_free(evbuf);
      return dmap_send_error(h, "avdb", "Out of memory");
    }

  dmap_add_container(evbuf, "avdb", 121 + namelen);
  dmap_add_int(evbuf, "mstt", 200);     /* 12 */
  dmap_add_char(evbuf, "muty", 0);      /* 9 */
  dmap_add_int(evbuf, "mtco", 1);       /* 12 */
  dmap_add_int(evbuf, "mrco", 1);       /* 12 */
  dmap_add_container(evbuf, "mlcl", 68 + namelen);
  dmap_add_container(evbuf, "mlit", 60 + namelen);
  dmap_add_int(evbuf, "miid", 1);       /* 12 */
  dmap_add_long(evbuf, "mper", 1);      /* 16 */
  dmap_add_string(evbuf, "minm", name); /* 8 + namelen */

  count = db_files_get_count();
  dmap_add_int(evbuf, "mimc", count); /* 12 */

  count = db_pl_get_count();
  dmap_add_int(evbuf, "mctc", count); /* 12 */

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    {
      evbuffer_free(evbuf);
      return dmap_send_error(h, "aply", "Server Error");
    }

  return httpd_send_reply(h->c, h->req, h->r, evbuf);
}

static int
daap_reply_songlist_generic(struct httpd_hdl *h, struct evbuffer *evbuf, int playlist)
{
  struct query_params qp;
  struct db_media_file_info dbmfi;
  struct evbuffer *song;
  struct evbuffer *songlist;
  const struct dmap_field **meta;
  struct sort_ctx *sctx;
  const char *param;
  char *tag;
  int nmeta;
  int sort_headers;
  int nsongs;
  int transcode;
  int ret;

  DPRINTF(E_DBG, L_DAAP, "Fetching song list for playlist %d\n", playlist);

  if (playlist != -1)
    tag = "apso"; /* Songs in playlist */
  else
    tag = "adbs"; /* Songs in database */

  ret = evbuffer_expand(evbuf, 61);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DAAP song list reply\n");

      ret = dmap_send_error(h, tag, "Out of memory");
      goto out_evbuf_free;
    }

  songlist = evbuffer_new();
  if (!songlist)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not create evbuffer for DMAP song list\n");

      ret = dmap_send_error(h, tag, "Out of memory");
      goto out_evbuf_free;
    }

  /* Start with a big enough evbuffer - it'll expand as needed */
  ret = evbuffer_expand(songlist, 4096);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DMAP song list\n");

      ret = dmap_send_error(h, tag, "Out of memory");
      goto out_list_free;
    }

  song = evbuffer_new();
  if (!song)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not create evbuffer for DMAP song block\n");

      ret = dmap_send_error(h, tag, "Out of memory");
      goto out_list_free;
    }

  /* The buffer will expand if needed */
  ret = evbuffer_expand(song, 512);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DMAP song block\n");

      ret = dmap_send_error(h, tag, "Out of memory");
      goto out_song_free;
    }

  param = keyval_get(h->query, "meta");
  if (!param)
    {
      DPRINTF(E_DBG, L_DAAP, "No meta parameter in query, using default\n");

      if (playlist != -1)
	param = default_meta_plsongs;
    }

  if (param)
    {
      ret = parse_meta(h, tag, param, &meta, &nmeta);
      if (nmeta < 0)
	{
	  DPRINTF(E_LOG, L_DAAP, "Failed to parse meta parameter in DAAP query\n");

	  /* retval from parse_meta() */
	  goto out_song_free;
	}
    }
  else
    {
      meta = NULL;
      nmeta = 0;
    }

  memset(&qp, 0, sizeof(struct query_params));
  get_query_params(h->query, &sort_headers, &qp);

  sctx = NULL;
  if (sort_headers)
    {
      sctx = daap_sort_context_new();
      if (!sctx)
	{
	  DPRINTF(E_LOG, L_DAAP, "Could not create sort context\n");

	  ret = dmap_send_error(h, tag, "Out of memory");
	  goto out_query_free;
	}
    }

  if (playlist != -1)
    {
      qp.type = Q_PLITEMS;
      qp.id = playlist;
    }
  else
    qp.type = Q_ITEMS;

  ret = db_query_start(&qp);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not start query\n");

      if (sort_headers)
	daap_sort_context_free(sctx);

      ret = dmap_send_error(h, tag, "Could not start query");
      goto out_query_free;
    }

  nsongs = 0;
  while (((ret = db_query_fetch_file(&qp, &dbmfi)) == 0) && (dbmfi.id))
    {
      nsongs++;

      transcode = transcode_needed(h->req, dbmfi.codectype);

      ret = dmap_encode_file_metadata(songlist, song, &dbmfi, meta, nmeta, 1, transcode);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DAAP, "Failed to encode song metadata\n");

	  ret = -100;
	  break;
	}

      if (sort_headers)
	{
	  ret = daap_sort_build(sctx, dbmfi.title_sort);
	  if (ret < 0)
	    {
	      DPRINTF(E_LOG, L_DAAP, "Could not add sort header to DAAP song list reply\n");

	      ret = -100;
	      break;
	    }
   	}

      DPRINTF(E_DBG, L_DAAP, "Done with song\n");
    }

  DPRINTF(E_DBG, L_DAAP, "Done with song list, %d songs\n", nsongs);

  if (nmeta > 0)
    free(meta);

  evbuffer_free(song);

  if (qp.filter)
    free(qp.filter);

  if (ret < 0)
    {
      db_query_end(&qp);

      if (sort_headers)
	daap_sort_context_free(sctx);

      if (ret == -100)
	ret = dmap_send_error(h , tag, "Out of memory");
      else
	{
	  DPRINTF(E_LOG, L_DAAP, "Error fetching results\n");
	  ret = dmap_send_error(h, tag, "Error fetching query results");
	}

      goto out_list_free;
    }

  /* Add header to evbuf, add songlist to evbuf */
  if (sort_headers)
    dmap_add_container(evbuf, tag, EVBUFFER_LENGTH(songlist) + EVBUFFER_LENGTH(sctx->headerlist) + 53);
  else
    dmap_add_container(evbuf, tag, EVBUFFER_LENGTH(songlist) + 53);
  dmap_add_int(evbuf, "mstt", 200);    /* 12 */
  dmap_add_char(evbuf, "muty", 0);     /* 9 */
  dmap_add_int(evbuf, "mtco", qp.results); /* 12 */
  dmap_add_int(evbuf, "mrco", nsongs); /* 12 */
  dmap_add_container(evbuf, "mlcl", EVBUFFER_LENGTH(songlist));

  db_query_end(&qp);

  ret = evbuffer_add_buffer(evbuf, songlist);
  evbuffer_free(songlist);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not add song list to DAAP song list reply\n");

      if (sort_headers)
	daap_sort_context_free(sctx);

      ret = dmap_send_error(h, tag, "Out of memory");
      goto out_evbuf_free;
    }

  if (sort_headers)
    {
      ret = daap_sort_finalize(sctx, evbuf);
      daap_sort_context_free(sctx);

      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DAAP, "Could not add sort headers to DAAP song list reply\n");

	  ret = dmap_send_error(h, tag, "Out of memory");
	  goto out_evbuf_free;
	}
    }

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    {
      ret = dmap_send_error(h, "aply", "Server Error");
      goto out_evbuf_free;
    }

  return httpd_send_reply(h->c, h->req, h->r, evbuf);

 out_query_free:
  if (nmeta > 0)
    free(meta);

  if (qp.filter)
    free(qp.filter);

 out_song_free:
  evbuffer_free(song);

 out_list_free:
  evbuffer_free(songlist);

 out_evbuf_free:
  evbuffer_free(evbuf);

  return ret;
}

static int
daap_reply_dbsonglist(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  int ret;

  ret = daap_session_find(h, &s);
  if (!s)
    {
      evbuffer_free(evbuf);
      return ret;
    }

  return daap_reply_songlist_generic(h, evbuf, -1);
}

static int
daap_reply_plsonglist(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  int playlist;
  int ret;

  ret = daap_session_find(h, &s);
  if (!s)
    {
      evbuffer_free(evbuf);
      return ret;
    }

  ret = safe_atoi32(uri[3], &playlist);
  if (ret < 0)
    {
      evbuffer_free(evbuf);
      return dmap_send_error(h, "apso", "Invalid playlist ID");
    }

  return daap_reply_songlist_generic(h, evbuf, playlist);
}

static int
daap_reply_playlists(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct query_params qp;
  struct db_playlist_info dbpli;
  struct daap_session *s;
  struct evbuffer *playlistlist;
  struct evbuffer *playlist;
  const struct dmap_field_map *dfm;
  const struct dmap_field *df;
  const struct dmap_field **meta;
  const char *param;
  char **strval;
  int nmeta;
  int npls;
  int32_t val;
  int i;
  int ret;

  ret = daap_session_find(h, &s);
  if (!s)
    {
      evbuffer_free(evbuf);
      return ret;
    }

  ret = evbuffer_expand(evbuf, 61);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DAAP playlists reply\n");

      ret = dmap_send_error(h, "aply", "Out of memory");
      goto out_evbuf_free;
    }

  playlistlist = evbuffer_new();
  if (!playlistlist)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not create evbuffer for DMAP playlist list\n");

      ret = dmap_send_error(h, "aply", "Out of memory");
      goto out_evbuf_free;
    }

  /* Start with a big enough evbuffer - it'll expand as needed */
  ret = evbuffer_expand(playlistlist, 1024);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DMAP playlist list\n");

      ret = dmap_send_error(h, "aply", "Out of memory");
      goto out_list_free;
    }

  playlist = evbuffer_new();
  if (!playlist)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not create evbuffer for DMAP playlist block\n");

      ret = dmap_send_error(h, "aply", "Out of memory");
      goto out_list_free;
    }

  /* The buffer will expand if needed */
  ret = evbuffer_expand(playlist, 128);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DMAP playlist block\n");

      ret = dmap_send_error(h, "aply", "Out of memory");
      goto out_pl_free;
    }

  param = keyval_get(h->query, "meta");
  if (!param)
    {
      DPRINTF(E_LOG, L_DAAP, "No meta parameter in query, using default\n");

      param = default_meta_pl;
    }

  ret = parse_meta(h, "aply", param, &meta, &nmeta);
  if (nmeta < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Failed to parse meta parameter in DAAP query\n");

      /* retval from parse_meta() */
      goto out_pl_free;
    }

  memset(&qp, 0, sizeof(struct query_params));
  get_query_params(h->query, NULL, &qp);
  qp.type = Q_PL;

  ret = db_query_start(&qp);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not start query\n");

      ret = dmap_send_error(h, "aply", "Could not start query");
      goto out_query_free;
    }

  npls = 0;
  while (((ret = db_query_fetch_pl(&qp, &dbpli)) == 0) && (dbpli.id))
    {
      npls++;

      for (i = 0; i < nmeta; i++)
	{
	  df = meta[i];
	  dfm = df->dfm;

	  /* dmap.itemcount - always added */
	  if (dfm == &dfm_dmap_mimc)
	    continue;

	  /* com.apple.itunes.smart-playlist - type = 1 AND id != 1 */
	  if (dfm == &dfm_dmap_aeSP)
	    {
	      val = 0;
	      ret = safe_atoi32(dbpli.type, &val);
	      if ((ret == 0) && (val == PL_SMART))
		{
		  val = 1;
		  ret = safe_atoi32(dbpli.id, &val);
		  if ((ret == 0) && (val != 1))
		    {
		      int32_t aePS = 0;
		      dmap_add_char(playlist, "aeSP", 1);

		      ret = safe_atoi32(dbpli.special_id, &aePS);
		      if ((ret == 0) && (aePS > 0))
			dmap_add_char(playlist, "aePS", aePS);
		    }
		}

	      continue;
	    }

	  /* Not in struct playlist_info */
	  if (dfm->pli_offset < 0)
	    continue;

          strval = (char **) ((char *)&dbpli + dfm->pli_offset);

          if (!(*strval) || (**strval == '\0'))
            continue;

	  dmap_add_field(playlist, df, *strval, 0);

	  DPRINTF(E_DBG, L_DAAP, "Done with meta tag %s (%s)\n", df->desc, *strval);
	}

      /* Item count (mimc) */
      val = 0;
      ret = safe_atoi32(dbpli.items, &val);
      if ((ret == 0) && (val > 0))
	dmap_add_int(playlist, "mimc", val);

      /* Container ID (mpco) */
      dmap_add_int(playlist, "mpco", 0);

      /* Base playlist (abpl), id = 1 */
      val = 0;
      ret = safe_atoi32(dbpli.id, &val);
      if ((ret == 0) && (val == 1))
	dmap_add_char(playlist, "abpl", 1);

      DPRINTF(E_DBG, L_DAAP, "Done with playlist\n");

      dmap_add_container(playlistlist, "mlit", EVBUFFER_LENGTH(playlist));
      ret = evbuffer_add_buffer(playlistlist, playlist);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DAAP, "Could not add playlist to playlist list for DAAP playlists reply\n");

	  ret = -100;
	  break;
	}
    }

  DPRINTF(E_DBG, L_DAAP, "Done with playlist list, %d playlists\n", npls);

  free(meta);
  evbuffer_free(playlist);

  if (qp.filter)
    free(qp.filter);

  if (ret < 0)
    {
      db_query_end(&qp);

      if (ret == -100)
	ret = dmap_send_error(h, "aply", "Out of memory");
      else
	{
	  DPRINTF(E_LOG, L_DAAP, "Error fetching results\n");
	  ret = dmap_send_error(h, "aply", "Error fetching query results");
	}

      goto out_list_free;
    }

  /* Add header to evbuf, add playlistlist to evbuf */
  dmap_add_container(evbuf, "aply", EVBUFFER_LENGTH(playlistlist) + 53);
  dmap_add_int(evbuf, "mstt", 200); /* 12 */
  dmap_add_char(evbuf, "muty", 0);  /* 9 */
  dmap_add_int(evbuf, "mtco", qp.results); /* 12 */
  dmap_add_int(evbuf,"mrco", npls); /* 12 */
  dmap_add_container(evbuf, "mlcl", EVBUFFER_LENGTH(playlistlist));

  db_query_end(&qp);

  ret = evbuffer_add_buffer(evbuf, playlistlist);
  evbuffer_free(playlistlist);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not add playlist list to DAAP playlists reply\n");

      ret = dmap_send_error(h, "aply", "Out of memory");
      goto out_evbuf_free;
    }

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    {
      ret = dmap_send_error(h, "aply", "Server Error");
      goto out_evbuf_free;
    }

  return httpd_send_reply(h->c, h->req, h->r, evbuf);

 out_query_free:
  free(meta);
  if (qp.filter)
    free(qp.filter);

 out_pl_free:
  evbuffer_free(playlist);

 out_list_free:
  evbuffer_free(playlistlist);

 out_evbuf_free:
  evbuffer_free(evbuf);

  return ret;
}

static int
daap_reply_groups(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct query_params qp;
  struct db_group_info dbgri;
  struct daap_session *s;
  struct evbuffer *group;
  struct evbuffer *grouplist;
  const struct dmap_field_map *dfm;
  const struct dmap_field *df;
  const struct dmap_field **meta;
  struct sort_ctx *sctx;
  const char *param;
  char **strval;
  int nmeta;
  int sort_headers;
  int ngrp;
  int32_t val;
  int i;
  int ret;
  char *tag;

  ret = daap_session_find(h, &s);
  if (!s)
    {
      evbuffer_free(evbuf);
      return ret;
    }

  /* For now we only support album groups */
  tag = "agal";

  ret = evbuffer_expand(evbuf, 61);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DAAP groups reply\n");

      ret = dmap_send_error(h, tag, "Out of memory");
      goto out_evbuf_free;
    }

  grouplist = evbuffer_new();
  if (!grouplist)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not create evbuffer for DMAP group list\n");

      ret = dmap_send_error(h, tag, "Out of memory");
      goto out_evbuf_free;
    }

  /* Start with a big enough evbuffer - it'll expand as needed */
  ret = evbuffer_expand(grouplist, 1024);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DMAP group list\n");

      ret = dmap_send_error(h, tag, "Out of memory");
      goto out_list_free;
    }

  group = evbuffer_new();
  if (!group)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not create evbuffer for DMAP group block\n");

      ret = dmap_send_error(h, tag, "Out of memory");
      goto out_list_free;
    }

  /* The buffer will expand if needed */
  ret = evbuffer_expand(group, 128);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DMAP group block\n");

      ret = dmap_send_error(h, tag, "Out of memory");
      goto out_group_free;
    }

  param = keyval_get(h->query, "meta");
  if (!param)
    {
      DPRINTF(E_LOG, L_DAAP, "No meta parameter in query, using default\n");

      param = default_meta_group;
    }

  ret = parse_meta(h, tag, param, &meta, &nmeta);
  if (nmeta < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Failed to parse meta parameter in DAAP query\n");

      /* retval from parse_meta() */
      goto out_group_free;
    }

  memset(&qp, 0, sizeof(struct query_params));
  get_query_params(h->query, &sort_headers, &qp);
  qp.type = Q_GROUPS;

  sctx = NULL;
  if (sort_headers)
    {
      sctx = daap_sort_context_new();
      if (!sctx)
	{
	  DPRINTF(E_LOG, L_DAAP, "Could not create sort context\n");

	  ret = dmap_send_error(h, tag, "Out of memory");
	  goto out_query_free;
	}
    }

  ret = db_query_start(&qp);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not start query\n");

      if (sort_headers)
	daap_sort_context_free(sctx);

      ret = dmap_send_error(h, tag, "Could not start query");
      goto out_query_free;
    }

  ngrp = 0;
  while ((ret = db_query_fetch_group(&qp, &dbgri)) == 0)
    {
      ngrp++;

      for (i = 0; i < nmeta; i++)
	{
	  df = meta[i];
	  dfm = df->dfm;

	  /* dmap.itemcount - always added */
	  if (dfm == &dfm_dmap_mimc)
	    continue;

	  /* Not in struct group_info */
	  if (dfm->gri_offset < 0)
	    continue;

          strval = (char **) ((char *)&dbgri + dfm->gri_offset);

          if (!(*strval) || (**strval == '\0'))
            continue;

	  dmap_add_field(group, df, *strval, 0);

	  DPRINTF(E_DBG, L_DAAP, "Done with meta tag %s (%s)\n", df->desc, *strval);
	}

      if (sort_headers)
	{
	  ret = daap_sort_build(sctx, dbgri.itemname);
	  if (ret < 0)
	    {
	      DPRINTF(E_LOG, L_DAAP, "Could not add sort header to DAAP groups reply\n");

	      ret = -100;
	      break;
	    }
	}

      /* Item count, always added (mimc) */
      val = 0;
      ret = safe_atoi32(dbgri.itemcount, &val);
      if ((ret == 0) && (val > 0))
	dmap_add_int(group, "mimc", val);

      /* Song album artist, always added (asaa) */
      dmap_add_string(group, "asaa", dbgri.songalbumartist);

      /* Item id (miid) */
      val = 0;
      ret = safe_atoi32(dbgri.id, &val);
      if ((ret == 0) && (val > 0))
	dmap_add_int(group, "miid", val);

      DPRINTF(E_DBG, L_DAAP, "Done with group\n");

      dmap_add_container(grouplist, "mlit", EVBUFFER_LENGTH(group));
      ret = evbuffer_add_buffer(grouplist, group);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DAAP, "Could not add group to group list for DAAP groups reply\n");

	  ret = -100;
	  break;
	}
    }

  DPRINTF(E_DBG, L_DAAP, "Done with group list, %d groups\n", ngrp);

  free(meta);
  evbuffer_free(group);

  if (qp.filter)
    free(qp.filter);

  if (ret < 0)
    {
      db_query_end(&qp);

      if (sort_headers)
	daap_sort_context_free(sctx);

      if (ret == -100)
	ret = dmap_send_error(h, tag, "Out of memory");
      else
	{
	  DPRINTF(E_LOG, L_DAAP, "Error fetching results\n");
	  ret = dmap_send_error(h, tag, "Error fetching query results");
	}

      goto out_list_free;
    }

  /* Add header to evbuf, add grouplist to evbuf */
  if (sort_headers)
    dmap_add_container(evbuf, tag, EVBUFFER_LENGTH(grouplist) + EVBUFFER_LENGTH(sctx->headerlist) + 53);
  else
    dmap_add_container(evbuf, tag, EVBUFFER_LENGTH(grouplist) + 53);

  dmap_add_int(evbuf, "mstt", 200); /* 12 */
  dmap_add_char(evbuf, "muty", 0);  /* 9 */
  dmap_add_int(evbuf, "mtco", qp.results); /* 12 */
  dmap_add_int(evbuf,"mrco", ngrp); /* 12 */
  dmap_add_container(evbuf, "mlcl", EVBUFFER_LENGTH(grouplist));

  db_query_end(&qp);

  ret = evbuffer_add_buffer(evbuf, grouplist);
  evbuffer_free(grouplist);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not add group list to DAAP groups reply\n");

      if (sort_headers)
	daap_sort_context_free(sctx);

      ret = dmap_send_error(h, tag, "Out of memory");
      goto out_evbuf_free;
    }

  if (sort_headers)
    {
      ret = daap_sort_finalize(sctx, evbuf);
      daap_sort_context_free(sctx);

      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DAAP, "Could not add sort headers to DAAP browse reply\n");

	  ret = dmap_send_error(h, tag, "Out of memory");
	  goto out_evbuf_free;
	}
    }

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    {
      ret = dmap_send_error(h, tag, "Server Error");
      goto out_evbuf_free;
    }

  return httpd_send_reply(h->c, h->req, h->r, evbuf);

 out_query_free:
  free(meta);
  if (qp.filter)
    free(qp.filter);

 out_group_free:
  evbuffer_free(group);

 out_list_free:
  evbuffer_free(grouplist);

 out_evbuf_free:
  evbuffer_free(evbuf);

  return ret;
}

static int
daap_reply_browse(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct query_params qp;
  struct daap_session *s;
  struct evbuffer *itemlist;
  struct sort_ctx *sctx;
  char *browse_item;
  char *sort_item;
  char *tag;
  int sort_headers;
  int nitems;
  int ret;

  ret = daap_session_find(h, &s);
  if (!s)
    {
      evbuffer_free(evbuf);
      return ret;
    }

  memset(&qp, 0, sizeof(struct query_params));

  if (strcmp(uri[3], "artists") == 0)
    {
      tag = "abar";
      qp.type = Q_BROWSE_ARTISTS;
    }
  else if (strcmp(uri[3], "genres") == 0)
    {
      tag = "abgn";
      qp.type = Q_BROWSE_GENRES;
    }
  else if (strcmp(uri[3], "albums") == 0)
    {
      tag = "abal";
      qp.type = Q_BROWSE_ALBUMS;
    }
  else if (strcmp(uri[3], "composers") == 0)
    {
      tag = "abcp";
      qp.type = Q_BROWSE_COMPOSERS;
    }
  else
    {
      DPRINTF(E_LOG, L_DAAP, "Invalid DAAP browse request type '%s'\n", uri[3]);

      evbuffer_free(evbuf);
      return dmap_send_error(h, "abro", "Invalid browse type");
    }

  ret = evbuffer_expand(evbuf, 52);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DAAP browse reply\n");

      evbuffer_free(evbuf);
      return dmap_send_error(h, "abro", "Out of memory");
    }

  itemlist = evbuffer_new();
  if (!itemlist)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not create evbuffer for DMAP browse item list\n");

      evbuffer_free(evbuf);
      return dmap_send_error(h, "abro", "Out of memory");
    }

  /* Start with a big enough evbuffer - it'll expand as needed */
  ret = evbuffer_expand(itemlist, 512);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not expand evbuffer for DMAP browse item list\n");

      evbuffer_free(evbuf);
      evbuffer_free(itemlist);

      return dmap_send_error(h, "abro", "Out of memory");
    }

  get_query_params(h->query, &sort_headers, &qp);

  sctx = NULL;
  if (sort_headers)
    {
      sctx = daap_sort_context_new();
      if (!sctx)
	{
	  DPRINTF(E_LOG, L_DAAP, "Could not create sort context\n");

	  evbuffer_free(evbuf);
	  evbuffer_free(itemlist);
	  if (qp.filter)
	    free(qp.filter);

	  return dmap_send_error(h, "abro", "Out of memory");
	}
    }

  ret = db_query_start(&qp);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not start query\n");

      if (sort_headers)
	daap_sort_context_free(sctx);

      evbuffer_free(evbuf);
      evbuffer_free(itemlist);
      if (qp.filter)
	free(qp.filter);

      return dmap_send_error(h, "abro", "Could not start query");
    }

  nitems = 0;
  while (((ret = db_query_fetch_string_sort(&qp, &browse_item, &sort_item)) == 0) && (browse_item))
    {
      nitems++;

      if (sort_headers)
	{
	  ret = daap_sort_build(sctx, sort_item);
	  if (ret < 0)
	    {
	      DPRINTF(E_LOG, L_DAAP, "Could not add sort header to DAAP browse reply\n");

	      break;
	    }
	}

      dmap_add_string(itemlist, "mlit", browse_item);
    }

  if (qp.filter)
    free(qp.filter);

  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Error fetching/building results\n");

      db_query_end(&qp);

      if (sort_headers)
	daap_sort_context_free(sctx);

      evbuffer_free(evbuf);
      evbuffer_free(itemlist);

      return dmap_send_error(h, "abro", "Error fetching/building query results");
    }

  if (sort_headers)
    dmap_add_container(evbuf, "abro", EVBUFFER_LENGTH(itemlist) + EVBUFFER_LENGTH(sctx->headerlist) + 44);
  else
    dmap_add_container(evbuf, "abro", EVBUFFER_LENGTH(itemlist) + 44);

  dmap_add_int(evbuf, "mstt", 200);    /* 12 */
  dmap_add_int(evbuf, "mtco", qp.results); /* 12 */
  dmap_add_int(evbuf, "mrco", nitems); /* 12 */

  dmap_add_container(evbuf, tag, EVBUFFER_LENGTH(itemlist));

  db_query_end(&qp);

  ret = evbuffer_add_buffer(evbuf, itemlist);
  evbuffer_free(itemlist);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not add item list to DAAP browse reply\n");

      if (sort_headers)
	daap_sort_context_free(sctx);

      evbuffer_free(evbuf);

      return dmap_send_error(h, tag, "Out of memory");
    }

  if (sort_headers)
    {
      ret = daap_sort_finalize(sctx, evbuf);
      daap_sort_context_free(sctx);

      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DAAP, "Could not add sort headers to DAAP browse reply\n");

	  evbuffer_free(evbuf);

	  return dmap_send_error(h, tag, "Out of memory");
	}
    }

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    {
      evbuffer_free(evbuf);

      return dmap_send_error(h, tag, "Server error");
    }

  return httpd_send_reply(h->c, h->req, h->r, evbuf);
}

/* NOTE: We only handle artwork at the moment */
static int
daap_reply_extra_data(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  char clen[32];
  struct daap_session *s;
  const char *param;
  char *ctype;
  int id;
  int max_w;
  int max_h;
  int ret;

  ret = daap_session_find(h, &s);
  if (!s)
    {
      evbuffer_free(evbuf);
      return ret;
    }

  ret = safe_atoi32(uri[3], &id);
  if (ret < 0)
    goto bad_request;

  param = keyval_get(h->query, "mw");
  if (!param)
    {
      DPRINTF(E_LOG, L_DAAP, "Request for artwork without mw parameter\n");

      goto bad_request;
    }

  ret = safe_atoi32(param, &max_w);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not convert mw parameter to integer\n");

      goto bad_request;
    }

  param = keyval_get(h->query, "mh");
  if (!param)
    {
      DPRINTF(E_LOG, L_DAAP, "Request for artwork without mh parameter\n");

      goto bad_request;
    }

  ret = safe_atoi32(param, &max_h);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not convert mh parameter to integer\n");

      goto bad_request;
    }

  if (strcmp(uri[2], "groups") == 0)
    ret = artwork_get_group(id, max_w, max_h, ART_CAN_PNG | ART_CAN_JPEG, evbuf);
  else if (strcmp(uri[2], "items") == 0)
    ret = artwork_get_item(id, max_w, max_h, ART_CAN_PNG | ART_CAN_JPEG, evbuf);

  switch (ret)
    {
      case ART_FMT_PNG:
	ctype = "image/png";
	break;

      case ART_FMT_JPEG:
	ctype = "image/jpeg";
	break;

      default:
	goto no_artwork;
    }

  http_response_set_body(h->r, evbuf);

  http_response_remove_header(h->r, "Content-Type");
  ret = http_response_add_header(h->r, "Content-Type", ctype);
  if (ret < 0)
    goto out_error;

  snprintf(clen, sizeof(clen), "%ld", (long)EVBUFFER_LENGTH(evbuf));
  ret = http_response_add_header(h->r, "Content-Length", clen);
  if (ret < 0)
    goto out_error;

  /* No gzip compression for artwork */
  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    goto out_error;

  ret = http_server_response_run(h->c, h->r);
  if (ret < 0)
    goto out_error;

  return 0;

 no_artwork:
  evbuffer_free(evbuf);

  ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "No Content");
  if (ret < 0)
    goto out_error;

  ret = http_server_response_run(h->c, h->r);
  if (ret < 0)
    goto out_error;

  return 0;

 out_error:
  return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");

 bad_request:
  evbuffer_free(evbuf);

  return http_server_error_run(h->c, h->r, HTTP_BAD_REQUEST, "Bad Request");
}

static int
daap_stream(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  int id;
  int ret;

  evbuffer_free(evbuf);

  ret = daap_session_find(h, &s);
  if (!s)
    return ret;

  ret = safe_atoi32(uri[3], &id);
  if (ret < 0)
    return http_server_error_run(h->c, h->r, HTTP_BAD_REQUEST, "Bad Request");

  return httpd_stream_file(h->c, h->req, h->r, id);
}


static char *
daap_fix_request_uri(char *uri)
{
  char *ret;

  /* iTunes 9 gives us an absolute request-uri like
   *  daap://10.1.1.20:3689/server-info
   */

  if (strncmp(uri, "daap://", strlen("daap://")) != 0)
    return uri;

  ret = strchr(uri + strlen("daap://"), '/');
  if (!ret)
    {
      DPRINTF(E_LOG, L_DAAP, "Malformed DAAP Request URI '%s'\n", uri);
      return NULL;
    }

  return ret;
}


#ifdef DMAP_TEST
static const struct dmap_field dmap_TEST = { "test.container", "TEST", NULL, DMAP_TYPE_LIST };
static const struct dmap_field dmap_TST1 = { "test.ubyte",     "TST1", NULL, DMAP_TYPE_UBYTE };
static const struct dmap_field dmap_TST2 = { "test.byte",      "TST2", NULL, DMAP_TYPE_BYTE };
static const struct dmap_field dmap_TST3 = { "test.ushort",    "TST3", NULL, DMAP_TYPE_USHORT };
static const struct dmap_field dmap_TST4 = { "test.short",     "TST4", NULL, DMAP_TYPE_SHORT };
static const struct dmap_field dmap_TST5 = { "test.uint",      "TST5", NULL, DMAP_TYPE_UINT };
static const struct dmap_field dmap_TST6 = { "test.int",       "TST6", NULL, DMAP_TYPE_INT };
static const struct dmap_field dmap_TST7 = { "test.ulong",     "TST7", NULL, DMAP_TYPE_ULONG };
static const struct dmap_field dmap_TST8 = { "test.long",      "TST8", NULL, DMAP_TYPE_LONG };
static const struct dmap_field dmap_TST9 = { "test.string",    "TST9", NULL, DMAP_TYPE_STRING };

static int
daap_reply_dmap_test(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  char buf[64];
  struct evbuffer *test;
  int ret;

  test = evbuffer_new();
  if (!test)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not create evbuffer for DMAP test\n");

      evbuffer_free(evbuf);
      return dmap_send_error(h, dmap_TEST.tag, "Out of memory");
    }

  /* UBYTE */
  snprintf(buf, sizeof(buf), "%" PRIu8, UINT8_MAX);
  dmap_add_field(test, &dmap_TST1, buf, 0);
  dmap_add_field(test, &dmap_TST9, buf, 0);

  /* BYTE */
  snprintf(buf, sizeof(buf), "%" PRIi8, INT8_MIN);
  dmap_add_field(test, &dmap_TST2, buf, 0);
  dmap_add_field(test, &dmap_TST9, buf, 0);
  snprintf(buf, sizeof(buf), "%" PRIi8, INT8_MAX);
  dmap_add_field(test, &dmap_TST2, buf, 0);
  dmap_add_field(test, &dmap_TST9, buf, 0);

  /* USHORT */
  snprintf(buf, sizeof(buf), "%" PRIu16, UINT16_MAX);
  dmap_add_field(test, &dmap_TST3, buf, 0);
  dmap_add_field(test, &dmap_TST9, buf, 0);

  /* SHORT */
  snprintf(buf, sizeof(buf), "%" PRIi16, INT16_MIN);
  dmap_add_field(test, &dmap_TST4, buf, 0);
  dmap_add_field(test, &dmap_TST9, buf, 0);
  snprintf(buf, sizeof(buf), "%" PRIi16, INT16_MAX);
  dmap_add_field(test, &dmap_TST4, buf, 0);
  dmap_add_field(test, &dmap_TST9, buf, 0);

  /* UINT */
  snprintf(buf, sizeof(buf), "%" PRIu32, UINT32_MAX);
  dmap_add_field(test, &dmap_TST5, buf, 0);
  dmap_add_field(test, &dmap_TST9, buf, 0);

  /* INT */
  snprintf(buf, sizeof(buf), "%" PRIi32, INT32_MIN);
  dmap_add_field(test, &dmap_TST6, buf, 0);
  dmap_add_field(test, &dmap_TST9, buf, 0);
  snprintf(buf, sizeof(buf), "%" PRIi32, INT32_MAX);
  dmap_add_field(test, &dmap_TST6, buf, 0);
  dmap_add_field(test, &dmap_TST9, buf, 0);

  /* ULONG */
  snprintf(buf, sizeof(buf), "%" PRIu64, UINT64_MAX);
  dmap_add_field(test, &dmap_TST7, buf, 0);
  dmap_add_field(test, &dmap_TST9, buf, 0);

  /* LONG */
  snprintf(buf, sizeof(buf), "%" PRIi64, INT64_MIN);
  dmap_add_field(test, &dmap_TST8, buf, 0);
  dmap_add_field(test, &dmap_TST9, buf, 0);
  snprintf(buf, sizeof(buf), "%" PRIi64, INT64_MAX);
  dmap_add_field(test, &dmap_TST8, buf, 0);
  dmap_add_field(test, &dmap_TST9, buf, 0);

  dmap_add_container(evbuf, dmap_TEST.tag, EVBUFFER_LENGTH(test));

  ret = evbuffer_add_buffer(evbuf, test);
  evbuffer_free(test);

  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not add test results to DMAP test reply\n");

      evbuffer_free(evbuf);
      return dmap_send_error(h, dmap_TEST.tag, "Out of memory");
    }

  http_response_set_body(r, evbuf);

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    goto out_error;

  ret = http_server_response_run(h->c, h->r);
  if (ret < 0)
    goto out_error;

  return 0;

 out_error:
  return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");
}
#endif /* DMAP_TEST */


static struct uri_map daap_handlers[] =
  {

    {
      .regexp = "^/server-info$",
      .handler = daap_reply_server_info
    },
    {
      .regexp = "^/content-codes$",
      .handler = daap_reply_content_codes
    },
    {
      .regexp = "^/login$",
      .handler = daap_reply_login
    },
    {
      .regexp = "^/logout$",
      .handler = daap_reply_logout
    },
    {
      .regexp = "^/update$",
      .handler = daap_reply_update
    },
    {
      .regexp = "^/activity$",
      .handler = daap_reply_activity
    },
    {
      .regexp = "^/databases$",
      .handler = daap_reply_dblist
    },
    {
      .regexp = "^/databases/[[:digit:]]+/browse/[^/]+$",
      .handler = daap_reply_browse
    },
    {
      .regexp = "^/databases/[[:digit:]]+/items$",
      .handler = daap_reply_dbsonglist
    },
    {
      .regexp = "^/databases/[[:digit:]]+/items/[[:digit:]]+[.][^/]+$",
      .handler = daap_stream
    },
    {
      .regexp = "^/databases/[[:digit:]]+/items/[[:digit:]]+/extra_data/artwork$",
      .handler = daap_reply_extra_data
    },
    {
      .regexp = "^/databases/[[:digit:]]+/containers$",
      .handler = daap_reply_playlists
    },
    {
      .regexp = "^/databases/[[:digit:]]+/containers/[[:digit:]]+/items$",
      .handler = daap_reply_plsonglist
    },
    {
      .regexp = "^/databases/[[:digit:]]+/groups$",
      .handler = daap_reply_groups
    },
    {
      .regexp = "^/databases/[[:digit:]]+/groups/[[:digit:]]+/extra_data/artwork$",
      .handler = daap_reply_extra_data
    },
#ifdef DMAP_TEST
    {
      .regexp = "^/dmap-test$",
      .handler = daap_reply_dmap_test
    },
#endif /* DMAP_TEST */
    { 
      .regexp = NULL,
      .handler = NULL
    }
  };


int
daap_request(struct http_connection *c, struct http_request *req, struct http_response *r)
{
  struct httpd_hdl hdl;
  struct keyval query;
  char *full_uri;
  char *uri;
  char *ptr;
  char *uri_parts[7];
  struct evbuffer *evbuf;
  const char *ua;
  cfg_t *lib;
  char *libname;
  char *passwd;
  int handler;
  int ret;
  int i;

  memset(&query, 0, sizeof(struct keyval));
  memset(&hdl, 0, sizeof(struct httpd_hdl));

  full_uri = httpd_fixup_uri(req);
  if (!full_uri)
    return http_server_error_run(c, r, HTTP_BAD_REQUEST, "Bad Request");

  ptr = daap_fix_request_uri(full_uri);
  if (!ptr)
    {
      free(full_uri);

      return http_server_error_run(c, r, HTTP_BAD_REQUEST, "Bad Request");
    }

  if (ptr != full_uri)
    {
      uri = strdup(ptr);
      free(full_uri);

      if (!uri)
	return http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");

      full_uri = uri;
    }

  ptr = strchr(full_uri, '?');
  if (ptr)
    *ptr = '\0';

  uri = strdup(full_uri);
  if (!uri)
    {
      free(full_uri);

      return http_server_error_run(c, r, HTTP_BAD_REQUEST, "Bad Request");
    }

  if (ptr)
    *ptr = '?';

  http_decode_uri(uri, URI_DECODE_NORMAL);

  DPRINTF(E_DBG, L_DAAP, "DAAP request: %s\n", full_uri);

  handler = -1;
  for (i = 0; daap_handlers[i].handler; i++)
    {
      ret = tre_regexec(&daap_handlers[i].preg, uri, 0, NULL, 0);
      if (ret == 0)
        {
          handler = i;
          break;
        }
    }

  if (handler < 0)
    {
      DPRINTF(E_LOG, L_DAAP, "Unrecognized DAAP request\n");

      ret = http_server_error_run(c, r, HTTP_BAD_REQUEST, "Bad Request");
      goto out;
    }

  /* Check authentication */
  lib = cfg_getsec(cfg, "library");
  passwd = cfg_getstr(lib, "password");

  /* No authentication for these URIs */
  if ((strcmp(uri, "/server-info") == 0)
      || (strcmp(uri, "/logout") == 0)
      || (strncmp(uri, "/databases/1/items/", strlen("/databases/1/items/")) == 0))
    passwd = NULL;

  /* Waive HTTP authentication for Remote
   * Remotes are authentified by their pairing-guid; DAAP queries require a
   * valid session-id that Remote can only obtain if its pairing-guid is in
   * our database. So HTTP authentication is waived for Remote.
   */
  ua = http_request_get_header(req, "User-Agent");
  if ((ua) && (strncmp(ua, "Remote", strlen("Remote")) == 0))
    passwd = NULL;

  if (passwd)
    {
      libname = cfg_getstr(lib, "name");

      DPRINTF(E_DBG, L_HTTPD, "Checking authentication for library '%s'\n", libname);

      /* We don't care about the username */
      ret = httpd_basic_auth(c, req, r, NULL, passwd, libname);
      switch (ret)
	{
	  case HTTP_OK:
	    DPRINTF(E_DBG, L_HTTPD, "Library authentication successful\n");
	    break;

	  case -1:
	    ret = -1;
	    goto out;

	  default:
	    /* HTTP_UNAUTHORIZED or HTTP_INTERNAL_ERROR on error */
	    ret = 0;
	    goto out;
	}
    }

  memset(uri_parts, 0, sizeof(uri_parts));

  uri_parts[0] = strtok_r(uri, "/", &ptr);
  for (i = 1; (i < sizeof(uri_parts) / sizeof(uri_parts[0])) && uri_parts[i - 1]; i++)
    {
      uri_parts[i] = strtok_r(NULL, "/", &ptr);
    }

  if (!uri_parts[0] || uri_parts[i - 1] || (i < 2))
    {
      DPRINTF(E_LOG, L_DAAP, "DAAP URI has too many/few components (%d)\n", (uri_parts[0]) ? i : 0);

      ret = http_server_error_run(c, r, HTTP_BAD_REQUEST, "Bad Request");
      goto out;
    }

  ret = http_parse_query_string(full_uri, &query);
  if (ret < 0)
    {
      ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
      goto out;
    }

  ret = http_response_add_header(r, "Accept-Ranges", "bytes");
  if (ret < 0)
    {
      ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
      goto out_clear_query;
    }

  ret = http_response_add_header(r, "DAAP-Server", PACKAGE "/" VERSION);
  if (ret < 0)
    {
      ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
      goto out_clear_query;
    }

  /* Content-Type for all replies, even the actual audio streaming. Note that
   * video streaming will override this Content-Type with a more appropriate
   * video/<type> Content-Type as expected by clients like Front Row.
   */
  ret = http_response_add_header(r, "Content-Type", "application/x-dmap-tagged");
  if (ret < 0)
    {
      ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
      goto out_clear_query;
    }

  /* Freed in the handler */
  evbuf = evbuffer_new();
  if (!evbuf)
    {
      DPRINTF(E_LOG, L_DAAP, "Could not allocate evbuffer for DAAP reply\n");

      ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
      goto out_clear_query;
    }

  ret = db_pool_get();
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_RSP, "Could not acquire database connection\n");

      evbuffer_free(evbuf);

      ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
      goto out_clear_query;
    }

  hdl.c = c;
  hdl.req = req;
  hdl.r = r;
  hdl.query = &query;

  ret = daap_handlers[handler].handler(&hdl, evbuf, uri_parts);

  db_pool_release();

 out_clear_query:
  keyval_clear(&query);
 out:
  free(uri);
  free(full_uri);

  return ret;
}

int
daap_is_request(char *uri)
{
  uri = daap_fix_request_uri(uri);
  if (!uri)
    return 0;

  if (strncmp(uri, "/databases/", strlen("/databases/")) == 0)
    return 1;
  if (strcmp(uri, "/databases") == 0)
    return 1;
  if (strcmp(uri, "/server-info") == 0)
    return 1;
  if (strcmp(uri, "/content-codes") == 0)
    return 1;
  if (strcmp(uri, "/login") == 0)
    return 1;
  if (strcmp(uri, "/update") == 0)
    return 1;
  if (strcmp(uri, "/activity") == 0)
    return 1;
  if (strcmp(uri, "/logout") == 0)
    return 1;

#ifdef DMAP_TEST
  if (strcmp(uri, "/dmap-test") == 0)
    return 1;
#endif

  return 0;
}

int
daap_init(void)
{
  char buf[64];
  int i;
  int ret;

  current_rev = 2;
  update_requests = NULL;

  sessions_sq = dispatch_queue_create("org.forked-daapd.daap.sessions", NULL);
  if (!sessions_sq)
    {
      DPRINTF(E_FATAL, L_DAAP, "Could not create dispatch queue for DAAP sessions\n");

      return -1;
    }

  updates_sq = dispatch_queue_create("org.forked-daapd.daap.updates", NULL);
  if (!updates_sq)
    {
      DPRINTF(E_FATAL, L_DAAP, "Could not create dispatch queue for DAAP update requests\n");

      goto updates_sq_fail;
    }

  for (i = 0; daap_handlers[i].handler; i++)
    {
      ret = tre_regcomp(&daap_handlers[i].preg, daap_handlers[i].regexp, REG_EXTENDED | REG_NOSUB);
      if (ret != 0)
        {
          tre_regerror(ret, &daap_handlers[i].preg, buf, sizeof(buf));

          DPRINTF(E_FATAL, L_DAAP, "DAAP init failed; regexp error: %s\n", buf);
	  goto regexp_fail;
        }
    }

  daap_sessions = avl_alloc_tree(daap_session_compare, daap_session_free);
  if (!daap_sessions)
    {
      DPRINTF(E_FATAL, L_DAAP, "DAAP init could not allocate DAAP sessions AVL tree\n");

      goto daap_avl_alloc_fail;
    }

  return 0;

 daap_avl_alloc_fail:
  for (i = 0; daap_handlers[i].handler; i++)
    tre_regfree(&daap_handlers[i].preg);
 regexp_fail:
  dispatch_release(updates_sq);
 updates_sq_fail:
  dispatch_release(sessions_sq);

  return -1;
}

void
daap_deinit(void)
{
  int i;

  for (i = 0; daap_handlers[i].handler; i++)
    tre_regfree(&daap_handlers[i].preg);

  avl_free_tree(daap_sessions);

  dispatch_release(sessions_sq);
  dispatch_release(updates_sq);

  /* Pending update requests are removed during HTTP server shutdown */
}
