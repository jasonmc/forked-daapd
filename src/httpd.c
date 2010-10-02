/*
 * Copyright (C) 2009-2010 Julien BLACHE <jb@jblache.org>
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
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <inttypes.h>

#include <zlib.h>

#include <dispatch/dispatch.h>

#include "evbuffer/evbuffer.h"
#include "logger.h"
#include "db.h"
#include "conffile.h"
#include "misc.h"
#include "network.h"
#include "http.h"
#include "httpd.h"
#include "httpd_rsp.h"
#include "httpd_daap.h"
#include "httpd_dacp.h"
#include "transcode.h"


/*
 * HTTP client quirks by User-Agent, from mt-daapd
 *
 * - iTunes:
 *   + Connection: Keep-Alive on HTTP error 401
 * - Hifidelio:
 *   + Connection: Keep-Alive for streaming (Connection: close not honoured)
 *
 * These quirks are not implemented. Implement as needed.
 *
 * Implemented quirks:
 *
 * - Roku:
 *   + Does not encode space as + in query string
 * - iTunes:
 *   + Does not encode space as + in query string
 */


#define STREAM_CHUNK_SIZE (64 * 1024)
#define WEBFACE_ROOT   DATADIR "/webface/"

struct content_type_map {
  char *ext;
  char *ctype;
};

struct stream_ctx {
  uint8_t *buf;
  struct evbuffer *evbuf;
  int id;
  int fd;
  off_t size;
  off_t stream_size;
  off_t offset;
  off_t start_offset;
  off_t end_offset;
  int marked;
  struct transcode_ctx *xcode;
};


static const struct content_type_map ext2ctype[] =
  {
    { ".html", "text/html; charset=utf-8" },
    { ".xml",  "text/xml; charset=utf-8" },
    { ".css",  "text/css; charset=utf-8" },
    { ".txt",  "text/plain; charset=utf-8" },
    { ".js",   "application/javascript; charset=utf-8" },
    { ".gif",  "image/gif" },
    { ".ico",  "image/x-ico" },
    { ".png",  "image/png" },
    { NULL, NULL }
  };

static dispatch_group_t http_group;
static struct http_server *http6;
static struct http_server *http4;


static void
stream_chunk_free_cb(void *data)
{
  struct stream_ctx *st;

  st = (struct stream_ctx *)data;

  DPRINTF(E_LOG, L_HTTPD, "Connection closed; stopping streaming of file ID %d\n", st->id);

  if (st->evbuf)
    evbuffer_free(st->evbuf);

  if (st->xcode)
    transcode_cleanup(st->xcode);
  else
    {
      free(st->buf);
      close(st->fd);
    }

  free(st);
}

static void
stream_up_playcount(struct stream_ctx *st)
{
  int ret;

  if (!st->marked
      && (st->stream_size > ((st->size * 50) / 100))
      && (st->offset > ((st->size * 80) / 100)))
    {
      ret = db_pool_get();
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_HTTPD, "Could not acquire database connection; cannot increase playcount\n");

	  return;
	}

      st->marked = 1;
      db_file_inc_playcount(st->id);

      db_pool_release();
    }
}

static int
stream_get_chunk_xcode(struct stream_ctx *st)
{
  int xcoded;
  int ret;

 consume:
  xcoded = transcode(st->xcode, st->evbuf, STREAM_CHUNK_SIZE);
  if (xcoded == 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Done streaming transcoded file id %d\n", st->id);

      return 0;
    }
  else if (xcoded < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Transcoding error, file id %d\n", st->id);

      return -1;
    }

  DPRINTF(E_DBG, L_HTTPD, "Got %d bytes from transcode; streaming file id %d\n", xcoded, st->id);

  /* Consume transcoded data until we meet start_offset */
  if (st->start_offset > st->offset)
    {
      ret = st->start_offset - st->offset;

      if (ret < xcoded)
	{
	  evbuffer_drain(st->evbuf, ret);
	  st->offset += ret;

	  ret = xcoded - ret;
	}
      else
	{
	  evbuffer_drain(st->evbuf, xcoded);
	  st->offset += xcoded;

	  goto consume;
	}
    }
  else
    ret = xcoded;

  st->offset += ret;

  return 0;
}

static int
stream_get_chunk_raw(struct stream_ctx *st)
{
  size_t chunk_size;
  int ret;

  if (st->end_offset && (st->offset > st->end_offset))
    return 0;

  if (st->end_offset && ((st->offset + STREAM_CHUNK_SIZE) > (st->end_offset + 1)))
    chunk_size = st->end_offset + 1 - st->offset;
  else
    chunk_size = STREAM_CHUNK_SIZE;  

  ret = read(st->fd, st->buf, chunk_size);
  if (ret == 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Done streaming file id %d\n", st->id);

      return 0;
    }
  else if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Streaming error, file id %d\n", st->id);

      return -1;
    }

  DPRINTF(E_DBG, L_HTTPD, "Read %d bytes; streaming file id %d\n", ret, st->id);

  st->offset += ret;

  ret = evbuffer_add(st->evbuf, st->buf, ret);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Out of memory for raw streaming evbuffer\n");

      return -1;
    }

  return 0;
}

static struct evbuffer *
stream_chunk_cb(struct http_connection *c, struct http_response *r, void *data)
{
  struct stream_ctx *st;
  struct evbuffer *evbuf;
  int ret;

  st = (struct stream_ctx *)data;

  if (st->xcode)
    ret = stream_get_chunk_xcode(st);
  else
    ret = stream_get_chunk_raw(st);

  if (ret < 0)
    return NULL;

  if (EVBUFFER_LENGTH(st->evbuf) == 0)
    {
      ret = http_server_response_end_chunked(c, r);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_HTTPD, "Failed to terminate chunked response properly!\n");

	  stream_chunk_free_cb(st);
	  return NULL;
	}

      /* Buffer will be freed by the server */
      evbuf = st->evbuf;
      st->evbuf = NULL;
      return evbuf;
    }

  stream_up_playcount(st);

  return st->evbuf;
}

int
httpd_stream_file(struct http_connection *c, struct http_request *req, struct http_response *r, int id)
{
  struct stat sb;
  struct media_file_info *mfi;
  struct stream_ctx *st;
  const char *param;
  const char *param_end;
  char buf[64];
  int64_t offset;
  int64_t end_offset;
  off_t pos;
  int transcode;
  int ret;

  offset = 0;
  end_offset = 0;
  param = http_request_get_header(req, "Range");
  if (param)
    {
      DPRINTF(E_DBG, L_HTTPD, "Found Range header: %s\n", param);

      /* Start offset */
      ret = safe_atoi64(param + strlen("bytes="), &offset);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_HTTPD, "Invalid start offset, will stream whole file (%s)\n", param);
	  offset = 0;
	}
      /* End offset, if any */
      else
	{
	  param_end = strchr(param, '-');
	  if (param_end)
	    {
	      ret = safe_atoi64(param_end + 1, &end_offset);
	      if (ret < 0)
		{
		  DPRINTF(E_LOG, L_HTTPD, "Invalid end offset, will stream to end of file (%s)\n", param);
		  end_offset = 0;
		}

	      if (end_offset < offset)
		{
		  DPRINTF(E_LOG, L_HTTPD, "End offset < start offset, will stream to end of file (%" PRIi64 " < %" PRIi64 ")\n", end_offset, offset);
		  end_offset = 0;
		}
	    }
	}
    }

  /* Caller must have obtained a database connection from the pool */
  mfi = db_file_fetch_byid(id);
  if (!mfi)
    {
      DPRINTF(E_LOG, L_HTTPD, "Item %d not found\n", id);

      return http_server_error_run(c, r, HTTP_NOT_FOUND, "Not Found");
    }

  if (mfi->data_kind != 0)
    {
      ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Cannot stream radio station");
      goto out_free_mfi;
    }

  st = (struct stream_ctx *)malloc(sizeof(struct stream_ctx));
  if (!st)
    {
      DPRINTF(E_LOG, L_HTTPD, "Out of memory for struct stream_ctx\n");

      ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
      goto out_free_mfi;
    }
  memset(st, 0, sizeof(struct stream_ctx));
  st->fd = -1;

  transcode = transcode_needed(req, mfi->codectype);

  if (transcode)
    {
      DPRINTF(E_INFO, L_HTTPD, "Preparing to transcode %s\n", mfi->path);

      st->xcode = transcode_setup(mfi, &st->size, 1);
      if (!st->xcode)
	{
	  DPRINTF(E_WARN, L_HTTPD, "Transcoding setup failed, aborting streaming\n");

	  ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
	  goto out_free_st;
	}

      if (!http_response_get_header(r, "Content-Type"))
	http_response_add_header(r, "Content-Type", "audio/wav");
    }
  else
    {
      /* Stream the raw file */
      DPRINTF(E_INFO, L_HTTPD, "Preparing to stream %s\n", mfi->path);

      st->buf = (uint8_t *)malloc(STREAM_CHUNK_SIZE);
      if (!st->buf)
	{
	  DPRINTF(E_LOG, L_HTTPD, "Out of memory for raw streaming buffer\n");

	  ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
	  goto out_free_st;
	}

      st->fd = open(mfi->path, O_RDONLY);
      if (st->fd < 0)
	{
	  DPRINTF(E_LOG, L_HTTPD, "Could not open %s: %s\n", mfi->path, strerror(errno));

	  ret = http_server_error_run(c, r, HTTP_NOT_FOUND, "Not Found");
	  goto out_cleanup;
	}

      ret = stat(mfi->path, &sb);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_HTTPD, "Could not stat() %s: %s\n", mfi->path, strerror(errno));

	  ret = http_server_error_run(c, r, HTTP_NOT_FOUND, "Not Found");
	  goto out_cleanup;
	}
      st->size = sb.st_size;

      pos = lseek(st->fd, offset, SEEK_SET);
      if (pos == (off_t) -1)
	{
	  DPRINTF(E_LOG, L_HTTPD, "Could not seek into %s: %s\n", mfi->path, strerror(errno));

	  ret = http_server_error_run(c, r, HTTP_BAD_REQUEST, "Bad Request");
	  goto out_cleanup;
	}
      st->offset = offset;
      st->end_offset = end_offset;

      /* Content-Type for video files is different than for audio files
       * and overrides whatever may have been set previously, like
       * application/x-dmap-tagged when we're speaking DAAP.
       */
      if (mfi->has_video)
	{
	  /* Front Row and others expect video/<type> */
	  ret = snprintf(buf, sizeof(buf), "video/%s", mfi->type);
	  if ((ret < 0) || (ret >= sizeof(buf)))
	    DPRINTF(E_LOG, L_HTTPD, "Content-Type too large for buffer, dropping\n");
	  else
	    {
	      http_response_remove_header(r, "Content-Type");
	      http_response_add_header(r, "Content-Type", buf);
	    }
	}
      /* If no Content-Type has been set and we're streaming audio, add a proper
       * Content-Type for the file we're streaming. Remember DAAP streams audio
       * with application/x-dmap-tagged as the Content-Type (ugh!).
       */
      else if (!http_response_get_header(r, "Content-Type") && mfi->type)
	{
	  ret = snprintf(buf, sizeof(buf), "audio/%s", mfi->type);
	  if ((ret < 0) || (ret >= sizeof(buf)))
	    DPRINTF(E_LOG, L_HTTPD, "Content-Type too large for buffer, dropping\n");
	  else
	    http_response_add_header(r, "Content-Type", buf);
	}
    }

  st->evbuf = evbuffer_new();
  if (!st->evbuf)
    {
      DPRINTF(E_LOG, L_HTTPD, "Could not allocate an evbuffer for streaming\n");

      goto out_error;
    }

  ret = evbuffer_expand(st->evbuf, STREAM_CHUNK_SIZE);
  if (ret != 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Could not expand evbuffer for streaming\n");

      goto out_error;
    }

  st->id = mfi->id;
  st->start_offset = offset;
  st->stream_size = st->size;

  if ((offset == 0) && (end_offset == 0))
    {
      /* If we are not decoding, send the Content-Length. We don't do
       * that if we are decoding because we can only guesstimate the
       * size in this case and the error margin is unknown and variable.
       */
      if (!transcode)
	{
	  ret = snprintf(buf, sizeof(buf), "%" PRIi64, (int64_t)st->size);
	  if ((ret < 0) || (ret >= sizeof(buf)))
	    DPRINTF(E_LOG, L_HTTPD, "Content-Length too large for buffer, dropping\n");
	  else
	    http_response_add_header(r, "Content-Length", buf);
	}

      ret = http_response_set_status(r, HTTP_OK, "OK");
    }
  else
    {
      if (offset > 0)
	st->stream_size -= offset;
      if (end_offset > 0)
	st->stream_size -= (st->size - end_offset);

      DPRINTF(E_DBG, L_HTTPD, "Stream request with range %" PRIi64 "-%" PRIi64 "\n", offset, end_offset);

      ret = snprintf(buf, sizeof(buf), "bytes %" PRIi64 "-%" PRIi64 "/%" PRIi64,
		     offset, (end_offset) ? end_offset : (int64_t)st->size, (int64_t)st->size);
      if ((ret < 0) || (ret >= sizeof(buf)))
	DPRINTF(E_LOG, L_HTTPD, "Content-Range too large for buffer, dropping\n");
      else
	http_response_add_header(r, "Content-Range", buf);

      ret = snprintf(buf, sizeof(buf), "%" PRIi64, ((end_offset) ? end_offset + 1 : (int64_t)st->size) - offset);
      if ((ret < 0) || (ret >= sizeof(buf)))
	DPRINTF(E_LOG, L_HTTPD, "Content-Length too large for buffer, dropping\n");
      else
	http_response_add_header(r, "Content-Length", buf);

      ret = http_response_set_status(r, HTTP_PARTIAL_CONTENT, "Partial Content");
    }

  /* http_response_set_status() retval */
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Could not set status on streaming response\n");

      goto out_error;
    }

#ifdef HAVE_POSIX_FADVISE
  if (!transcode)
    {
      /* Hint the OS */
      posix_fadvise(st->fd, st->start_offset, st->stream_size, POSIX_FADV_WILLNEED);
      posix_fadvise(st->fd, st->start_offset, st->stream_size, POSIX_FADV_SEQUENTIAL);
      posix_fadvise(st->fd, st->start_offset, st->stream_size, POSIX_FADV_NOREUSE);
    }
#endif

  /* Get first chunk */
  if (transcode)
    ret = stream_get_chunk_xcode(st);
  else
    ret = stream_get_chunk_raw(st);

  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Could not obtain first chunk for streaming\n");

      goto out_error;
    }

  /* Empty response */
  if (EVBUFFER_LENGTH(st->evbuf) == 0)
    {
      DPRINTF(E_INFO, L_HTTPD, "Empty streaming response\n");

      ret = http_server_response_run(c, r);
      if (ret < 0)
	goto out_error;

      /* Nothing more to do */
      goto out_cleanup;
    }

  /* Start streaming */
  ret = http_server_response_run_chunked(c, r, st->evbuf, stream_chunk_cb, stream_chunk_free_cb, st);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Could not start chunked response for streaming\n");

      goto out_error;
    }

  DPRINTF(E_INFO, L_HTTPD, "Kicking off streaming for %s\n", mfi->path);

  free_mfi(mfi, 0);

  return 0;

 out_error:
  ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");

 out_cleanup:
  if (st->evbuf)
    evbuffer_free(st->evbuf);
  if (st->xcode)
    transcode_cleanup(st->xcode);
  if (st->buf)
    free(st->buf);
  if (st->fd > 0)
    close(st->fd);
 out_free_st:
  free(st);
 out_free_mfi:
  free_mfi(mfi, 0);

  return ret;
}

int
httpd_send_reply(struct http_connection *c, struct http_request *req, struct http_response *r, struct evbuffer *evbuf)
{
  unsigned char outbuf[128 * 1024];
  z_stream strm;
  struct evbuffer *gzbuf;
  const char *param;
  int flush;
  int zret;
  int ret;

  if (!evbuf || (EVBUFFER_LENGTH(evbuf) == 0))
    {
      DPRINTF(E_DBG, L_HTTPD, "Not gzipping body-less reply\n");

      goto no_gzip;
    }

  param = http_request_get_header(req, "Accept-Encoding");
  if (!param)
    {
      DPRINTF(E_DBG, L_HTTPD, "Not gzipping; no Accept-Encoding header\n");

      goto no_gzip;
    }
  else if (!strstr(param, "gzip") && !strstr(param, "*"))
    {
      DPRINTF(E_DBG, L_HTTPD, "Not gzipping; gzip not in Accept-Encoding (%s)\n", param);

      goto no_gzip;
    }

  gzbuf = evbuffer_new();
  if (!gzbuf)
    {
      DPRINTF(E_LOG, L_HTTPD, "Could not allocate evbuffer for gzipped reply\n");

      goto no_gzip;
    }

  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;

  /* Set up a gzip stream (the "+ 16" in 15 + 16), instead of a zlib stream (default) */
  zret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
  if (zret != Z_OK)
    {
      DPRINTF(E_DBG, L_HTTPD, "zlib setup failed: %s\n", zError(zret));

      goto out_fail_init;
    }

  strm.next_in = EVBUFFER_DATA(evbuf);
  strm.avail_in = EVBUFFER_LENGTH(evbuf);

  flush = Z_NO_FLUSH;

  /* 2 iterations: Z_NO_FLUSH until input is consumed, then Z_FINISH */
  for (;;)
    {
      do
	{
	  strm.next_out = outbuf;
	  strm.avail_out = sizeof(outbuf);

	  zret = deflate(&strm, flush);
	  if (zret == Z_STREAM_ERROR)
	    {
	      DPRINTF(E_LOG, L_HTTPD, "Could not deflate data: %s\n", strm.msg);

	      goto out_fail_gz;
	    }

	  ret = evbuffer_add(gzbuf, outbuf, sizeof(outbuf) - strm.avail_out);
	  if (ret < 0)
	    {
	      DPRINTF(E_LOG, L_HTTPD, "Out of memory adding gzipped data to evbuffer\n");

	      goto out_fail_gz;
	    }
	}
      while (strm.avail_out == 0);

      if (flush == Z_FINISH)
	break;

      flush = Z_FINISH;
    }

  if (zret != Z_STREAM_END)
    {
      DPRINTF(E_LOG, L_HTTPD, "Compressed data not finalized!\n");

      goto out_fail_gz;
    }

  deflateEnd(&strm);

  ret = http_response_add_header(r, "Content-Encoding", "gzip");
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Out of memory for Content-Encoding: gzip header, not gzipping\n");

      evbuffer_free(gzbuf);
      goto no_gzip;
    }

  http_response_set_body(r, gzbuf);
  evbuffer_free(evbuf);

  ret = http_server_response_run(c, r);
  if (ret < 0)
    return http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");

  return 0;

 out_fail_gz:
  deflateEnd(&strm);
 out_fail_init:
  evbuffer_free(gzbuf);

 no_gzip:
  http_response_set_body(r, evbuf);

  ret = http_server_response_run(c, r);
  if (ret < 0)
    return http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");

  return 0;
}

static int
path_is_legal(char *path)
{
  return strncmp(WEBFACE_ROOT, path, strlen(WEBFACE_ROOT));
}

static int
redirect_to_index(struct http_connection *c, struct http_response *r, char *uri)
{
  char buf[256];
  int slashed;
  int ret;

  slashed = (uri[strlen(uri) - 1] == '/');

  ret = snprintf(buf, sizeof(buf), "%s%sindex.html", uri, (slashed) ? "" : "/");
  if ((ret < 0) || (ret >= sizeof(buf)))
    {
      DPRINTF(E_LOG, L_HTTPD, "Redirection URL exceeds buffer length\n");

      return http_server_error_run(c, r, HTTP_NOT_FOUND, "Not Found");
    }

  ret = http_response_add_header(r, "Location", buf);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Out of memory for Location header\n");

      goto out_error;
    }

  ret = http_response_set_status(r, HTTP_MOVE_TEMP, "Moved");
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Out of memory for response reason\n");

      goto out_error;
    }

  ret = http_server_response_run(c, r);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Failed to run redirect response\n");

      goto out_error;
    }

  return 0;

 out_error:
  return http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
}

static int
serve_file(struct http_connection *c, struct http_request *req, struct http_response *r, char *uri)
{
  char path[PATH_MAX];
  char remote_host[NCONN_ADDRSTRLEN];
  char *ext;
  char *deref;
  char *ctype;
  char *passwd;
  struct evbuffer *evbuf;
  struct stat sb;
  int fd;
  int i;
  int ret;

  /* Check authentication */
  passwd = cfg_getstr(cfg_getsec(cfg, "general"), "admin_password");
  if (passwd)
    {
      DPRINTF(E_DBG, L_HTTPD, "Checking web interface authentication\n");

      ret = httpd_basic_auth(c, req, r, "admin", passwd, PACKAGE " web interface");
      switch (ret)
	{
	  case HTTP_OK:
	    DPRINTF(E_DBG, L_HTTPD, "Authentication successful\n");
	    break;

	  case -1:
	    /* Kill connection */
	    return -1;

	  default:
	    /* HTTP_UNAUTHORIZED or HTTP_INTERNAL_ERROR on error */
	    return 0;
	}
    }
  else
    {
      remote_host[0] = '\0';
      http_connection_get_remote_addr(c, remote_host);
      if ((strcmp(remote_host, "::1") != 0) &&
	  (strcmp(remote_host, "127.0.0.1") != 0))
	{
	  DPRINTF(E_LOG, L_HTTPD, "Remote web interface request denied; no password set\n");

	  return http_server_error_run(c, r, HTTP_FORBIDDEN, "Forbidden");
	}
    }

  ret = snprintf(path, sizeof(path), "%s%s", WEBFACE_ROOT, uri + 1); /* skip starting '/' */
  if ((ret < 0) || (ret >= sizeof(path)))
    {
      DPRINTF(E_LOG, L_HTTPD, "Request exceeds PATH_MAX: %s\n", uri);

      goto out_notfound;
    }

  ret = lstat(path, &sb);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Could not lstat() %s: %s\n", path, strerror(errno));

      goto out_notfound;
    }

  if (S_ISDIR(sb.st_mode))
    return redirect_to_index(c, r, uri);
  else if (S_ISLNK(sb.st_mode))
    {
      deref = m_realpath(path);
      if (!deref)
	{
	  DPRINTF(E_LOG, L_HTTPD, "Could not dereference %s: %s\n", path, strerror(errno));

	  goto out_notfound;
	}

      if (strlen(deref) + 1 > PATH_MAX)
	{
	  DPRINTF(E_LOG, L_HTTPD, "Dereferenced path exceeds PATH_MAX: %s\n", path);

	  free(deref);
	  goto out_notfound;
	}

      strcpy(path, deref);
      free(deref);

      ret = stat(path, &sb);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_HTTPD, "Could not stat() %s: %s\n", path, strerror(errno));

	  goto out_notfound;
	}

      if (S_ISDIR(sb.st_mode))
	return redirect_to_index(c, r, uri);
    }

  if (path_is_legal(path) != 0)
    return http_server_error_run(c, r, HTTP_FORBIDDEN, "Forbidden");

  fd = open(path, O_RDONLY);
  if (fd < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Could not open %s: %s\n", path, strerror(errno));

      goto out_notfound;
    }

  evbuf = evbuffer_new();
  if (!evbuf)
    {
      DPRINTF(E_LOG, L_HTTPD, "Could not create evbuffer\n");

      close(fd);
      goto out_unavail;
    }

  /* FIXME: this is broken, if we ever need to serve files here,
   * this must be fixed.
   */
  ret = evbuffer_read(evbuf, fd, sb.st_size);
  close(fd);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Could not read file into evbuffer\n");

      evbuffer_free(evbuf);
      goto out_unavail;
    }

  http_response_set_body(r, evbuf);

  ctype = "application/octet-stream";
  ext = strrchr(path, '.');
  if (ext)
    {
      for (i = 0; ext2ctype[i].ext; i++)
	{
	  if (strcmp(ext, ext2ctype[i].ext) == 0)
	    {
	      ctype = ext2ctype[i].ctype;
	      break;
	    }
	}
    }

  ret = http_response_add_header(r, "Content-Type", ctype);
  if (ret < 0)
    goto out_unavail;

  ret = http_response_set_status(r, HTTP_OK, "OK");
  if (ret < 0)
    goto out_unavail;

  ret = http_server_response_run(c, r);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Failed to serve file %s: could not run response\n", path);

      goto out_unavail;
    }

  return 0;

 out_unavail:
  return http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");

 out_notfound:
  return http_server_error_run(c, r, HTTP_NOT_FOUND, "Not Found");
}

static void
httpd_close_cb(struct http_server *srv, void *data)
{
  if (srv == http4)
    {
      DPRINTF(E_LOG, L_HTTPD, "v4 HTTP server failure!\n");
      http4 = NULL;
    }
  else
    {
      DPRINTF(E_LOG, L_HTTPD, "v6 HTTP server failure!\n");
      http6 = NULL;
    }

  http_server_free(srv);
}

/* Queue: c->queue (read queue) */
static int
httpd_cb(struct http_connection *c, struct http_request *req, struct http_response *r, void *data)
{
  const char *req_uri;
  char *uri;
  char *ptr;
  int ret;

  req_uri = http_request_get_uri(req);
  if (!req_uri)
    return redirect_to_index(c, r, "/");

  uri = strdup(req_uri);
  ptr = strchr(uri, '?');
  if (ptr)
    {
      DPRINTF(E_DBG, L_HTTPD, "Found query string\n");

      *ptr = '\0';
    }

  http_decode_uri(uri, URI_DECODE_NORMAL);

  /* Dispatch protocol-specific URIs */
  if (rsp_is_request(uri))
    {
      free(uri);

      return rsp_request(c, req, r);
    }
  else if (daap_is_request(uri))
    {
      free(uri);

      return daap_request(c, req, r);
    }
  else if (dacp_is_request(uri))
    {
      free(uri);

      return dacp_request(c, req, r);
    }

  DPRINTF(E_DBG, L_HTTPD, "HTTP request: %s\n", uri);

  /* Serve web interface files */
  ret = serve_file(c, req, r, uri);

  free(uri);
  return ret;
}

char *
httpd_fixup_uri(struct http_request *req)
{
  const char *ua;
  const char *uri;
  const char *u;
  const char *q;
  char *fixed;
  char *f;
  int len;

  uri = http_request_get_uri(req);
  if (!uri)
    return NULL;

  /* No query string, nothing to do */
  q = strchr(uri, '?');
  if (!q)
    return strdup(uri);

  ua = http_request_get_header(req, "User-Agent");
  if (!ua)
    return strdup(uri);

  if ((strncmp(ua, "iTunes", strlen("iTunes")) != 0)
      && (strncmp(ua, "Remote", strlen("Remote")) != 0)
      && (strncmp(ua, "Roku", strlen("Roku")) != 0))
    return strdup(uri);

  /* Reencode + as %2B and space as + in the query,
     which iTunes and Roku devices don't do */
  len = strlen(uri);

  u = q;
  while (*u)
    {
      if (*u == '+')
	len += 2;

      u++;
    }

  fixed = (char *)malloc(len + 1);
  if (!fixed)
    return NULL;

  strncpy(fixed, uri, q - uri);

  f = fixed + (q - uri);
  while (*q)
    {
      switch (*q)
	{
	  case '+':
	    *f = '%';
	    f++;
	    *f = '2';
	    f++;
	    *f = 'B';
	    break;

	  case ' ':
	    *f = '+';
	    break;

	  default:
	    *f = *q;
	    break;
	}

      q++;
      f++;
    }

  *f = '\0';

  return fixed;
}

static const char *http_reply_401 = "<html><head><title>401 Unauthorized</title></head><body>Authorization required</body></html>";

int
httpd_basic_auth(struct http_connection *c, struct http_request *req, struct http_response *r, char *user, char *passwd, char *realm)
{
  struct evbuffer *evbuf;
  char *header;
  const char *auth;
  char *authuser;
  char *authpwd;
  int len;
  int ret;

  auth = http_request_get_header(req, "Authorization");
  if (!auth)
    {
      DPRINTF(E_DBG, L_HTTPD, "No Authorization header\n");

      goto need_auth;
    }

  if (strncmp(auth, "Basic ", strlen("Basic ")) != 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Bad Authentication header\n");

      goto need_auth;
    }

  auth += strlen("Basic ");

  authuser = b64_decode(auth);
  if (!authuser)
    {
      DPRINTF(E_LOG, L_HTTPD, "Could not decode Authentication header\n");

      goto need_auth;
    }

  authpwd = strchr(authuser, ':');
  if (!authpwd)
    {
      DPRINTF(E_LOG, L_HTTPD, "Malformed Authentication header\n");

      free(authuser);
      goto need_auth;
    }

  *authpwd = '\0';
  authpwd++;

  if (user)
    {
      if (strcmp(user, authuser) != 0)
	{
	  DPRINTF(E_LOG, L_HTTPD, "Username mismatch\n");

	  free(authuser);
	  goto need_auth;
	}
    }

  if (strcmp(passwd, authpwd) != 0)
    {
      DPRINTF(E_LOG, L_HTTPD, "Bad password\n");

      free(authuser);
      goto need_auth;
    }

  free(authuser);

  return HTTP_OK;

 need_auth:
  len = strlen(realm) + strlen("Basic realm=") + 3;
  header = (char *)malloc(len);
  if (!header)
    goto out_error;

  ret = snprintf(header, len, "Basic realm=\"%s\"", realm);
  if ((ret < 0) || (ret >= len))
    goto out_error;

  ret = http_response_add_header(r, "WWW-Authenticate", header);
  free(header);
  if (ret < 0)
    goto out_error;

  ret = http_response_set_status(r, HTTP_UNAUTHORIZED, "Unauthorized");
  if (ret < 0)
    goto out_error;

  evbuf = evbuffer_new();
  if (!evbuf)
    goto out_error;

  evbuffer_add(evbuf, http_reply_401, strlen(http_reply_401));
  http_response_set_body(r, evbuf);

  ret = http_server_response_run(c, r);
  if (ret < 0)
    goto out_error;

  return HTTP_UNAUTHORIZED;

 out_error:
  ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
  if (ret < 0)
    return -1;

  return HTTP_INTERNAL_ERROR;
}

/* Thread: main */
int
httpd_init(void)
{
  unsigned short port;
  int v6enabled;
  int ret;

  port = cfg_getint(cfg_getsec(cfg, "library"), "port");
  v6enabled = cfg_getbool(cfg_getsec(cfg, "general"), "ipv6");

  http6 = NULL;

  http_group = dispatch_group_create();
  if (!http_group)
    {
      DPRINTF(E_FATAL, L_HTTPD, "Could not create dispatch group for HTTP servers\n");

      return -1;
    }

  http4 = http_server_new(L_HTTPD, http_group, "0.0.0.0", port, httpd_cb, httpd_close_cb);
  if (!http4)
    {
      DPRINTF(E_FATAL, L_HTTPD, "Could not create v4 HTTP server\n");

      goto http4_fail;
    }

  if (v6enabled)
    {
      http6 = http_server_new(L_HTTPD, http_group, "::", port, httpd_cb, httpd_close_cb);
      if (!http6)
	DPRINTF(E_WARN, L_HTTPD, "Could not create v6 HTTP server; that's OK\n");
    }

  ret = rsp_init();
  if (ret < 0)
    {
      DPRINTF(E_FATAL, L_HTTPD, "RSP protocol init failed\n");

      goto rsp_fail;
    }

  ret = daap_init();
  if (ret < 0)
    {
      DPRINTF(E_FATAL, L_HTTPD, "DAAP protocol init failed\n");

      goto daap_fail;
    }

  ret = dacp_init();
  if (ret < 0)
    {
      DPRINTF(E_FATAL, L_HTTPD, "DACP protocol init failed\n");

      goto dacp_fail;
    }

  ret = http_server_start(http4);
  if (ret < 0)
    {
      DPRINTF(E_FATAL, L_HTTPD, "Failed to start v4 HTTP server\n");

      goto start_fail;
    }

  if (!http6)
    return 0;

  ret = http_server_start(http6);
  if (ret < 0)
    {
      DPRINTF(E_WARN, L_HTTPD, "Failed to start v6 HTTP server; that's OK\n");

      http_server_free(http6);
      http6 = NULL;
    }

  return 0;

 start_fail:
  dacp_deinit();
 dacp_fail:
  daap_deinit();
 daap_fail:
  rsp_deinit();
 rsp_fail:
  if (http6)
    http_server_free(http6);
  http_server_free(http4);

  /* Wait for shutdown completion for both servers */
  ret = dispatch_group_wait(http_group, DISPATCH_TIME_FOREVER);
  if (ret != 0)
    DPRINTF(E_LOG, L_HTTPD, "Error waiting for dispatch group\n");
 http4_fail:
  dispatch_release(http_group);

  return -1;
}

/* Thread: main */
void
httpd_deinit(void)
{
  int ret;

  if (http6)
    http_server_free(http6);

  if (http4)
    http_server_free(http4);

  DPRINTF(E_INFO, L_HTTPD, "Waiting for HTTP servers to shut down...\n");

  ret = dispatch_group_wait(http_group, DISPATCH_TIME_FOREVER);
  dispatch_release(http_group);

  if (ret != 0)
    DPRINTF(E_LOG, L_HTTPD, "Error waiting for dispatch group\n");

  rsp_deinit();
  dacp_deinit();
  daap_deinit();
}
