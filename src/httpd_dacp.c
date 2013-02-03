/*
 * Copyright (C) 2010-2011 Julien BLACHE <jb@jblache.org>
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
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>

#include <dispatch/dispatch.h>

#include <tre/tre.h>

#include "evbuffer/evbuffer.h"
#include "logger.h"
#include "misc.h"
#include "conffile.h"
#include "artwork.h"
#include "http.h"
#include "httpd.h"
#include "httpd_dacp.h"
#include "dmap_common.h"
#include "db.h"
#include "player.h"


/* From httpd_daap.c */
struct daap_session;

int
daap_session_find(struct httpd_hdl *h, struct daap_session **s);


struct uri_map {
  regex_t preg;
  char *regexp;
  int (*handler)(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri);
};

struct dacp_update_request {
  struct http_connection *c;
  struct http_request *req;
  struct http_response *r;

  struct dacp_update_request *next;
};

typedef void (*dacp_propget)(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
typedef void (*dacp_propset)(const char *value, struct keyval *query);

struct dacp_prop_map {
  char *desc;
  dacp_propget propget;
  dacp_propset propset;
};


/* Forward - properties getters */
static void
dacp_propget_volume(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_volumecontrollable(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_playerstate(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_shufflestate(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_availableshufflestates(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_repeatstate(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_availablerepeatstates(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_nowplaying(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_playingtime(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);

static void
dacp_propget_fullscreenenabled(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_fullscreen(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_visualizerenabled(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_visualizer(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_itms_songid(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);
static void
dacp_propget_haschapterdata(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi);

/* Forward - properties setters */
static void
dacp_propset_volume(const char *value, struct keyval *query);
static void
dacp_propset_playingtime(const char *value, struct keyval *query);
static void
dacp_propset_shufflestate(const char *value, struct keyval *query);
static void
dacp_propset_repeatstate(const char *value, struct keyval *query);
static void
dacp_propset_userrating(const char *value, struct keyval *query);


/* gperf static hash, dacp_prop.gperf */
#include "dacp_prop_hash.c"


/* Play status update */
static int current_rev;
static dispatch_queue_t updates_sq;
static dispatch_source_t updates_src;
static struct dacp_update_request *update_requests;

/* Seek timer */
static dispatch_queue_t seek_sq;
static dispatch_source_t seek_timer;
static int seek_target;


/* DACP helpers */
static void
dacp_nowplaying(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
  char canp[16];

  if ((status->status == PLAY_STOPPED) || !mfi)
    return;

  memset(canp, 0, sizeof(canp));

  canp[3] = 1; /* 0-3 database ID */

  canp[4]  = (status->plid >> 24) & 0xff;
  canp[5]  = (status->plid >> 16) & 0xff;
  canp[6]  = (status->plid >> 8) & 0xff;
  canp[7]  = status->plid & 0xff;

  canp[8]  = (status->pos_pl >> 24) & 0xff; /* 8-11 position in playlist */
  canp[9]  = (status->pos_pl >> 16) & 0xff;
  canp[10] = (status->pos_pl >> 8) & 0xff;
  canp[11] = status->pos_pl & 0xff;

  canp[12] = (status->id >> 24) & 0xff; /* 12-15 track ID */
  canp[13] = (status->id >> 16) & 0xff;
  canp[14] = (status->id >> 8) & 0xff;
  canp[15] = status->id & 0xff;

  dmap_add_literal(evbuf, "canp", canp, sizeof(canp));

  dmap_add_string(evbuf, "cann", mfi->title);
  dmap_add_string(evbuf, "cana", mfi->artist);
  dmap_add_string(evbuf, "canl", mfi->album);
  dmap_add_string(evbuf, "cang", mfi->genre);
  dmap_add_long(evbuf, "asai", mfi->songalbumid);

  dmap_add_int(evbuf, "cmmk", 1);
}

static void
dacp_playingtime(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
  if ((status->status == PLAY_STOPPED) || !mfi)
    return;

  dmap_add_int(evbuf, "cant", mfi->song_length - status->pos_ms); /* Remaining time in ms */
  dmap_add_int(evbuf, "cast", mfi->song_length); /* Song length in ms */
}


/* Update requests helpers */
static int
make_playstatusupdate(struct evbuffer *evbuf)
{
  struct player_status status;
  struct media_file_info *mfi;
  struct evbuffer *psu;
  int ret;

  psu = evbuffer_new();
  if (!psu)
    {
      DPRINTF(E_LOG, L_DACP, "Could not allocate evbuffer for playstatusupdate\n");

      return -1;
    }

  player_get_status(&status);

  if (status.status != PLAY_STOPPED)
    {
      mfi = db_file_fetch_byid(status.id);
      if (!mfi)
	{
	  DPRINTF(E_LOG, L_DACP, "Could not fetch file id %d\n", status.id);

	  return -1;
	}
    }
  else
    mfi = NULL;

  dmap_add_int(psu, "mstt", 200);         /* 12 */

  dmap_add_int(psu, "cmsr", current_rev); /* 12 */

  dmap_add_char(psu, "cavc", 1);              /* 9 */ /* volume controllable */
  dmap_add_char(psu, "caps", status.status);  /* 9 */ /* play status, 2 = stopped, 3 = paused, 4 = playing */
  dmap_add_char(psu, "cash", status.shuffle); /* 9 */ /* shuffle, true/false */
  dmap_add_char(psu, "carp", status.repeat);  /* 9 */ /* repeat, 0 = off, 1 = repeat song, 2 = repeat (playlist) */

  dmap_add_int(psu, "caas", 2);           /* 12 */ /* available shuffle states */
  dmap_add_int(psu, "caar", 6);           /* 12 */ /* available repeat states */

  if (mfi)
    {
      dacp_nowplaying(psu, &status, mfi);
      dacp_playingtime(psu, &status, mfi);

      free_mfi(mfi, 0);
    }

  dmap_add_container(evbuf, "cmst", EVBUFFER_LENGTH(psu));    /* 8 + len */

  ret = evbuffer_add_buffer(evbuf, psu);
  evbuffer_free(psu);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Could not add status data to playstatusupdate reply\n");

      return -1;
    }

  return 0;
}

/* Queue: updates_sq */
static void
playstatus_update_cb(void *arg)
{
  struct dacp_update_request *ur;
  struct evbuffer *evbuf;
  struct evbuffer *update;
  int ret;

  if (!update_requests)
    {
      DPRINTF(E_DBG, L_DACP, "Playstatus updates: no clients\n");
      return;
    }
  else
    DPRINTF(E_DBG, L_DACP, "Playstatus updates: sending out updates\n");

  update = evbuffer_new();
  if (!update)
    {
      DPRINTF(E_LOG, L_DACP, "Could not allocate evbuffer for playstatusupdate data\n");

      return;
    }

  ret = db_pool_get();
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Could not acquire database connection; skipping playstatus update\n");

      goto out_free_update;
    }

  ret = make_playstatusupdate(update);

  db_pool_release();

  if (ret < 0)
    goto out_free_update;

  for (ur = update_requests; update_requests; ur = update_requests)
    {
      evbuf = evbuffer_new();
      if (!evbuf)
	{
	  DPRINTF(E_LOG, L_DACP, "Could not allocate evbuffer for playstatusupdate reply\n");

	  break;
	}

      ret = evbuffer_add(evbuf, EVBUFFER_DATA(update), EVBUFFER_LENGTH(update));
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DACP, "Out of memory for playstatus update\n");

	  evbuffer_free(evbuf);
	  break;
	}

      ret = http_response_set_status(ur->r, HTTP_OK, "OK");
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DACP, "Could not set response status for playstatus update\n");

	  evbuffer_free(evbuf);
	  break;
	}

      http_response_set_body(ur->r, evbuf);

      ret = http_server_response_thaw_and_run(ur->c, ur->r);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DACP, "Could not thaw and run response to playstatus update request\n");

	  http_server_kill_connection(ur->c);
	}

      update_requests = ur->next;
      free(ur);
    }

  current_rev++;

 out_free_update:
  evbuffer_free(update);
}

/* Queue: player */
static void
dacp_playstatus_update_handler(void)
{
  dispatch_source_merge_data(updates_src, 1);
}

/* Queue: updates_sq */
static void
update_free_cb_task(void *arg)
{
  struct dacp_update_request *ur;
  struct dacp_update_request *p;

  ur = (struct dacp_update_request *)arg;

  DPRINTF(E_DBG, L_DACP, "Update request: client closed connection\n");

  if (ur == update_requests)
    update_requests = ur->next;
  else
    {
      for (p = update_requests; p && (p->next != ur); p = p->next)
	;

      if (!p)
	{
	  DPRINTF(E_LOG, L_DACP, "WARNING: struct dacp_update_request not found in list; BUG!\n");
	  return;
	}

      p->next = ur->next;
    }

  free(ur);
}

static void
update_free_cb(void *data)
{
  DPRINTF(E_DBG, L_DACP, "Update request: connection closed\n");

  dispatch_sync_f(updates_sq, data, update_free_cb_task);
}


/* Properties getters */
static void
dacp_propget_volume(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
  dmap_add_int(evbuf, "cmvo", status->volume);
}

static void
dacp_propget_volumecontrollable(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
  dmap_add_char(evbuf, "cavc", 1);
}

static void
dacp_propget_playerstate(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
  dmap_add_char(evbuf, "caps", status->status);
}

static void
dacp_propget_shufflestate(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
  dmap_add_char(evbuf, "cash", status->shuffle);
}

static void
dacp_propget_availableshufflestates(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
  dmap_add_int(evbuf, "caas", 2);
}

static void
dacp_propget_repeatstate(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
  dmap_add_char(evbuf, "carp", status->repeat);
}

static void
dacp_propget_availablerepeatstates(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
  dmap_add_int(evbuf, "caar", 6);
}

static void
dacp_propget_nowplaying(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
  dacp_nowplaying(evbuf, status, mfi);
}

static void
dacp_propget_playingtime(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
  dacp_playingtime(evbuf, status, mfi);
}

static void
dacp_propget_fullscreenenabled(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
	// TODO
}

static void
dacp_propget_fullscreen(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
	// TODO
}

static void
dacp_propget_visualizerenabled(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
	// TODO
}

static void
dacp_propget_visualizer(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
	// TODO
}

static void
dacp_propget_itms_songid(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
	// TODO
}

static void
dacp_propget_haschapterdata(struct evbuffer *evbuf, struct player_status *status, struct media_file_info *mfi)
{
	// TODO
}


/* Properties setters */
static void
dacp_propset_volume(const char *value, struct keyval *query)
{
  const char *param;
  uint64_t id;
  int volume;
  int ret;

  ret = safe_atoi32(value, &volume);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "dmcp.volume argument doesn't convert to integer: %s\n", value);

      return;
    }

  param = keyval_get(query, "speaker-id");
  if (param)
    {
      ret = safe_atou64(param, &id);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DACP, "Invalid speaker ID in dmcp.volume request\n");

	  return;
	}

      player_volume_setrel_speaker(id, volume);
      return;
    }

  param = keyval_get(query, "include-speaker-id");
  if (param)
    {
      ret = safe_atou64(param, &id);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DACP, "Invalid speaker ID in dmcp.volume request\n");

	  return;
	}

      player_volume_setabs_speaker(id, volume);
      return;
    }

  player_volume_set(volume);
}

static void
seek_timer_cb(void *arg)
{
  int ret;

  dispatch_source_cancel(seek_timer);
  dispatch_release(seek_timer);
  seek_timer = NULL;

  DPRINTF(E_DBG, L_DACP, "Seek timer expired, target %d ms\n", seek_target);

  ret = player_playback_seek(seek_target);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Player failed to seek to %d ms\n", seek_target);

      return;
    }

  ret = player_playback_start(NULL);
  if (ret < 0)
    DPRINTF(E_LOG, L_DACP, "Player returned an error for start after seek\n");
}

static void
dacp_propset_playingtime(const char *value, struct keyval *query)
{
  int target;
  int ret;

  ret = safe_atoi32(value, &target);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "dacp.playingtime argument doesn't convert to integer: %s\n", value);

      return;
    }

  dispatch_async(seek_sq, ^{
      if (!seek_timer)
	{
	  seek_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, seek_sq);
	  if (!seek_timer)
	    {
	      DPRINTF(E_LOG, L_DACP, "Could not create dispatch source for seek timer\n");

	      return;
	    }

	  dispatch_source_set_event_handler_f(seek_timer, seek_timer_cb);
	}
      else
	dispatch_suspend(seek_timer);

      dispatch_source_set_timer(seek_timer,
				dispatch_time(DISPATCH_TIME_NOW, 200 * (NSEC_PER_SEC / 1000)),
				DISPATCH_TIME_FOREVER /* one-shot */, 0);

      seek_target = target;

      dispatch_resume(seek_timer);
    });
}

static void
dacp_propset_shufflestate(const char *value, struct keyval *query)
{
  int enable;
  int ret;

  ret = safe_atoi32(value, &enable);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "dacp.shufflestate argument doesn't convert to integer: %s\n", value);

      return;
    }

  player_shuffle_set(enable);
}

static void
dacp_propset_repeatstate(const char *value, struct keyval *query)
{
  int mode;
  int ret;

  ret = safe_atoi32(value, &mode);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "dacp.repeatstate argument doesn't convert to integer: %s\n", value);

      return;
    }

  player_repeat_set(mode);
}

static void
dacp_propset_userrating(const char *value, struct keyval *query)
{
  struct media_file_info *mfi;
  const char *param;
  uint32_t itemid;
  uint32_t rating;
  int ret;

  ret = safe_atou32(value, &rating);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "dacp.userrating argument doesn't convert to integer: %s\n", value);

      return;
    }

  param = keyval_get(query, "item-spec");
  if (!param)
    {
      DPRINTF(E_LOG, L_DACP, "Missing item-spec parameter in dacp.userrating query\n");

      return;
    }

  param = strchr(param, ':');
  if (!param)
    {
      DPRINTF(E_LOG, L_DACP, "Malformed item-spec parameter in dacp.userrating query\n");

      return;
    }

  param++;
  ret = safe_hextou32(param, &itemid);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Couldn't convert item-spec to an integer in dacp.userrating (%s)\n", param);

      return;
    }

  mfi = db_file_fetch_byid(itemid);
  if (!mfi)
    {
      DPRINTF(E_LOG, L_DACP, "Could not fetch file id %d\n", itemid);

      return;
    }

  mfi->rating = rating;

  /* We're not touching any string field in mfi, so it's safe to
   * skip unicode_fixup_mfi() before the update
   */
  db_file_update(mfi);

  free_mfi(mfi, 0);
}


static int
dacp_reply_ctrlint(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  int ret;

  dmap_add_container(evbuf, "caci", 127); /* 8 + len */
  dmap_add_int(evbuf, "mstt", 200);       /* 12 */
  dmap_add_char(evbuf, "muty", 0);        /* 9 */
  dmap_add_int(evbuf, "mtco", 1);         /* 12 */
  dmap_add_int(evbuf, "mrco", 1);         /* 12 */
  dmap_add_container(evbuf, "mlcl", 125); /* 8 + len */
  dmap_add_container(evbuf, "mlit", 117); /* 8 + len */
  dmap_add_int(evbuf, "miid", 1);         /* 12 */ /* Database ID */
  dmap_add_char(evbuf, "cmik", 1);        /* 9 */

  dmap_add_int(evbuf, "cmpr", (2 << 16 | 1)); /* 12 */
  dmap_add_int(evbuf, "capr", (2 << 16 | 2)); /* 12 */

  dmap_add_char(evbuf, "cmsp", 1);        /* 9 */
  dmap_add_char(evbuf, "aeFR", 0x64);     /* 9 */
  dmap_add_char(evbuf, "cmsv", 1);        /* 9 */
  dmap_add_char(evbuf, "cass", 1);        /* 9 */
  dmap_add_char(evbuf, "caov", 1);        /* 9 */
  dmap_add_char(evbuf, "casu", 1);        /* 9 */
  dmap_add_char(evbuf, "ceSG", 1);        /* 9 */
  dmap_add_char(evbuf, "cmrl", 1);        /* 9 */

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    {
      evbuffer_free(evbuf);

      return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");
    }

  return httpd_send_reply(h->c, h->req, h->r, evbuf);
}

static int
dacp_reply_cue_play(struct httpd_hdl *h, struct evbuffer *evbuf)
{
  struct player_status status;
  struct player_source *ps;
  const char *sort;
  const char *cuequery;
  const char *param;
  uint32_t id;
  int clear;
  int ret;

  /* /cue?command=play&query=...&sort=...&index=N */

  param = keyval_get(h->query, "clear-first");
  if (param)
    {
      ret = safe_atoi32(param, &clear);
      if (ret < 0)
	DPRINTF(E_LOG, L_DACP, "Invalid clear-first value in cue request\n");
      else if (clear)
	{
	  player_playback_stop();

	  player_queue_clear();
	}
    }

  cuequery = keyval_get(h->query, "query");
  if (cuequery)
    {
      sort = keyval_get(h->query, "sort");

      ps = player_queue_make_daap(cuequery, sort);
      if (!ps)
	{
	  DPRINTF(E_LOG, L_DACP, "Could not build song queue\n");

	  evbuffer_free(evbuf);
	  return dmap_send_error(h, "cacr", "Could not build song queue");
	}

      player_queue_add(ps);
    }
  else
    {
      player_get_status(&status);

      if (status.status != PLAY_STOPPED)
	player_playback_stop();
    }

  param = keyval_get(h->query, "dacp.shufflestate");
  if (param)
    dacp_propset_shufflestate(param, NULL);

  id = 0;
  param = keyval_get(h->query, "index");
  if (param)
    {
      ret = safe_atou32(param, &id);
      if (ret < 0)
	DPRINTF(E_LOG, L_DACP, "Invalid index (%s) in cue request\n", param);
    }

  ret = player_playback_start(&id);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Could not start playback\n");

      evbuffer_free(evbuf);
      return dmap_send_error(h, "cacr", "Playback failed to start");
    }

  dmap_add_container(evbuf, "cacr", 24); /* 8 + len */
  dmap_add_int(evbuf, "mstt", 200);      /* 12 */
  dmap_add_int(evbuf, "miid", id);       /* 12 */

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");

  return httpd_send_reply(h->c, h->req, h->r, evbuf);
}

static int
dacp_reply_cue_clear(struct httpd_hdl *h, struct evbuffer *evbuf)
{
  int ret;

  /* /cue?command=clear */

  player_playback_stop();

  player_queue_clear();

  dmap_add_container(evbuf, "cacr", 24); /* 8 + len */
  dmap_add_int(evbuf, "mstt", 200);      /* 12 */
  dmap_add_int(evbuf, "miid", 0);        /* 12 */

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");

  return httpd_send_reply(h->c, h->req, h->r, evbuf);
}

static int
dacp_reply_cue(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  const char *param;
  int ret;

  ret = daap_session_find(h, &s);
  if (!s)
    {
      evbuffer_free(evbuf);
      return ret;
    }

  param = keyval_get(h->query, "command");
  if (!param)
    {
      DPRINTF(E_DBG, L_DACP, "No command in cue request\n");

      evbuffer_free(evbuf);
      return dmap_send_error(h, "cacr", "No command in cue request");
    }

  if (strcmp(param, "clear") == 0)
    return dacp_reply_cue_clear(h, evbuf);
  else if (strcmp(param, "play") == 0)
    return dacp_reply_cue_play(h, evbuf);

  DPRINTF(E_LOG, L_DACP, "Unknown cue command %s\n", param);

  evbuffer_free(evbuf);

  return dmap_send_error(h, "cacr", "Unknown command in cue request");
}

static int
dacp_reply_playspec(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct player_status status;
  struct player_source *ps;
  struct daap_session *s;
  const char *param;
  const char *shuffle;
  uint32_t plid;
  uint32_t id;
  int ret;

  /* /ctrl-int/1/playspec?database-spec='dmap.persistentid:0x1'&container-spec='dmap.persistentid:0x5'&container-item-spec='dmap.containeritemid:0x9'
   * With our DAAP implementation, container-spec is the playlist ID and container-item-spec is the song ID
   */

  evbuffer_free(evbuf);

  ret = daap_session_find(h, &s);
  if (!s)
    return ret;

  /* Check for shuffle */
  shuffle = keyval_get(h->query, "dacp.shufflestate");

  /* Playlist ID */
  param = keyval_get(h->query, "container-spec");
  if (!param)
    {
      DPRINTF(E_LOG, L_DACP, "No container-spec in playspec request\n");

      goto out_error;
    }

  param = strchr(param, ':');
  if (!param)
    {
      DPRINTF(E_LOG, L_DACP, "Malformed container-spec parameter in playspec request\n");

      goto out_error;
    }
  param++;

  ret = safe_hextou32(param, &plid);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Couldn't convert container-spec to an integer in playspec (%s)\n", param);

      goto out_error;
    }

  if (!shuffle)
    {
      /* Start song ID */
      param = keyval_get(h->query, "container-item-spec");
      if (!param)
	{
	  DPRINTF(E_LOG, L_DACP, "No container-item-spec in playspec request\n");

	  goto out_error;
	}

      param = strchr(param, ':');
      if (!param)
	{
	  DPRINTF(E_LOG, L_DACP, "Malformed container-item-spec parameter in playspec request\n");

	  goto out_error;
	}
      param++;

      ret = safe_hextou32(param, &id);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DACP, "Couldn't convert container-item-spec to an integer in playspec (%s)\n", param);

	  goto out_error;
	}
    }
  else
    id = 0;

  DPRINTF(E_DBG, L_DACP, "Playspec request for playlist %d, start song id %d%s\n", plid, id, (shuffle) ? ", shuffle" : "");

  ps = player_queue_make_pl(plid, &id);
  if (!ps)
    {
      DPRINTF(E_LOG, L_DACP, "Could not build song queue from playlist %d\n", plid);

      goto out_error;
    }

  DPRINTF(E_DBG, L_DACP, "Playspec start song index is %d\n", id);

  player_get_status(&status);

  if (status.status != PLAY_STOPPED)
    player_playback_stop();

  player_queue_clear();
  player_queue_add(ps);
  player_queue_plid(plid);

  if (shuffle)
    dacp_propset_shufflestate(shuffle, NULL);

  ret = player_playback_start(&id);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Could not start playback\n");

      goto out_error;
    }

  /* 204 No Content is the canonical reply */
  ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "No Content");
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
dacp_reply_pause(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  int ret;

  evbuffer_free(evbuf);

  ret = daap_session_find(h, &s);
  if (!s)
    return ret;

  player_playback_pause();

  /* 204 No Content is the canonical reply */
  ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "No Content");
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
dacp_reply_playpause(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  int ret;

  evbuffer_free(evbuf);

  ret = daap_session_find(h, &s);
  if (!s)
    return ret;

  ret = player_playback_start(NULL);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Player returned an error for start after pause\n");

      goto out_error;
    }

  /* 204 No Content is the canonical reply */
  ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "No Content");
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
dacp_reply_nextitem(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  int ret;

  evbuffer_free(evbuf);

  ret = daap_session_find(h, &s);
  if (!s)
    return ret;

  ret = player_playback_next();
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Player returned an error for nextitem\n");

      goto out_error;
    }

  ret = player_playback_start(NULL);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Player returned an error for start after nextitem\n");

      goto out_error;
    }

  /* 204 No Content is the canonical reply */
  ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "No Content");
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
dacp_reply_previtem(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  int ret;

  evbuffer_free(evbuf);

  ret = daap_session_find(h, &s);
  if (!s)
    return ret;

  ret = player_playback_prev();
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Player returned an error for previtem\n");

      goto out_error;
    }

  ret = player_playback_start(NULL);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Player returned an error for start after previtem\n");

      goto out_error;
    }

  /* 204 No Content is the canonical reply */
  ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "No Content");
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
dacp_reply_beginff(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  int ret;

  evbuffer_free(evbuf);

  ret = daap_session_find(h, &s);
  if (!s)
    return ret;

  /* TODO */

  /* 204 No Content is the canonical reply */
  ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "No Content");
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
dacp_reply_beginrew(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  int ret;

  evbuffer_free(evbuf);

  ret = daap_session_find(h, &s);
  if (!s)
    return ret;

  /* TODO */

  /* 204 No Content is the canonical reply */
  ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "No Content");
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
dacp_reply_playresume(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  int ret;

  ret = daap_session_find(h, &s);
  if (!s)
    return ret;

  /* TODO */

  /* 204 No Content is the canonical reply */
  ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "No Content");
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
dacp_reply_playstatusupdate(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  struct dacp_update_request *ur;
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
      DPRINTF(E_LOG, L_DACP, "Missing revision-number in update request\n");

      return dmap_send_error(h, "cmst", "Invalid request");
    }

  ret = safe_atoi32(param, &reqd_rev);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Parameter revision-number not an integer\n");

      return dmap_send_error(h, "cmst", "Invalid request");
    }

  if (reqd_rev == 1)
    {
      ret = make_playstatusupdate(evbuf);
      if (ret < 0)
	{
	  evbuffer_free(evbuf);

	  return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");
	}

      ret = http_response_set_status(h->r, HTTP_OK, "OK");
      if (ret < 0)
	{
	  evbuffer_free(evbuf);

	  return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");
	}

      return httpd_send_reply(h->c, h->req, h->r, evbuf);
    }

  evbuffer_free(evbuf);

  ur = (struct dacp_update_request *)malloc(sizeof(struct dacp_update_request));
  if (!ur)
    {
      DPRINTF(E_LOG, L_DACP, "Out of memory for update request\n");

      return dmap_send_error(h, "cmst", "Out of memory");
    }

  /* Freeze the request */
  http_server_response_freeze(h->c, h->r, update_free_cb, ur);

  ur->c = h->c;
  ur->req = h->req;
  ur->r = h->r;

  dispatch_sync(updates_sq, ^{
		  ur->next = update_requests;
		  update_requests = ur;
		});

  return 0;
}

static int
dacp_reply_nowplayingartwork(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  char clen[32];
  struct daap_session *s;
  const char *param;
  char *ctype;
  uint32_t id;
  int max_w;
  int max_h;
  int ret;

  ret = daap_session_find(h, &s);
  if (!s)
    {
      evbuffer_free(evbuf);
      return ret;
    }

  param = keyval_get(h->query, "mw");
  if (!param)
    {
      DPRINTF(E_LOG, L_DACP, "Request for artwork without mw parameter\n");

      goto bad_request;
    }

  ret = safe_atoi32(param, &max_w);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Could not convert mw parameter to integer\n");

      goto bad_request;
    }

  param = keyval_get(h->query, "mh");
  if (!param)
    {
      DPRINTF(E_LOG, L_DACP, "Request for artwork without mh parameter\n");

      goto bad_request;
    }

  ret = safe_atoi32(param, &max_h);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Could not convert mh parameter to integer\n");

      goto bad_request;
    }

  ret = player_now_playing(&id);
  if (ret < 0)
    goto no_artwork;

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

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    goto out_error;

  /* No gzip compression for artwork */
  ret = http_server_response_run(h->c, h->r);
  if (ret < 0)
    goto out_error;

  return 0;

 bad_request:
  evbuffer_free(evbuf);
  return http_server_error_run(h->c, h->r, HTTP_BAD_REQUEST, "Bad Request");

 no_artwork:
  evbuffer_free(evbuf);
  return http_server_error_run(h->c, h->r, HTTP_NOT_FOUND, "Not Found");

 out_error:
  return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");
}

static int
dacp_reply_getproperty(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct player_status status;
  struct daap_session *s;
  const struct dacp_prop_map *dpm;
  struct media_file_info *mfi;
  struct evbuffer *proplist;
  const char *param;
  char *ptr;
  char *prop;
  char *propstr;
  int ret;

  ret = daap_session_find(h, &s);
  if (!s)
    goto out_free_evbuf;

  param = keyval_get(h->query, "properties");
  if (!param)
    {
      DPRINTF(E_WARN, L_DACP, "Invalid DACP getproperty request, no properties\n");

      ret = dmap_send_error(h, "cmgt", "Invalid request");
      goto out_free_evbuf;
    }

  propstr = strdup(param);
  if (!propstr)
    {
      DPRINTF(E_LOG, L_DACP, "Could not duplicate properties parameter; out of memory\n");

      ret = dmap_send_error(h, "cmgt", "Out of memory");
      goto out_free_evbuf;
    }

  proplist = evbuffer_new();
  if (!proplist)
    {
      DPRINTF(E_LOG, L_DACP, "Could not allocate evbuffer for properties list\n");

      ret = dmap_send_error(h, "cmgt", "Out of memory");
      goto out_free_propstr;
    }

  player_get_status(&status);

  if (status.status != PLAY_STOPPED)
    {
      mfi = db_file_fetch_byid(status.id);
      if (!mfi)
	{
	  DPRINTF(E_LOG, L_DACP, "Could not fetch file id %d\n", status.id);

	  ret = dmap_send_error(h, "cmgt", "Server error");
	  goto out_free_proplist;
	}
    }
  else
    mfi = NULL;

  prop = strtok_r(propstr, ",", &ptr);
  while (prop)
    {
      dpm = dacp_find_prop(prop, strlen(prop));
      if (dpm)
	{
	  if (dpm->propget)
	    dpm->propget(proplist, &status, mfi);
	  else
	    DPRINTF(E_WARN, L_DACP, "No getter method for DACP property %s\n", prop);
	}
      else
	DPRINTF(E_LOG, L_DACP, "Could not find requested property '%s'\n", prop);

      prop = strtok_r(NULL, ",", &ptr);
    }

  free(propstr);

  if (mfi)
    free_mfi(mfi, 0);

  dmap_add_container(evbuf, "cmgt", 12 + EVBUFFER_LENGTH(proplist)); /* 8 + len */
  dmap_add_int(evbuf, "mstt", 200);      /* 12 */

  ret = evbuffer_add_buffer(evbuf, proplist);
  evbuffer_free(proplist);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Could not add properties to getproperty reply\n");

      ret = dmap_send_error(h, "cmgt", "Out of memory");
      goto out_free_evbuf;
    }

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    {
      ret = dmap_send_error(h, "cmgt", "Server error");
      goto out_free_evbuf;
    }

  return httpd_send_reply(h->c, h->req, h->r, evbuf);

 out_free_proplist:
  evbuffer_free(proplist);
 out_free_propstr:
  free(propstr);
 out_free_evbuf:
  evbuffer_free(evbuf);

  return ret;
}

static int
dacp_reply_setproperty(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  const struct dacp_prop_map *dpm;
  struct onekeyval *okv;
  int ret;

  evbuffer_free(evbuf);

  ret = daap_session_find(h, &s);
  if (!s)
    return ret;

  /* Known properties:
   * dacp.shufflestate 0/1
   * dacp.repeatstate  0/1/2
   * dacp.playingtime  seek to time in ms
   * dmcp.volume       0-100, float
   */

  /* /ctrl-int/1/setproperty?dacp.shufflestate=1&session-id=100 */

  for (okv = h->query->head; okv; okv = okv->next)
    {
      dpm = dacp_find_prop(okv->name, strlen(okv->name));
      if (!dpm)
	{
	  DPRINTF(E_SPAM, L_DACP, "Unknown DACP property %s\n", okv->name);
	  continue;
	}

      if (dpm->propset)
	dpm->propset(okv->value, h->query);
      else
	DPRINTF(E_WARN, L_DACP, "No setter method for DACP property %s\n", dpm->desc);
    }

  /* 204 No Content is the canonical reply */
  ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "No Content");
  if (ret < 0)
    goto out_error;

  ret = http_server_response_run(h->c, h->r);
  if (ret < 0)
    goto out_error;

  return 0;

 out_error:
  return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");
}

static void
speaker_enum_cb(uint64_t id, const char *name, int relvol, struct spk_flags flags, void *arg)
{
  struct evbuffer *evbuf;
  int len;

  evbuf = (struct evbuffer *)arg;

  len = 8 + strlen(name) + 28;
  if (flags.selected)
    len += 9;
  if (flags.has_password)
    len += 9;
  if (flags.has_video)
    len += 9;

  dmap_add_container(evbuf, "mdcl", len); /* 8 + len */
  if (flags.selected)
    dmap_add_char(evbuf, "caia", 1);      /* 9 */
  if (flags.has_password)
    dmap_add_char(evbuf, "cahp", 1);      /* 9 */
  if (flags.has_video)
    dmap_add_char(evbuf, "caiv", 1);      /* 9 */
  dmap_add_string(evbuf, "minm", name);   /* 8 + len */
  dmap_add_long(evbuf, "msma", id);       /* 16 */

  dmap_add_int(evbuf, "cmvo", relvol);    /* 12 */
}

static int
dacp_reply_getspeakers(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  struct evbuffer *spklist;
  int ret;

  ret = daap_session_find(h, &s);
  if (!s)
    goto out;

  spklist = evbuffer_new();
  if (!spklist)
    {
      DPRINTF(E_LOG, L_DACP, "Could not create evbuffer for speaker list\n");

      ret = dmap_send_error(h, "casp", "Out of memory");
      goto out;
    }

  player_speaker_enumerate(speaker_enum_cb, spklist);

  dmap_add_container(evbuf, "casp", 12 + EVBUFFER_LENGTH(spklist)); /* 8 + len */
  dmap_add_int(evbuf, "mstt", 200); /* 12 */

  evbuffer_add_buffer(evbuf, spklist);

  evbuffer_free(spklist);

  ret = http_response_set_status(h->r, HTTP_OK, "OK");
  if (ret < 0)
    {
      ret = dmap_send_error(h, "casp", "Server error");
      goto out;
    }

  return httpd_send_reply(h->c, h->req, h->r, evbuf);

 out:
  evbuffer_free(evbuf);

  return ret;
}

static int
dacp_reply_setspeakers(struct httpd_hdl *h, struct evbuffer *evbuf, char **uri)
{
  struct daap_session *s;
  const char *param;
  const char *ptr;
  uint64_t *ids;
  int nspk;
  int i;
  int ret;

  evbuffer_free(evbuf);

  ret = daap_session_find(h, &s);
  if (!s)
    return ret;

  param = keyval_get(h->query, "speaker-id");
  if (!param)
    {
      DPRINTF(E_LOG, L_DACP, "Missing speaker-id parameter in DACP setspeakers request\n");

      return http_server_error_run(h->c, h->r, HTTP_BAD_REQUEST, "Bad Request");
    }

  if (strlen(param) == 0)
    {
      ids = NULL;
      goto fastpath;
    }

  nspk = 1;
  ptr = param;
  while ((ptr = strchr(ptr + 1, ',')))
    nspk++;

  ids = (uint64_t *)malloc((nspk + 1) * sizeof(uint64_t));
  if (!ids)
    {
      DPRINTF(E_LOG, L_DACP, "Out of memory for speaker ids\n");

      goto out_error;
    }

  param--;
  i = 1;
  do
    {
      param++;
      ret = safe_hextou64(param, &ids[i]);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DACP, "Invalid speaker id in request: %s\n", param);

	  nspk--;
	  continue;
	}

      i++;
    }
  while ((param = strchr(param + 1, ',')));

  ids[0] = nspk;

 fastpath:
  ret = player_speaker_set(ids);

  if (ids)
    free(ids);

  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Speakers de/activation failed!\n");

      /* Password problem */
      if (ret == -2)
	{
	  ret = http_response_set_status(h->r, 902, "");
	  if (ret < 0)
	    goto out_error;
	}
      else
	goto out_error;
    }
  else
    {
      /* 204 No Content is the canonical reply */
      ret = http_response_set_status(h->r, HTTP_NO_CONTENT, "No Content");
      if (ret < 0)
	goto out_error;
    }

  ret = http_server_response_run(h->c, h->r);
  if (ret < 0)
    goto out_error;

  return 0;

 out_error:
  return http_server_error_run(h->c, h->r, HTTP_INTERNAL_ERROR, "Internal Server Error");
}


static struct uri_map dacp_handlers[] =
  {
    {
      .regexp = "^/ctrl-int$",
      .handler = dacp_reply_ctrlint
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/cue$",
      .handler = dacp_reply_cue
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/playspec$",
      .handler = dacp_reply_playspec
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/pause$",
      .handler = dacp_reply_pause
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/playpause$",
      .handler = dacp_reply_playpause
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/nextitem$",
      .handler = dacp_reply_nextitem
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/previtem$",
      .handler = dacp_reply_previtem
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/beginff$",
      .handler = dacp_reply_beginff
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/beginrew$",
      .handler = dacp_reply_beginrew
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/playresume$",
      .handler = dacp_reply_playresume
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/playstatusupdate$",
      .handler = dacp_reply_playstatusupdate
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/nowplayingartwork$",
      .handler = dacp_reply_nowplayingartwork
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/getproperty$",
      .handler = dacp_reply_getproperty
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/setproperty$",
      .handler = dacp_reply_setproperty
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/getspeakers$",
      .handler = dacp_reply_getspeakers
    },
    {
      .regexp = "^/ctrl-int/[[:digit:]]+/setspeakers$",
      .handler = dacp_reply_setspeakers
    },
    {
      .regexp = NULL,
      .handler = NULL
    }
  };

int
dacp_request(struct http_connection *c, struct http_request *req, struct http_response *r)
{
  struct httpd_hdl hdl;
  struct keyval query;
  char *full_uri;
  char *uri;
  char *ptr;
  char *uri_parts[7];
  struct evbuffer *evbuf;
  int handler;
  int ret;
  int i;

  memset(&query, 0, sizeof(struct keyval));
  memset(&hdl, 0, sizeof(struct httpd_hdl));

  full_uri = httpd_fixup_uri(req);
  if (!full_uri)
    return http_server_error_run(c, r, HTTP_BAD_REQUEST, "Bad Request");

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

  DPRINTF(E_DBG, L_DACP, "DACP request: %s\n", full_uri);

  handler = -1;
  for (i = 0; dacp_handlers[i].handler; i++)
    {
      ret = tre_regexec(&dacp_handlers[i].preg, uri, 0, NULL, 0);
      if (ret == 0)
        {
          handler = i;
          break;
        }
    }

  if (handler < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Unrecognized DACP request\n");

      ret = http_server_error_run(c, r, HTTP_BAD_REQUEST, "Bad Request");
      goto out;
    }

  /* DACP has no HTTP authentication - Remote is identified by its pairing-guid */

  memset(uri_parts, 0, sizeof(uri_parts));

  uri_parts[0] = strtok_r(uri, "/", &ptr);
  for (i = 1; (i < sizeof(uri_parts) / sizeof(uri_parts[0])) && uri_parts[i - 1]; i++)
    {
      uri_parts[i] = strtok_r(NULL, "/", &ptr);
    }

  if (!uri_parts[0] || uri_parts[i - 1] || (i < 2))
    {
      DPRINTF(E_LOG, L_DACP, "DACP URI has too many/few components (%d)\n", (uri_parts[0]) ? i : 0);

      ret = http_server_error_run(c, r, HTTP_BAD_REQUEST, "Bad Request");
      goto out;
    }

  ret = http_parse_query_string(full_uri, &query);
  if (ret < 0)
    {
      ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
      goto out;
    }

  ret = http_response_add_header(r, "DAAP-Server", PACKAGE "/" VERSION);
  if (ret < 0)
    {
      ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
      goto out_clear_query;
    }

  /* Content-Type for all DACP replies; can be overriden as needed */
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
      DPRINTF(E_LOG, L_DACP, "Could not allocate evbuffer for DACP reply\n");

      ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
      goto out_clear_query;
    }

  ret = db_pool_get();
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DACP, "Could not acquire database connection\n");

      evbuffer_free(evbuf);

      ret = http_server_error_run(c, r, HTTP_INTERNAL_ERROR, "Internal Server Error");
      goto out_clear_query;
    }

  hdl.c = c;
  hdl.req = req;
  hdl.r = r;
  hdl.query = &query;

  /* Freeze playstatus updates to avoid sending out updates for
   * transient statuses that could confuse Remote during DACP operations
   */
  dispatch_suspend(updates_src);

  ret = dacp_handlers[handler].handler(&hdl, evbuf, uri_parts);

  /* Thaw playstatus updates */
  dispatch_resume(updates_src);

  db_pool_release();

 out_clear_query:
  keyval_clear(&query);
 out:
  free(uri);
  free(full_uri);

  return ret;
}

int
dacp_is_request(char *uri)
{
  if (strncmp(uri, "/ctrl-int/", strlen("/ctrl-int/")) == 0)
    return 1;
  if (strcmp(uri, "/ctrl-int") == 0)
    return 1;

  return 0;
}


int
dacp_init(void)
{
  char buf[64];
  int i;
  int ret;

  seek_timer = NULL;

  current_rev = 2;
  update_requests = NULL;

  updates_sq = dispatch_queue_create("org.forked-daapd.dacp.updates", NULL);
  if (!updates_sq)
    {
      DPRINTF(E_FATAL, L_DACP, "Could not create dispatch queue for DACP update requests\n");

      return -1;
    }

  seek_sq = dispatch_queue_create("org.forked-daapd.dacp.seek", NULL);
  if (!seek_sq)
    {
      DPRINTF(E_FATAL, L_DACP, "Could not create dispatch queue for DACP seek handling\n");

      goto seek_sq_fail;
    }

  updates_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD, 0, 0, updates_sq);
  if (!updates_src)
    {
      DPRINTF(E_FATAL, L_DACP, "Could not create dispatch source for playstatus updates\n");

      goto updates_src_fail;
    }

  dispatch_source_set_event_handler_f(updates_src, playstatus_update_cb);

  for (i = 0; dacp_handlers[i].handler; i++)
    {
      ret = tre_regcomp(&dacp_handlers[i].preg, dacp_handlers[i].regexp, REG_EXTENDED | REG_NOSUB);
      if (ret != 0)
        {
          tre_regerror(ret, &dacp_handlers[i].preg, buf, sizeof(buf));

          DPRINTF(E_FATAL, L_DACP, "DACP init failed; regexp error: %s\n", buf);
	  goto regexp_fail;
        }
    }

  player_set_update_handler(dacp_playstatus_update_handler);

  dispatch_resume(updates_src);

  return 0;

 regexp_fail:
  dispatch_resume(updates_src);
  dispatch_source_cancel(updates_src);
  dispatch_release(updates_src);
 updates_src_fail:
  dispatch_release(seek_sq);
 seek_sq_fail:
  dispatch_release(updates_sq);

  return -1;
}

void
dacp_deinit(void)
{
  int i;

  player_set_update_handler(NULL);

  for (i = 0; dacp_handlers[i].handler; i++)
    tre_regfree(&dacp_handlers[i].preg);

  dispatch_source_cancel(updates_src);
  dispatch_release(updates_src);
  dispatch_release(updates_sq);

  dispatch_sync(seek_sq, ^{
      if (!seek_timer)
	return;

      dispatch_source_cancel(seek_timer);
      dispatch_release(seek_timer);
    });
  dispatch_release(seek_sq);

  /* Pending update requests are removed during HTTP server shutdown */
}
