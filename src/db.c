/*
 * Copyright (C) 2009-2011 Julien BLACHE <jb@jblache.org>
 * Copyright (C) 2010 Kai Elwert <elwertk@googlemail.com>
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
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>

#include <pthread.h>

#include <dispatch/dispatch.h>

#include <sqlite3.h>

#include "conffile.h"
#include "logger.h"
#include "misc.h"
#include "db.h"


#define STR(x) ((x) ? (x) : "")

/* Inotify cookies are uint32_t */
#define INOTIFY_FAKE_COOKIE ((int64_t)1 << 32)

enum group_type {
  G_ALBUMS = 1,
};

#define DB_POOL_MIN_SIZE 4
#define DB_POOL_MIN_FREE 2
#define DB_POOL_MAX_AGE  (5 * 60)
#define DB_POOL_MAX_AGE_NSEC (DB_POOL_MAX_AGE * NSEC_PER_SEC)

struct db_pool_hdl {
  sqlite3 *hdl;

  time_t last;

  struct db_pool_hdl *next;
  struct db_pool_hdl *saved;
};

struct db_unlock {
  int proceed;
  pthread_cond_t cond;
  pthread_mutex_t lck;
};

#define DB_TYPE_CHAR    1
#define DB_TYPE_INT     2
#define DB_TYPE_INT64   3
#define DB_TYPE_STRING  4

struct col_type_map {
  ssize_t offset;
  short type;
};

/* This list must be kept in sync with
 * - the order of the columns in the files table
 * - the type and name of the fields in struct media_file_info
 */
static const struct col_type_map mfi_cols_map[] =
  {
    { mfi_offsetof(id),                 DB_TYPE_INT },
    { mfi_offsetof(path),               DB_TYPE_STRING },
    { mfi_offsetof(fname),              DB_TYPE_STRING },
    { mfi_offsetof(title),              DB_TYPE_STRING },
    { mfi_offsetof(artist),             DB_TYPE_STRING },
    { mfi_offsetof(album),              DB_TYPE_STRING },
    { mfi_offsetof(genre),              DB_TYPE_STRING },
    { mfi_offsetof(comment),            DB_TYPE_STRING },
    { mfi_offsetof(type),               DB_TYPE_STRING },
    { mfi_offsetof(composer),           DB_TYPE_STRING },
    { mfi_offsetof(orchestra),          DB_TYPE_STRING },
    { mfi_offsetof(conductor),          DB_TYPE_STRING },
    { mfi_offsetof(grouping),           DB_TYPE_STRING },
    { mfi_offsetof(url),                DB_TYPE_STRING },
    { mfi_offsetof(bitrate),            DB_TYPE_INT },
    { mfi_offsetof(samplerate),         DB_TYPE_INT },
    { mfi_offsetof(song_length),        DB_TYPE_INT },
    { mfi_offsetof(file_size),          DB_TYPE_INT64 },
    { mfi_offsetof(year),               DB_TYPE_INT },
    { mfi_offsetof(track),              DB_TYPE_INT },
    { mfi_offsetof(total_tracks),       DB_TYPE_INT },
    { mfi_offsetof(disc),               DB_TYPE_INT },
    { mfi_offsetof(total_discs),        DB_TYPE_INT },
    { mfi_offsetof(bpm),                DB_TYPE_INT },
    { mfi_offsetof(compilation),        DB_TYPE_CHAR },
    { mfi_offsetof(rating),             DB_TYPE_INT },
    { mfi_offsetof(play_count),         DB_TYPE_INT },
    { mfi_offsetof(data_kind),          DB_TYPE_INT },
    { mfi_offsetof(item_kind),          DB_TYPE_INT },
    { mfi_offsetof(description),        DB_TYPE_STRING },
    { mfi_offsetof(time_added),         DB_TYPE_INT },
    { mfi_offsetof(time_modified),      DB_TYPE_INT },
    { mfi_offsetof(time_played),        DB_TYPE_INT },
    { mfi_offsetof(db_timestamp),       DB_TYPE_INT },
    { mfi_offsetof(disabled),           DB_TYPE_INT },
    { mfi_offsetof(sample_count),       DB_TYPE_INT64 },
    { mfi_offsetof(codectype),          DB_TYPE_STRING },
    { mfi_offsetof(index),              DB_TYPE_INT },
    { mfi_offsetof(has_video),          DB_TYPE_INT },
    { mfi_offsetof(contentrating),      DB_TYPE_INT },
    { mfi_offsetof(bits_per_sample),    DB_TYPE_INT },
    { mfi_offsetof(album_artist),       DB_TYPE_STRING },
    { mfi_offsetof(media_kind),         DB_TYPE_INT },
    { mfi_offsetof(tv_series_name),     DB_TYPE_STRING },
    { mfi_offsetof(tv_episode_num_str), DB_TYPE_STRING },
    { mfi_offsetof(tv_network_name),    DB_TYPE_STRING },
    { mfi_offsetof(tv_episode_sort),    DB_TYPE_INT },
    { mfi_offsetof(tv_season_num),      DB_TYPE_INT },
    { mfi_offsetof(songalbumid),        DB_TYPE_INT64 },
    { mfi_offsetof(title_sort),         DB_TYPE_STRING },
    { mfi_offsetof(artist_sort),        DB_TYPE_STRING },
    { mfi_offsetof(album_sort),         DB_TYPE_STRING },
    { mfi_offsetof(composer_sort),      DB_TYPE_STRING },
    { mfi_offsetof(album_artist_sort),  DB_TYPE_STRING },
  };

/* This list must be kept in sync with
 * - the order of the columns in the playlists table
 * - the type and name of the fields in struct playlist_info
 */
static const struct col_type_map pli_cols_map[] =
  {
    { pli_offsetof(id),           DB_TYPE_INT },
    { pli_offsetof(title),        DB_TYPE_STRING },
    { pli_offsetof(type),         DB_TYPE_INT },
    { pli_offsetof(query),        DB_TYPE_STRING },
    { pli_offsetof(db_timestamp), DB_TYPE_INT },
    { pli_offsetof(disabled),     DB_TYPE_INT },
    { pli_offsetof(path),         DB_TYPE_STRING },
    { pli_offsetof(index),        DB_TYPE_INT },
    { pli_offsetof(special_id),   DB_TYPE_INT },

    /* items is computed on the fly */
  };

/* This list must be kept in sync with
 * - the order of the columns in the files table
 * - the name of the fields in struct db_media_file_info
 */
static const ssize_t dbmfi_cols_map[] =
  {
    dbmfi_offsetof(id),
    dbmfi_offsetof(path),
    dbmfi_offsetof(fname),
    dbmfi_offsetof(title),
    dbmfi_offsetof(artist),
    dbmfi_offsetof(album),
    dbmfi_offsetof(genre),
    dbmfi_offsetof(comment),
    dbmfi_offsetof(type),
    dbmfi_offsetof(composer),
    dbmfi_offsetof(orchestra),
    dbmfi_offsetof(conductor),
    dbmfi_offsetof(grouping),
    dbmfi_offsetof(url),
    dbmfi_offsetof(bitrate),
    dbmfi_offsetof(samplerate),
    dbmfi_offsetof(song_length),
    dbmfi_offsetof(file_size),
    dbmfi_offsetof(year),
    dbmfi_offsetof(track),
    dbmfi_offsetof(total_tracks),
    dbmfi_offsetof(disc),
    dbmfi_offsetof(total_discs),
    dbmfi_offsetof(bpm),
    dbmfi_offsetof(compilation),
    dbmfi_offsetof(rating),
    dbmfi_offsetof(play_count),
    dbmfi_offsetof(data_kind),
    dbmfi_offsetof(item_kind),
    dbmfi_offsetof(description),
    dbmfi_offsetof(time_added),
    dbmfi_offsetof(time_modified),
    dbmfi_offsetof(time_played),
    dbmfi_offsetof(db_timestamp),
    dbmfi_offsetof(disabled),
    dbmfi_offsetof(sample_count),
    dbmfi_offsetof(codectype),
    dbmfi_offsetof(idx),
    dbmfi_offsetof(has_video),
    dbmfi_offsetof(contentrating),
    dbmfi_offsetof(bits_per_sample),
    dbmfi_offsetof(album_artist),
    dbmfi_offsetof(media_kind),
    dbmfi_offsetof(tv_series_name),
    dbmfi_offsetof(tv_episode_num_str),
    dbmfi_offsetof(tv_network_name),
    dbmfi_offsetof(tv_episode_sort),
    dbmfi_offsetof(tv_season_num),
    dbmfi_offsetof(songalbumid),
    dbmfi_offsetof(title_sort),
    dbmfi_offsetof(artist_sort),
    dbmfi_offsetof(album_sort),
    dbmfi_offsetof(composer_sort),
    dbmfi_offsetof(album_artist_sort),
  };

/* This list must be kept in sync with
 * - the order of the columns in the playlists table
 * - the name of the fields in struct playlist_info
 */
static const ssize_t dbpli_cols_map[] =
  {
    dbpli_offsetof(id),
    dbpli_offsetof(title),
    dbpli_offsetof(type),
    dbpli_offsetof(query),
    dbpli_offsetof(db_timestamp),
    dbpli_offsetof(disabled),
    dbpli_offsetof(path),
    dbpli_offsetof(index),
    dbpli_offsetof(special_id),

    /* items is computed on the fly */
  };

/* This list must be kept in sync with
 * - the order of fields in the Q_GROUPS query
 * - the name of the fields in struct group_info
 */
static const ssize_t dbgri_cols_map[] =
  {
    dbgri_offsetof(itemcount),
    dbgri_offsetof(id),
    dbgri_offsetof(persistentid),
    dbgri_offsetof(songalbumartist),
    dbgri_offsetof(itemname),
  };

/* This list must be kept in sync with
 * - the order of the columns in the inotify table
 * - the name and type of the fields in struct watch_info
 */
static const struct col_type_map wi_cols_map[] =
  {
    { wi_offsetof(wd),     DB_TYPE_INT },
    { wi_offsetof(cookie), DB_TYPE_INT },
    { wi_offsetof(path),   DB_TYPE_STRING },
  };

/* Sort clauses */
/* Keep in sync with enum sort_type */
static const char *sort_clause[] =
  {
    "",
    "ORDER BY f.title_sort ASC",
    "ORDER BY f.album_sort ASC, f.disc ASC, f.track ASC",
    "ORDER BY f.artist_sort ASC",
  };

static char *db_path;
static __thread struct db_pool_hdl *pool_hdl;

static dispatch_queue_t dbpool_sq;
static dispatch_source_t pool_reclaim_timer;
static int pool_size;
static int pool_free_size;
static struct db_pool_hdl *pool_free;
static struct db_pool_hdl *pool_used;


/* Forward */
static int
db_pl_count_items(int id);

static int
db_smartpl_count_items(const char *smartpl_query);

struct playlist_info *
db_pl_fetch_byid(int id);


char *
db_escape_string(const char *str)
{
  char *escaped;
  char *ret;

  escaped = sqlite3_mprintf("%q", str);
  if (!escaped)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for escaped string\n");

      return NULL;
    }

  ret = strdup(escaped);

  sqlite3_free(escaped);

  return ret;
}

void
free_pi(struct pairing_info *pi, int content_only)
{
  if (pi->remote_id)
    free(pi->remote_id);

  if (pi->name)
    free(pi->name);

  if (pi->guid)
    free(pi->guid);

  if (!content_only)
    free(pi);
}

void
free_mfi(struct media_file_info *mfi, int content_only)
{
  if (mfi->path)
    free(mfi->path);

  if (mfi->fname)
    free(mfi->fname);

  if (mfi->title)
    free(mfi->title);

  if (mfi->artist)
    free(mfi->artist);

  if (mfi->album)
    free(mfi->album);

  if (mfi->genre)
    free(mfi->genre);

  if (mfi->comment)
    free(mfi->comment);

  if (mfi->type)
    free(mfi->type);

  if (mfi->composer)
    free(mfi->composer);

  if (mfi->orchestra)
    free(mfi->orchestra);

  if (mfi->conductor)
    free(mfi->conductor);

  if (mfi->grouping)
    free(mfi->grouping);

  if (mfi->description)
    free(mfi->description);

  if (mfi->codectype)
    free(mfi->codectype);

  if (mfi->album_artist)
    free(mfi->album_artist);

  if (mfi->tv_series_name)
    free(mfi->tv_series_name);

  if (mfi->tv_episode_num_str)
    free(mfi->tv_episode_num_str);

  if (mfi->tv_network_name)
    free(mfi->tv_network_name);

  if (mfi->title_sort)
    free(mfi->title_sort);

  if (mfi->artist_sort)
    free(mfi->artist_sort);

  if (mfi->album_sort)
    free(mfi->album_sort);

  if (mfi->composer_sort)
    free(mfi->composer_sort);

  if (mfi->album_artist_sort)
    free(mfi->album_artist_sort);

  if (!content_only)
    free(mfi);
}

void
unicode_fixup_mfi(struct media_file_info *mfi)
{
  char *ret;
  char **field;
  int i;

  for (i = 0; i < (sizeof(mfi_cols_map) / sizeof(mfi_cols_map[0])); i++)
    {
      if (mfi_cols_map[i].type != DB_TYPE_STRING)
	continue;

      switch (mfi_cols_map[i].offset)
	{
	  case mfi_offsetof(path):
	  case mfi_offsetof(fname):
	  case mfi_offsetof(codectype):
	    continue;
	}

      field = (char **) ((char *)mfi + mfi_cols_map[i].offset);

      if (!*field)
	continue;

      ret = unicode_fixup_string(*field);
      if (ret != *field)
	{
	  free(*field);
	  *field = ret;
	}
    }
}

void
free_pli(struct playlist_info *pli, int content_only)
{
  if (pli->title)
    free(pli->title);

  if (pli->query)
    free(pli->query);

  if (pli->path)
    free(pli->path);

  if (!content_only)
    free(pli);
}


/* Unlock notification support */
static void
unlock_notify_cb(void **args, int nargs)
{
  struct db_unlock *u;
  int i;

  for (i = 0; i < nargs; i++)
    {
      u = (struct db_unlock *)args[i];

      pthread_mutex_lock(&u->lck);

      u->proceed = 1;
      pthread_cond_signal(&u->cond);

      pthread_mutex_unlock(&u->lck);
    }
}

static int
db_wait_unlock(void)
{
  struct db_unlock u;
  int ret;

  u.proceed = 0;
  pthread_mutex_init(&u.lck, NULL);
  pthread_cond_init(&u.cond, NULL);

  ret = sqlite3_unlock_notify(pool_hdl->hdl, unlock_notify_cb, &u);
  if (ret == SQLITE_OK)
    {
      pthread_mutex_lock(&u.lck);

      if (!u.proceed)
	pthread_cond_wait(&u.cond, &u.lck);

      pthread_mutex_unlock(&u.lck);
    }

  pthread_cond_destroy(&u.cond);
  pthread_mutex_destroy(&u.lck);

  return ret;
}

static int
db_blocking_step(sqlite3_stmt *stmt)
{
  int ret;

  while ((ret = sqlite3_step(stmt)) == SQLITE_LOCKED)
    {
      ret = db_wait_unlock();
      if (ret != SQLITE_OK)
	{
	  DPRINTF(E_LOG, L_DB, "Database deadlocked!\n");
	  break;
	}

      sqlite3_reset(stmt);
    }

  return ret;
}

static int
db_blocking_prepare_v2(const char *query, int len, sqlite3_stmt **stmt, const char **end)
{
  int ret;

  while ((ret = sqlite3_prepare_v2(pool_hdl->hdl, query, len, stmt, end)) == SQLITE_LOCKED)
    {
      ret = db_wait_unlock();
      if (ret != SQLITE_OK)
	{
	  DPRINTF(E_LOG, L_DB, "Database deadlocked!\n");
	  break;
	}
    }

  return ret;
}


/* Modelled after sqlite3_exec() */
static int
db_exec(const char *query, char **errmsg)
{
  sqlite3_stmt *stmt;
  int try;
  int ret;

  *errmsg = NULL;

  for (try = 0; try < 5; try++)
    {
      ret = db_blocking_prepare_v2(query, -1, &stmt, NULL);
      if (ret != SQLITE_OK)
	{
	  *errmsg = sqlite3_mprintf("prepare failed: %s", sqlite3_errmsg(pool_hdl->hdl));
	  return ret;
	}

      while ((ret = db_blocking_step(stmt)) == SQLITE_ROW)
	; /* EMPTY */

      sqlite3_finalize(stmt);

      if (ret != SQLITE_SCHEMA)
	break;
    }

  if (ret != SQLITE_DONE)
    {
      *errmsg = sqlite3_mprintf("step failed: %s", sqlite3_errmsg(pool_hdl->hdl));
      return ret;
    }

  return SQLITE_OK;
}


/* Maintenance and DB hygiene */
static void
db_analyze(void)
{
  char *query = "ANALYZE;";
  char *errmsg;
  int ret;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "ANALYZE failed: %s\n", errmsg);

      sqlite3_free(errmsg);
    }
}

void
db_hook_post_scan(void)
{
  DPRINTF(E_DBG, L_DB, "Running post-scan DB maintenance tasks...\n");

  db_analyze();

  DPRINTF(E_DBG, L_DB, "Done with post-scan DB maintenance\n");
}

void
db_purge_cruft(time_t ref)
{
  char *errmsg;
  int i;
  int ret;
  char *queries[3] = { NULL, NULL, NULL };
  char *queries_tmpl[3] =
    {
      "DELETE FROM playlistitems WHERE playlistid IN (SELECT id FROM playlists p WHERE p.type <> 1 AND p.db_timestamp < %" PRIi64 ");",
      "DELETE FROM playlists WHERE type <> 1 AND db_timestamp < %" PRIi64 ";",
      "DELETE FROM files WHERE db_timestamp < %" PRIi64 ";"
    };

  if (sizeof(queries) != sizeof(queries_tmpl))
    {
      DPRINTF(E_LOG, L_DB, "db_purge_cruft(): queries out of sync with queries_tmpl\n");
      return;
    }

  for (i = 0; i < (sizeof(queries_tmpl) / sizeof(queries_tmpl[0])); i++)
    {
      queries[i] = sqlite3_mprintf(queries_tmpl[i], (int64_t)ref);
      if (!queries[i])
	{
	  DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
	  goto purge_fail;
	}
    }

  for (i = 0; i < (sizeof(queries) / sizeof(queries[0])); i++)
    {
      DPRINTF(E_DBG, L_DB, "Running purge query '%s'\n", queries[i]);

      ret = db_exec(queries[i], &errmsg);
      if (ret != SQLITE_OK)
	{
	  DPRINTF(E_LOG, L_DB, "Purge query %d error: %s\n", i, errmsg);

	  sqlite3_free(errmsg);
	}
      else
	DPRINTF(E_DBG, L_DB, "Purged %d rows\n", sqlite3_changes(pool_hdl->hdl));
    }

 purge_fail:
  for (i = 0; i < (sizeof(queries) / sizeof(queries[0])); i++)
    {
      sqlite3_free(queries[i]);
    }

}

static int
db_get_count(char *query)
{
  sqlite3_stmt *stmt;
  int ret;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_blocking_prepare_v2(query, -1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));
      return -1;
    }

  ret = db_blocking_step(stmt);
  if (ret != SQLITE_ROW)
    {
      DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);
      return -1;
    }

  ret = sqlite3_column_int(stmt, 0);

#ifdef DB_PROFILE
  while (db_blocking_step(stmt) == SQLITE_ROW)
    ; /* EMPTY */
#endif

  sqlite3_finalize(stmt);

  return ret;
}


/* Queries */
static int
db_build_query_index_clause(struct query_params *qp, char **i)
{
  char *idx;

  switch (qp->idx_type)
    {
      case I_FIRST:
	idx = sqlite3_mprintf("LIMIT %d", qp->limit);
	break;

      case I_LAST:
	idx = sqlite3_mprintf("LIMIT -1 OFFSET %d", qp->results - qp->limit);
	break;

      case I_SUB:
	idx = sqlite3_mprintf("LIMIT %d OFFSET %d", qp->limit, qp->offset);
	break;

      case I_NONE:
	*i = NULL;
	return 0;

      default:
	DPRINTF(E_LOG, L_DB, "Unknown index type\n");
	return -1;
    }

  if (!idx)
    {
      DPRINTF(E_LOG, L_DB, "Could not build index string; out of memory");
      return -1;
    }

  *i = idx;

  return 0;
}

static int
db_build_query_items(struct query_params *qp, char **q)
{
  char *query;
  char *count;
  char *idx;
  const char *sort;
  int ret;

  if (qp->filter)
    count = sqlite3_mprintf("SELECT COUNT(*) FROM files f WHERE f.disabled = 0 AND %s;", qp->filter);
  else
    count = sqlite3_mprintf("SELECT COUNT(*) FROM files f WHERE f.disabled = 0;");

  if (!count)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for count query string\n");

      return -1;
    }

  qp->results = db_get_count(count);
  sqlite3_free(count);

  if (qp->results < 0)
    return -1;

  /* Get index clause */
  ret = db_build_query_index_clause(qp, &idx);
  if (ret < 0)
    return -1;

  sort = sort_clause[qp->sort];

  if (idx && qp->filter)
    query = sqlite3_mprintf("SELECT f.* FROM files f WHERE f.disabled = 0 AND %s %s %s;", qp->filter, sort, idx);
  else if (idx)
    query = sqlite3_mprintf("SELECT f.* FROM files f WHERE f.disabled = 0 %s %s;", sort, idx);
  else if (qp->filter)
    query = sqlite3_mprintf("SELECT f.* FROM files f WHERE f.disabled = 0 AND %s %s;", qp->filter, sort);
  else
    query = sqlite3_mprintf("SELECT f.* FROM files f WHERE f.disabled = 0 %s;", sort);

  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  *q = query;

  return 0;
}

static int
db_build_query_pls(struct query_params *qp, char **q)
{
  char *query;
  char *idx;
  int ret;

  qp->results = db_get_count("SELECT COUNT(*) FROM playlists p WHERE p.disabled = 0;");
  if (qp->results < 0)
    return -1;

  /* Get index clause */
  ret = db_build_query_index_clause(qp, &idx);
  if (ret < 0)
    return -1;

  if (idx && qp->filter)
    query = sqlite3_mprintf("SELECT f.* FROM playlists f WHERE f.disabled = 0 AND %s %s;", qp->filter, idx);
  else if (idx)
    query = sqlite3_mprintf("SELECT f.* FROM playlists f WHERE f.disabled = 0 %s;", idx);
  else if (qp->filter)
    query = sqlite3_mprintf("SELECT f.* FROM playlists f WHERE f.disabled = 0 AND %s;", qp->filter);
  else
    query = sqlite3_mprintf("SELECT f.* FROM playlists f WHERE f.disabled = 0;");

  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  *q = query;

  return 0;
}

static int
db_build_query_plitems_plain(struct query_params *qp, char **q)
{
  char *query;
  char *count;
  char *idx;
  int ret;

  if (qp->filter)
    count = sqlite3_mprintf("SELECT COUNT(*) FROM files f JOIN playlistitems pi ON f.path = pi.filepath"
			    " WHERE pi.playlistid = %d AND f.disabled = 0 AND %s;", qp->id, qp->filter);
  else
    count = sqlite3_mprintf("SELECT COUNT(*) FROM files f JOIN playlistitems pi ON f.path = pi.filepath"
			    " WHERE pi.playlistid = %d AND f.disabled = 0;", qp->id);

  if (!count)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for count query string\n");

      return -1;
    }

  qp->results = db_get_count(count);
  sqlite3_free(count);

  if (qp->results < 0)
    return -1;

  /* Get index clause */
  ret = db_build_query_index_clause(qp, &idx);
  if (ret < 0)
    return -1;

  if (idx && qp->filter)
    query = sqlite3_mprintf("SELECT f.* FROM files f JOIN playlistitems pi ON f.path = pi.filepath"
			    " WHERE pi.playlistid = %d AND f.disabled = 0 AND %s ORDER BY pi.id ASC %s;",
			    qp->id, qp->filter, idx);
  else if (idx)
    query = sqlite3_mprintf("SELECT f.* FROM files f JOIN playlistitems pi ON f.path = pi.filepath"
			    " WHERE pi.playlistid = %d AND f.disabled = 0 ORDER BY pi.id ASC %s;",
			    qp->id, idx);
  else if (qp->filter)
    query = sqlite3_mprintf("SELECT f.* FROM files f JOIN playlistitems pi ON f.path = pi.filepath"
			    " WHERE pi.playlistid = %d AND f.disabled = 0 AND %s ORDER BY pi.id ASC;",
			    qp->id, qp->filter);
  else
    query = sqlite3_mprintf("SELECT f.* FROM files f JOIN playlistitems pi ON f.path = pi.filepath"
			    " WHERE pi.playlistid = %d AND f.disabled = 0 ORDER BY pi.id ASC;",
			    qp->id);

  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  *q = query;

  return 0;
}

static int
db_build_query_plitems_smart(struct query_params *qp, char *smartpl_query, char **q)
{
  char *query;
  char *count;
  char *filter;
  char *idx;
  const char *sort;
  int ret;

  if (qp->filter)
    filter = qp->filter;
  else
    filter = "1 = 1";

  count = sqlite3_mprintf("SELECT COUNT(*) FROM files f WHERE f.disabled = 0 AND %s AND %s;", filter, smartpl_query);
  if (!count)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for count query string\n");
      return -1;
    }

  qp->results = db_get_count(count);

  sqlite3_free(count);

  if (qp->results < 0)
    return -1;

  /* Get index clause */
  ret = db_build_query_index_clause(qp, &idx);
  if (ret < 0)
    return -1;

  if (!idx)
    idx = "";

  sort = sort_clause[qp->sort];

  query = sqlite3_mprintf("SELECT f.* FROM files f WHERE f.disabled = 0 AND %s AND %s %s %s;", smartpl_query, filter, sort, idx);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  *q = query;

  return 0;
}

static int
db_build_query_plitems(struct query_params *qp, char **q)
{
  struct playlist_info *pli;
  int ret;

  if (qp->id <= 0)
    {
      DPRINTF(E_LOG, L_DB, "No playlist id specified in playlist items query\n");
      return -1;
    }

  pli = db_pl_fetch_byid(qp->id);
  if (!pli)
    return -1;

  switch (pli->type)
    {
      case PL_SMART:
	ret = db_build_query_plitems_smart(qp, pli->query, q);
	break;

      case PL_PLAIN:
	ret = db_build_query_plitems_plain(qp, q);
	break;

      default:
	DPRINTF(E_LOG, L_DB, "Unknown playlist type %d in playlist items query\n", pli->type);
	ret = -1;
	break;
    }

  free_pli(pli, 0);

  return ret;
}

static int
db_build_query_groups(struct query_params *qp, char **q)
{
  char *query;
  char *idx;
  int ret;

  qp->results = db_get_count("SELECT COUNT(DISTINCT f.songalbumid) FROM files f WHERE f.disabled = 0;");
  if (qp->results < 0)
    return -1;

  /* Get index clause */
  ret = db_build_query_index_clause(qp, &idx);
  if (ret < 0)
    return -1;

  if (idx && qp->filter)
    query = sqlite3_mprintf("SELECT COUNT(*), g.id, g.persistentid, f.album_artist, g.name FROM files f, groups g WHERE f.songalbumid = g.persistentid AND g.type = %d AND f.disabled = 0 AND %s GROUP BY f.album, g.name %s;", G_ALBUMS, qp->filter, idx);
  else if (idx)
    query = sqlite3_mprintf("SELECT COUNT(*), g.id, g.persistentid, f.album_artist, g.name FROM files f, groups g WHERE f.songalbumid = g.persistentid AND g.type = %d AND f.disabled = 0 GROUP BY f.album, g.name %s;", G_ALBUMS, idx);
  else if (qp->filter)
    query = sqlite3_mprintf("SELECT COUNT(*), g.id, g.persistentid, f.album_artist, g.name FROM files f, groups g WHERE f.songalbumid = g.persistentid AND g.type = %d AND f.disabled = 0 AND %s GROUP BY f.album, g.name;", G_ALBUMS, qp->filter);
  else
    query = sqlite3_mprintf("SELECT COUNT(*), g.id, g.persistentid, f.album_artist, g.name FROM files f, groups g WHERE f.songalbumid = g.persistentid AND g.type = %d AND f.disabled = 0 GROUP BY f.album, g.name;", G_ALBUMS);

  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  *q = query;

  return 0;
}

static int
db_build_query_groupitems(struct query_params *qp, char **q)
{
  char *query;
  char *count;
  enum group_type gt;

  gt = db_group_type_byid(qp->id);

  switch (gt)
    {
      case G_ALBUMS:
	count = sqlite3_mprintf("SELECT COUNT(*) FROM files f JOIN groups g ON f.songalbumid = g.persistentid"
				" WHERE g.id = %d AND f.disabled = 0;", qp->id);
	break;

      default:
	DPRINTF(E_LOG, L_DB, "Unsupported group type %d for group id %d\n", gt, qp->id);
	return -1;
    }

  if (!count)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for count query string\n");

      return -1;
    }

  qp->results = db_get_count(count);
  sqlite3_free(count);

  if (qp->results < 0)
    return -1;

  switch (gt)
    {
      case G_ALBUMS:
	query = sqlite3_mprintf("SELECT f.* FROM files f JOIN groups g ON f.songalbumid = g.persistentid"
				" WHERE g.id = %d AND f.disabled = 0;", qp->id);
	break;
    }

  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  *q = query;

  return 0;
}

static int
db_build_query_group_dirs(struct query_params *qp, char **q)
{
  char *query;
  char *count;
  enum group_type gt;

  gt = db_group_type_byid(qp->id);

  switch (gt)
    {
      case G_ALBUMS:
	count = sqlite3_mprintf("SELECT COUNT(DISTINCT(SUBSTR(f.path, 1, LENGTH(f.path) - LENGTH(f.fname) - 1)))"
				" FROM files f JOIN groups g ON f.songalbumid = g.persistentid"
				" WHERE g.id = %d AND f.disabled = 0;", qp->id);
	break;

      default:
	DPRINTF(E_LOG, L_DB, "Unsupported group type %d for group id %d\n", gt, qp->id);
	return -1;
    }

  if (!count)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for count query string\n");

      return -1;
    }

  qp->results = db_get_count(count);
  sqlite3_free(count);

  if (qp->results < 0)
    return -1;

  switch (gt)
    {
      case G_ALBUMS:
	query = sqlite3_mprintf("SELECT DISTINCT(SUBSTR(f.path, 1, LENGTH(f.path) - LENGTH(f.fname) - 1))"
				" FROM files f JOIN groups g ON f.songalbumid = g.persistentid"
				" WHERE g.id = %d AND f.disabled = 0;", qp->id);
	break;
    }

  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  *q = query;

  return 0;
}

static int
db_build_query_browse(struct query_params *qp, char *field, char **q)
{
  char *query;
  char *count;
  char *idx;
  int ret;

  if (qp->filter)
    count = sqlite3_mprintf("SELECT COUNT(DISTINCT f.%s) FROM files f WHERE f.data_kind = 0 AND f.disabled = 0 AND f.%s != '' AND %s;",
			    field, field, qp->filter);
  else
    count = sqlite3_mprintf("SELECT COUNT(DISTINCT f.%s) FROM files f WHERE f.data_kind = 0 AND f.disabled = 0 AND f.%s != '';",
			    field, field);

  if (!count)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for count query string\n");

      return -1;
    }

  qp->results = db_get_count(count);
  sqlite3_free(count);

  if (qp->results < 0)
    return -1;

  /* Get index clause */
  ret = db_build_query_index_clause(qp, &idx);
  if (ret < 0)
    return -1;

  if (idx && qp->filter)
    query = sqlite3_mprintf("SELECT DISTINCT f.%s, f.%s FROM files f WHERE f.data_kind = 0 AND f.disabled = 0 AND f.%s != ''"
			    " AND %s ORDER BY f.%s %s;", field, field, field, qp->filter, field, idx);
  else if (idx)
    query = sqlite3_mprintf("SELECT DISTINCT f.%s, f.%s FROM files f WHERE f.data_kind = 0 AND f.disabled = 0 AND f.%s != ''"
			    " ORDER BY f.%s %s;", field, field, field, field, idx);
  else if (qp->filter)
    query = sqlite3_mprintf("SELECT DISTINCT f.%s, f.%s FROM files f WHERE f.data_kind = 0 AND f.disabled = 0 AND f.%s != ''"
			    " AND %s ORDER BY f.%s;", field, field, field, qp->filter, field);
  else
    query = sqlite3_mprintf("SELECT DISTINCT f.%s, f.%s FROM files f WHERE f.data_kind = 0 AND f.disabled = 0 AND f.%s != '' ORDER BY f.%s",
			    field, field, field, field);

  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  *q = query;

  return 0;
}

int
db_query_start(struct query_params *qp)
{
  char *query;
  int ret;

  qp->stmt = NULL;

  switch (qp->type)
    {
      case Q_ITEMS:
	ret = db_build_query_items(qp, &query);
	break;

      case Q_PL:
	ret = db_build_query_pls(qp, &query);
	break;

      case Q_PLITEMS:
	ret = db_build_query_plitems(qp, &query);
	break;

      case Q_GROUPS:
	ret = db_build_query_groups(qp, &query);
	break;

      case Q_GROUPITEMS:
	ret = db_build_query_groupitems(qp, &query);
	break;

      case Q_GROUP_DIRS:
	ret = db_build_query_group_dirs(qp, &query);
	break;

      case Q_BROWSE_ALBUMS:
	ret = db_build_query_browse(qp, "album", &query);
	break;

      case Q_BROWSE_ARTISTS:
	ret = db_build_query_browse(qp, "artist", &query);
	break;

      case Q_BROWSE_GENRES:
	ret = db_build_query_browse(qp, "genre", &query);
	break;

      case Q_BROWSE_COMPOSERS:
	ret = db_build_query_browse(qp, "composer", &query);
	break;

      default:
	DPRINTF(E_LOG, L_DB, "Unknown query type\n");
	return -1;
    }

  if (ret < 0)
    return -1;

  DPRINTF(E_DBG, L_DB, "Starting query '%s'\n", query);

  ret = db_blocking_prepare_v2(query, -1, &qp->stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  return 0;
}

void
db_query_end(struct query_params *qp)
{
  if (!qp->stmt)
    return;

  qp->results = -1;

  sqlite3_finalize(qp->stmt);
  qp->stmt = NULL;
}

int
db_query_fetch_file(struct query_params *qp, struct db_media_file_info *dbmfi)
{
  int ncols;
  char **strcol;
  int i;
  int ret;

  memset(dbmfi, 0, sizeof(struct db_media_file_info));

  if (!qp->stmt)
    {
      DPRINTF(E_LOG, L_DB, "Query not started!\n");
      return -1;
    }

  if ((qp->type != Q_ITEMS) && (qp->type != Q_PLITEMS) && (qp->type != Q_GROUPITEMS))
    {
      DPRINTF(E_LOG, L_DB, "Not an items, playlist or group items query!\n");
      return -1;
    }

  ret = db_blocking_step(qp->stmt);
  if (ret == SQLITE_DONE)
    {
      DPRINTF(E_INFO, L_DB, "End of query results\n");
      dbmfi->id = NULL;
      return 0;
    }
  else if (ret != SQLITE_ROW)
    {
      DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));
      return -1;
    }

  ncols = sqlite3_column_count(qp->stmt);

  if (sizeof(dbmfi_cols_map) / sizeof(dbmfi_cols_map[0]) != ncols)
    {
      DPRINTF(E_LOG, L_DB, "BUG: dbmfi column map out of sync with schema\n");
      return -1;
    }

  for (i = 0; i < ncols; i++)
    {
      strcol = (char **) ((char *)dbmfi + dbmfi_cols_map[i]);

      *strcol = (char *)sqlite3_column_text(qp->stmt, i);
    }

  return 0;
}

int
db_query_fetch_pl(struct query_params *qp, struct db_playlist_info *dbpli)
{
  int ncols;
  char **strcol;
  int id;
  int type;
  int nitems;
  int i;
  int ret;

  memset(dbpli, 0, sizeof(struct db_playlist_info));

  if (!qp->stmt)
    {
      DPRINTF(E_LOG, L_DB, "Query not started!\n");
      return -1;
    }

  if (qp->type != Q_PL)
    {
      DPRINTF(E_LOG, L_DB, "Not a playlist query!\n");
      return -1;
    }

  ret = db_blocking_step(qp->stmt);
  if (ret == SQLITE_DONE)
    {
      DPRINTF(E_INFO, L_DB, "End of query results\n");
      dbpli->id = NULL;
      return 0;
    }
  else if (ret != SQLITE_ROW)
    {
      DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));
      return -1;
    }

  ncols = sqlite3_column_count(qp->stmt);

  if (sizeof(dbpli_cols_map) / sizeof(dbpli_cols_map[0]) != ncols)
    {
      DPRINTF(E_LOG, L_DB, "BUG: dbpli column map out of sync with schema\n");
      return -1;
    }

  for (i = 0; i < ncols; i++)
    {
      strcol = (char **) ((char *)dbpli + dbpli_cols_map[i]);

      *strcol = (char *)sqlite3_column_text(qp->stmt, i);
    }

  type = sqlite3_column_int(qp->stmt, 2);

  switch (type)
    {
      case PL_PLAIN:
	id = sqlite3_column_int(qp->stmt, 0);
	nitems = db_pl_count_items(id);
	break;

      case PL_SMART:
	nitems = db_smartpl_count_items(dbpli->query);
	break;

      default:
	DPRINTF(E_LOG, L_DB, "Unknown playlist type %d while fetching playlist\n", type);
	return -1;
    }

  dbpli->items = qp->buf;
  ret = snprintf(qp->buf, sizeof(qp->buf), "%d", nitems);
  if ((ret < 0) || (ret >= sizeof(qp->buf)))
    {
      DPRINTF(E_LOG, L_DB, "Could not convert items, buffer too small\n");

      strcpy(qp->buf, "0");
    }

  return 0;
}

int
db_query_fetch_group(struct query_params *qp, struct db_group_info *dbgri)
{
  int ncols;
  char **strcol;
  int i;
  int ret;

  memset(dbgri, 0, sizeof(struct db_group_info));

  if (!qp->stmt)
    {
      DPRINTF(E_LOG, L_DB, "Query not started!\n");
      return -1;
    }

  if (qp->type != Q_GROUPS)
    {
      DPRINTF(E_LOG, L_DB, "Not a groups query!\n");
      return -1;
    }

  ret = db_blocking_step(qp->stmt);
  if (ret == SQLITE_DONE)
    {
      DPRINTF(E_INFO, L_DB, "End of query results\n");
      return 1;
    }
  else if (ret != SQLITE_ROW)
    {
      DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));
      return -1;
    }

  ncols = sqlite3_column_count(qp->stmt);

  if (sizeof(dbgri_cols_map) / sizeof(dbgri_cols_map[0]) != ncols)
    {
      DPRINTF(E_LOG, L_DB, "BUG: dbgri column map out of sync with schema\n");
      return -1;
    }

  for (i = 0; i < ncols; i++)
    {
      strcol = (char **) ((char *)dbgri + dbgri_cols_map[i]);

      *strcol = (char *)sqlite3_column_text(qp->stmt, i);
    }

  return 0;
}

int
db_query_fetch_string(struct query_params *qp, char **string)
{
  int ret;

  *string = NULL;

  if (!qp->stmt)
    {
      DPRINTF(E_LOG, L_DB, "Query not started!\n");
      return -1;
    }

  if (!(qp->type & Q_F_BROWSE))
    {
      DPRINTF(E_LOG, L_DB, "Not a browse query!\n");
      return -1;
    }

  ret = db_blocking_step(qp->stmt);
  if (ret == SQLITE_DONE)
    {
      DPRINTF(E_INFO, L_DB, "End of query results\n");
      *string = NULL;
      return 0;
    }
  else if (ret != SQLITE_ROW)
    {
      DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));
      return -1;
    }

  *string = (char *)sqlite3_column_text(qp->stmt, 0);

  return 0;
}

int
db_query_fetch_string_sort(struct query_params *qp, char **string, char **sortstring)
{
  int ret;

  *string = NULL;

  if (!qp->stmt)
    {
      DPRINTF(E_LOG, L_DB, "Query not started!\n");
      return -1;
    }

  if (!(qp->type & Q_F_BROWSE))
    {
      DPRINTF(E_LOG, L_DB, "Not a browse query!\n");
      return -1;
    }

  ret = db_blocking_step(qp->stmt);
  if (ret == SQLITE_DONE)
    {
      DPRINTF(E_INFO, L_DB, "End of query results\n");
      *string = NULL;
      return 0;
    }
  else if (ret != SQLITE_ROW)
    {
      DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));
      return -1;
    }

  *string = (char *)sqlite3_column_text(qp->stmt, 0);
  *sortstring = (char *)sqlite3_column_text(qp->stmt, 1);

  return 0;
}


/* Files */
int
db_files_get_count(void)
{
  return db_get_count("SELECT COUNT(*) FROM files f WHERE f.disabled = 0;");
}

void
db_files_update_songalbumid(void)
{
#define Q_SONGALBUMID "UPDATE files SET songalbumid = daap_songalbumid(album_artist, album);"
  char *errmsg;
  int ret;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", Q_SONGALBUMID);

  ret = db_exec(Q_SONGALBUMID, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error updating songalbumid: %s\n", errmsg);

  sqlite3_free(errmsg);

#undef Q_SONGALBUMID
}

void
db_file_inc_playcount(int id)
{
#define Q_TMPL "UPDATE files SET play_count = play_count + 1, time_played = %" PRIi64 " WHERE id = %d;"
  char *query;
  char *errmsg;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, (int64_t)time(NULL), id);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error incrementing play count on %d: %s\n", id, errmsg);

  sqlite3_free(errmsg);
  sqlite3_free(query);

#undef Q_TMPL
}

void
db_file_ping(int id)
{
#define Q_TMPL "UPDATE files SET db_timestamp = %" PRIi64 ", disabled = 0 WHERE id = %d;"
  char *query;
  char *errmsg;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, (int64_t)time(NULL), id);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error pinging file ID %d: %s\n", id, errmsg);

  sqlite3_free(errmsg);
  sqlite3_free(query);

#undef Q_TMPL
}

char *
db_file_path_byid(int id)
{
#define Q_TMPL "SELECT f.path FROM files f WHERE f.id = %d;"
  char *query;
  sqlite3_stmt *stmt;
  char *res;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, id);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return NULL;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_blocking_prepare_v2(query, strlen(query) + 1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_free(query);
      return NULL;
    }

  ret = db_blocking_step(stmt);
  if (ret != SQLITE_ROW)
    {
      if (ret == SQLITE_DONE)
	DPRINTF(E_INFO, L_DB, "No results\n");
      else
	DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);
      sqlite3_free(query);
      return NULL;
    }

  res = (char *)sqlite3_column_text(stmt, 0);
  if (res)
    res = strdup(res);

#ifdef DB_PROFILE
  while (db_blocking_step(stmt) == SQLITE_ROW)
    ; /* EMPTY */
#endif

  sqlite3_finalize(stmt);
  sqlite3_free(query);

  return res;

#undef Q_TMPL
}

static int
db_file_id_byquery(char *query)
{
  sqlite3_stmt *stmt;
  int ret;

  if (!query)
    return 0;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_blocking_prepare_v2(query, strlen(query) + 1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      return 0;
    }

  ret = db_blocking_step(stmt);
  if (ret != SQLITE_ROW)
    {
      if (ret == SQLITE_DONE)
	DPRINTF(E_INFO, L_DB, "No results\n");
      else
	DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);
      return 0;
    }

  ret = sqlite3_column_int(stmt, 0);

#ifdef DB_PROFILE
  while (db_blocking_step(stmt) == SQLITE_ROW)
    ; /* EMPTY */
#endif

  sqlite3_finalize(stmt);

  return ret;
}

int
db_file_id_bypath(char *path)
{
#define Q_TMPL "SELECT f.id FROM files f WHERE f.path = '%q';"
  char *query;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return 0;
    }

  ret = db_file_id_byquery(query);

  sqlite3_free(query);

  return ret;

#undef Q_TMPL
}

int
db_file_id_byfilebase(char *filename, char *base)
{
#define Q_TMPL "SELECT f.id FROM files f WHERE f.path LIKE '%q/%%/%q';"
  char *query;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, base, filename);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return 0;
    }

  ret = db_file_id_byquery(query);

  sqlite3_free(query);

  return ret;

#undef Q_TMPL
}

int
db_file_id_byfile(char *filename)
{
#define Q_TMPL "SELECT f.id FROM files f WHERE f.fname = '%q';"
  char *query;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, filename);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return 0;
    }

  ret = db_file_id_byquery(query);

  sqlite3_free(query);

  return ret;

#undef Q_TMPL
}

int
db_file_id_byurl(char *url)
{
#define Q_TMPL "SELECT f.id FROM files f WHERE f.url = '%q';"
  char *query;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, url);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return 0;
    }

  ret = db_file_id_byquery(query);

  sqlite3_free(query);

  return ret;

#undef Q_TMPL
}

void
db_file_stamp_bypath(char *path, time_t *stamp, int *id)
{
#define Q_TMPL "SELECT f.id, f.db_timestamp FROM files f WHERE f.path = '%q';"
  char *query;
  sqlite3_stmt *stmt;
  int ret;

  *stamp = 0;

  query = sqlite3_mprintf(Q_TMPL, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_blocking_prepare_v2(query, strlen(query) + 1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_free(query);
      return;
    }

  ret = db_blocking_step(stmt);
  if (ret != SQLITE_ROW)
    {
      if (ret == SQLITE_DONE)
	DPRINTF(E_INFO, L_DB, "No results\n");
      else
	DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);
      sqlite3_free(query);
      return;
    }

  *id = sqlite3_column_int(stmt, 0);
  *stamp = (time_t)sqlite3_column_int64(stmt, 1);

#ifdef DB_PROFILE
  while (db_blocking_step(stmt) == SQLITE_ROW)
    ; /* EMPTY */
#endif

  sqlite3_finalize(stmt);
  sqlite3_free(query);

#undef Q_TMPL
}

static struct media_file_info *
db_file_fetch_byquery(char *query)
{
  struct media_file_info *mfi;
  sqlite3_stmt *stmt;
  int ncols;
  char *cval;
  uint32_t *ival;
  uint64_t *i64val;
  char **strval;
  uint64_t disabled;
  int i;
  int ret;

  if (!query)
    return NULL;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  mfi = (struct media_file_info *)malloc(sizeof(struct media_file_info));
  if (!mfi)
    {
      DPRINTF(E_LOG, L_DB, "Could not allocate struct media_file_info, out of memory\n");
      return NULL;
    }
  memset(mfi, 0, sizeof(struct media_file_info));

  ret = db_blocking_prepare_v2(query, -1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      free(mfi);
      return NULL;
    }

  ret = db_blocking_step(stmt);

  if (ret != SQLITE_ROW)
    {
      if (ret == SQLITE_DONE)
	DPRINTF(E_INFO, L_DB, "No results\n");
      else
	DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);
      free(mfi);
      return NULL;
    }

  ncols = sqlite3_column_count(stmt);

  if (sizeof(mfi_cols_map) / sizeof(mfi_cols_map[0]) != ncols)
    {
      DPRINTF(E_LOG, L_DB, "BUG: mfi column map out of sync with schema\n");

      sqlite3_finalize(stmt);
      free(mfi);
      return NULL;
    }

  for (i = 0; i < ncols; i++)
    {
      switch (mfi_cols_map[i].type)
	{
	  case DB_TYPE_CHAR:
	    cval = (char *)mfi + mfi_cols_map[i].offset;

	    *cval = sqlite3_column_int(stmt, i);
	    break;

	  case DB_TYPE_INT:
	    ival = (uint32_t *) ((char *)mfi + mfi_cols_map[i].offset);

	    if (mfi_cols_map[i].offset == mfi_offsetof(disabled))
	      {
		disabled = sqlite3_column_int64(stmt, i);
		*ival = (disabled != 0);
	      }
	    else
	      *ival = sqlite3_column_int(stmt, i);
	    break;

	  case DB_TYPE_INT64:
	    i64val = (uint64_t *) ((char *)mfi + mfi_cols_map[i].offset);

	    *i64val = sqlite3_column_int64(stmt, i);
	    break;

	  case DB_TYPE_STRING:
	    strval = (char **) ((char *)mfi + mfi_cols_map[i].offset);

	    cval = (char *)sqlite3_column_text(stmt, i);
	    if (cval)
	      *strval = strdup(cval);
	    break;

	  default:
	    DPRINTF(E_LOG, L_DB, "BUG: Unknown type %d in mfi column map\n", mfi_cols_map[i].type);

	    free_mfi(mfi, 0);
	    sqlite3_finalize(stmt);
	    return NULL;
	}
    }

#ifdef DB_PROFILE
  while (db_blocking_step(stmt) == SQLITE_ROW)
    ; /* EMPTY */
#endif

  sqlite3_finalize(stmt);

  return mfi;
}

struct media_file_info *
db_file_fetch_byid(int id)
{
#define Q_TMPL "SELECT f.* FROM files f WHERE f.id = %d;"
  struct media_file_info *mfi;
  char *query;

  query = sqlite3_mprintf(Q_TMPL, id);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return NULL;
    }

  mfi = db_file_fetch_byquery(query);

  sqlite3_free(query);

  return mfi;

#undef Q_TMPL
}

int
db_file_add(struct media_file_info *mfi)
{
#define Q_TMPL "INSERT INTO files (id, path, fname, title, artist, album, genre, comment, type, composer," \
               " orchestra, conductor, grouping, url, bitrate, samplerate, song_length, file_size, year, track," \
               " total_tracks, disc, total_discs, bpm, compilation, rating, play_count, data_kind, item_kind," \
               " description, time_added, time_modified, time_played, db_timestamp, disabled, sample_count," \
               " codectype, idx, has_video, contentrating, bits_per_sample, album_artist," \
               " media_kind, tv_series_name, tv_episode_num_str, tv_network_name, tv_episode_sort, tv_season_num, " \
               " songalbumid, title_sort, artist_sort, album_sort, composer_sort, album_artist_sort" \
               " ) " \
               " VALUES (NULL, '%q', '%q', TRIM(%Q), TRIM(%Q), TRIM(%Q), TRIM(%Q), TRIM(%Q), %Q, TRIM(%Q)," \
               " TRIM(%Q), TRIM(%Q), TRIM(%Q), %Q, %d, %d, %d, %" PRIi64 ", %d, %d," \
               " %d, %d, %d, %d, %d, %d, %d, %d, %d," \
               " %Q, %" PRIi64 ", %" PRIi64 ", %" PRIi64 ", %" PRIi64 ", %d, %" PRIi64 "," \
               " %Q, %d, %d, %d, %d, TRIM(%Q), %d, TRIM(%Q), TRIM(%Q), TRIM(%Q), %d, %d, daap_songalbumid(TRIM(%Q), TRIM(%Q))," \
               " TRIM(%Q), TRIM(%Q), TRIM(%Q), TRIM(%Q), TRIM(%Q));"

  char *query;
  char *errmsg;
  int ret;


  if (mfi->id != 0)
    {
      DPRINTF(E_WARN, L_DB, "Trying to add file with non-zero id; use db_file_update()?\n");
      return -1;
    }

  mfi->db_timestamp = (uint64_t)time(NULL);
  mfi->time_added = mfi->db_timestamp;

  if (mfi->time_modified == 0)
    mfi->time_modified = mfi->db_timestamp;

  query = sqlite3_mprintf(Q_TMPL,
			  STR(mfi->path), STR(mfi->fname), mfi->title, mfi->artist, mfi->album,
			  mfi->genre, mfi->comment, mfi->type, mfi->composer,
			  mfi->orchestra, mfi->conductor, mfi->grouping, mfi->url, mfi->bitrate,
			  mfi->samplerate, mfi->song_length, mfi->file_size, mfi->year, mfi->track,
			  mfi->total_tracks, mfi->disc, mfi->total_discs, mfi->bpm, mfi->compilation,
			  mfi->rating, mfi->play_count, mfi->data_kind, mfi->item_kind,
			  mfi->description, (int64_t)mfi->time_added, (int64_t)mfi->time_modified,
			  (int64_t)mfi->time_played, (int64_t)mfi->db_timestamp, mfi->disabled, mfi->sample_count,
			  mfi->codectype, mfi->index, mfi->has_video,
			  mfi->contentrating, mfi->bits_per_sample, mfi->album_artist,
                          mfi->media_kind, mfi->tv_series_name, mfi->tv_episode_num_str, 
                          mfi->tv_network_name, mfi->tv_episode_sort, mfi->tv_season_num,
			  mfi->album_artist, mfi->album, mfi->title_sort, mfi->artist_sort, mfi->album_sort,
			  mfi->composer_sort, mfi->album_artist_sort);

  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Query error: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  return 0;

#undef Q_TMPL
}

int
db_file_update(struct media_file_info *mfi)
{
#define Q_TMPL "UPDATE files SET path = '%q', fname = '%q', title = TRIM(%Q), artist = TRIM(%Q), album = TRIM(%Q), genre = TRIM(%Q)," \
               " comment = TRIM(%Q), type = %Q, composer = TRIM(%Q), orchestra = TRIM(%Q), conductor = TRIM(%Q), grouping = TRIM(%Q)," \
               " url = %Q, bitrate = %d, samplerate = %d, song_length = %d, file_size = %" PRIi64 "," \
               " year = %d, track = %d, total_tracks = %d, disc = %d, total_discs = %d, bpm = %d," \
               " compilation = %d, rating = %d, data_kind = %d, item_kind = %d," \
               " description = %Q, time_modified = %" PRIi64 "," \
               " db_timestamp = %" PRIi64 ", sample_count = %" PRIi64 "," \
               " codectype = %Q, idx = %d, has_video = %d," \
               " bits_per_sample = %d, album_artist = TRIM(%Q)," \
               " media_kind = %d, tv_series_name = TRIM(%Q), tv_episode_num_str = TRIM(%Q)," \
               " tv_network_name = TRIM(%Q), tv_episode_sort = %d, tv_season_num = %d," \
               " songalbumid = daap_songalbumid(TRIM(%Q), TRIM(%Q))," \
               " title_sort = TRIM(%Q), artist_sort = TRIM(%Q), album_sort = TRIM(%Q), composer_sort = TRIM(%Q), album_artist_sort = TRIM(%Q)" \
               " WHERE id = %d;"
  char *query;
  char *errmsg;
  int ret;

  if (mfi->id == 0)
    {
      DPRINTF(E_WARN, L_DB, "Trying to update file with id 0; use db_file_add()?\n");
      return -1;
    }

  mfi->db_timestamp = (uint64_t)time(NULL);

  if (mfi->time_modified == 0)
    mfi->time_modified = mfi->db_timestamp;

  query = sqlite3_mprintf(Q_TMPL,
			  STR(mfi->path), STR(mfi->fname), mfi->title, mfi->artist, mfi->album, mfi->genre,
			  mfi->comment, mfi->type, mfi->composer, mfi->orchestra, mfi->conductor, mfi->grouping, 
			  mfi->url, mfi->bitrate, mfi->samplerate, mfi->song_length, mfi->file_size,
			  mfi->year, mfi->track, mfi->total_tracks, mfi->disc, mfi->total_discs, mfi->bpm,
			  mfi->compilation, mfi->rating, mfi->data_kind, mfi->item_kind,
			  mfi->description, (int64_t)mfi->time_modified,
			  (int64_t)mfi->db_timestamp, mfi->sample_count,
			  mfi->codectype, mfi->index, mfi->has_video,
			  mfi->bits_per_sample, mfi->album_artist,
			  mfi->media_kind, mfi->tv_series_name, mfi->tv_episode_num_str, 
			  mfi->tv_network_name, mfi->tv_episode_sort, mfi->tv_season_num,
			  mfi->album_artist, mfi->album,
			  mfi->title_sort, mfi->artist_sort, mfi->album_sort,
			  mfi->composer_sort, mfi->album_artist_sort,
			  mfi->id);

  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Query error: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  return 0;

#undef Q_TMPL
}

void
db_file_delete_bypath(char *path)
{
#define Q_TMPL "DELETE FROM files WHERE path = '%q';"
  char *query;
  char *errmsg;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error deleting file: %s\n", errmsg);

  sqlite3_free(errmsg);
  sqlite3_free(query);

#undef Q_TMPL
}

static void
db_file_disable_byquery(char *query)
{
  char *errmsg;
  int ret;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error disabling file: %s\n", errmsg);

  sqlite3_free(errmsg);
}

void
db_file_disable_bypath(char *path, char *strip, uint32_t cookie)
{
#define Q_TMPL "UPDATE files SET path = substr(path, %d), disabled = %" PRIi64 " WHERE path = '%q';"
  char *query;
  int64_t disabled;
  int striplen;

  disabled = (cookie != 0) ? cookie : INOTIFY_FAKE_COOKIE;
  striplen = strlen(strip) + 1;

  query = sqlite3_mprintf(Q_TMPL, striplen, disabled, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  db_file_disable_byquery(query);

  sqlite3_free(query);

#undef Q_TMPL
}

void
db_file_disable_bymatch(char *path, char *strip, uint32_t cookie)
{
#define Q_TMPL "UPDATE files SET path = substr(path, %d), disabled = %" PRIi64 " WHERE path LIKE '%q/%%';"
  char *query;
  int64_t disabled;
  int striplen;

  disabled = (cookie != 0) ? cookie : INOTIFY_FAKE_COOKIE;
  striplen = strlen(strip) + 1;

  query = sqlite3_mprintf(Q_TMPL, striplen, disabled, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  db_file_disable_byquery(query);

  sqlite3_free(query);

#undef Q_TMPL
}

int
db_file_enable_bycookie(uint32_t cookie, char *path)
{
#define Q_TMPL "UPDATE files SET path = '%q' || path, disabled = 0 WHERE disabled = %" PRIi64 ";"
  char *query;
  char *errmsg;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, path, (int64_t)cookie);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Error enabling files: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  return sqlite3_changes(pool_hdl->hdl);

#undef Q_TMPL
}


/* Playlists */
int
db_pl_get_count(void)
{
  return db_get_count("SELECT COUNT(*) FROM playlists p WHERE p.disabled = 0;");
}

static int
db_pl_count_items(int id)
{
#define Q_TMPL "SELECT COUNT(*) FROM playlistitems pi JOIN files f" \
               " ON pi.filepath = f.path WHERE f.disabled = 0 AND pi.playlistid = %d;"
  char *query;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, id);

  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return 0;
    }

  ret = db_get_count(query);

  sqlite3_free(query);

  return ret;

#undef Q_TMPL
}

static int
db_smartpl_count_items(const char *smartpl_query)
{
#define Q_TMPL "SELECT COUNT(*) FROM files f WHERE f.disabled = 0 AND %s;"
  char *query;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, smartpl_query);

  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return 0;
    }

  ret = db_get_count(query);

  sqlite3_free(query);

  return ret;

#undef Q_TMPL
}

void
db_pl_ping(int id)
{
#define Q_TMPL "UPDATE playlists SET db_timestamp = %" PRIi64 ", disabled = 0 WHERE id = %d;"
  char *query;
  char *errmsg;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, (int64_t)time(NULL), id);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error pinging playlist %d: %s\n", id, errmsg);

  sqlite3_free(errmsg);
  sqlite3_free(query);

#undef Q_TMPL
}

static int
db_pl_id_bypath(char *path, int *id)
{
#define Q_TMPL "SELECT p.id FROM playlists p WHERE p.path = '%q';"
  char *query;
  sqlite3_stmt *stmt;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_blocking_prepare_v2(query, -1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_free(query);
      return -1;
    }

  ret = db_blocking_step(stmt);
  if (ret != SQLITE_ROW)
    {
      if (ret == SQLITE_DONE)
	DPRINTF(E_INFO, L_DB, "No results\n");
      else
	DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);
      sqlite3_free(query);
      return -1;
    }

  *id = sqlite3_column_int(stmt, 0);

#ifdef DB_PROFILE
  while (db_blocking_step(stmt) == SQLITE_ROW)
    ; /* EMPTY */
#endif

  sqlite3_finalize(stmt);
  sqlite3_free(query);

  return 0;

#undef Q_TMPL
}

static struct playlist_info *
db_pl_fetch_byquery(char *query)
{
  struct playlist_info *pli;
  sqlite3_stmt *stmt;
  int ncols;
  char *cval;
  uint32_t *ival;
  char **strval;
  uint64_t disabled;
  int i;
  int ret;

  if (!query)
    return NULL;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  pli = (struct playlist_info *)malloc(sizeof(struct playlist_info));
  if (!pli)
    {
      DPRINTF(E_LOG, L_DB, "Could not allocate struct playlist_info, out of memory\n");
      return NULL;
    }
  memset(pli, 0, sizeof(struct playlist_info));

  ret = db_blocking_prepare_v2(query, -1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      free(pli);
      return NULL;
    }

  ret = db_blocking_step(stmt);
  if (ret != SQLITE_ROW)
    {
      if (ret == SQLITE_DONE)
	DPRINTF(E_INFO, L_DB, "No results\n");
      else
	DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);
      free(pli);
      return NULL;
    }

  ncols = sqlite3_column_count(stmt);

  if (sizeof(pli_cols_map) / sizeof(pli_cols_map[0]) != ncols)
    {
      DPRINTF(E_LOG, L_DB, "BUG: pli column map out of sync with schema\n");

      sqlite3_finalize(stmt);
      free(pli);
      return NULL;
    }

  for (i = 0; i < ncols; i++)
    {
      switch (pli_cols_map[i].type)
	{
	  case DB_TYPE_INT:
	    ival = (uint32_t *) ((char *)pli + pli_cols_map[i].offset);

	    if (pli_cols_map[i].offset == pli_offsetof(disabled))
	      {
		disabled = sqlite3_column_int64(stmt, i);
		*ival = (disabled != 0);
	      }
	    else
	      *ival = sqlite3_column_int(stmt, i);
	    break;

	  case DB_TYPE_STRING:
	    strval = (char **) ((char *)pli + pli_cols_map[i].offset);

	    cval = (char *)sqlite3_column_text(stmt, i);
	    if (cval)
	      *strval = strdup(cval);
	    break;

	  default:
	    DPRINTF(E_LOG, L_DB, "BUG: Unknown type %d in pli column map\n", pli_cols_map[i].type);

	    sqlite3_finalize(stmt);
	    free_pli(pli, 0);
	    return NULL;
	}
    }

  ret = db_blocking_step(stmt);
  sqlite3_finalize(stmt);

  if (ret != SQLITE_DONE)
    {
      DPRINTF(E_WARN, L_DB, "Query had more than a single result!\n");

      free_pli(pli, 0);
      return NULL;
    }

  switch (pli->type)
    {
      case PL_PLAIN:
	pli->items = db_pl_count_items(pli->id);
	break;

      case PL_SMART:
	pli->items = db_smartpl_count_items(pli->query);
	break;

      default:
	DPRINTF(E_LOG, L_DB, "Unknown playlist type %d while fetching playlist\n", pli->type);

	free_pli(pli, 0);
	return NULL;
    }

  return pli;
}

struct playlist_info *
db_pl_fetch_bypath(char *path)
{
#define Q_TMPL "SELECT p.* FROM playlists p WHERE p.path = '%q';"
  struct playlist_info *pli;
  char *query;

  query = sqlite3_mprintf(Q_TMPL, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return NULL;
    }

  pli = db_pl_fetch_byquery(query);

  sqlite3_free(query);

  return pli;

#undef Q_TMPL
}

struct playlist_info *
db_pl_fetch_byid(int id)
{
#define Q_TMPL "SELECT p.* FROM playlists p WHERE p.id = %d;"
  struct playlist_info *pli;
  char *query;

  query = sqlite3_mprintf(Q_TMPL, id);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return NULL;
    }

  pli = db_pl_fetch_byquery(query);

  sqlite3_free(query);

  return pli;

#undef Q_TMPL
}

struct playlist_info *
db_pl_fetch_bytitlepath(char *title, char *path)
{
#define Q_TMPL "SELECT p.* FROM playlists p WHERE p.title = '%q' AND p.path = '%q';"
  struct playlist_info *pli;
  char *query;

  query = sqlite3_mprintf(Q_TMPL, title, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return NULL;
    }

  pli = db_pl_fetch_byquery(query);

  sqlite3_free(query);

  return pli;

#undef Q_TMPL
}

int
db_pl_add(char *title, char *path, int *id)
{
#define QDUP_TMPL "SELECT COUNT(*) FROM playlists p WHERE p.title = '%q' AND p.path = '%q';"
#define QADD_TMPL "INSERT INTO playlists (title, type, query, db_timestamp, disabled, path, idx, special_id)" \
                  " VALUES ('%q', 0, NULL, %" PRIi64 ", 0, '%q', 0, 0);"
  char *query;
  char *errmsg;
  int ret;

  /* Check duplicates */
  query = sqlite3_mprintf(QDUP_TMPL, title, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  ret = db_get_count(query);

  sqlite3_free(query);

  if (ret > 0)
    {
      DPRINTF(E_WARN, L_DB, "Duplicate playlist with title '%s' path '%s'\n", title, path);
      return -1;
    }

  /* Add */
  query = sqlite3_mprintf(QADD_TMPL, title, (int64_t)time(NULL), path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Query error: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  *id = (int)sqlite3_last_insert_rowid(pool_hdl->hdl);
  if (*id == 0)
    {
      DPRINTF(E_LOG, L_DB, "Successful insert but no last_insert_rowid!\n");
      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Added playlist %s (path %s) with id %d\n", title, path, *id);

  return 0;

#undef QDUP_TMPL
#undef QADD_TMPL
}

int
db_pl_add_item_bypath(int plid, char *path)
{
#define Q_TMPL "INSERT INTO playlistitems (playlistid, filepath) VALUES (%d, '%q');"
  char *query;
  char *errmsg;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, plid, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Query error: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  return 0;

#undef Q_TMPL
}

int
db_pl_add_item_byid(int plid, int fileid)
{
#define Q_TMPL "INSERT INTO playlistitems (playlistid, filepath) VALUES (%d, (SELECT f.path FROM files f WHERE f.id = %d));"
  char *query;
  char *errmsg;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, plid, fileid);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Query error: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  return 0;

#undef Q_TMPL
}

void
db_pl_clear_items(int id)
{
#define Q_TMPL "DELETE FROM playlistitems WHERE playlistid = %d;"
  char *query;
  char *errmsg;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, id);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error clearing playlist %d items: %s\n", id, errmsg);

  sqlite3_free(errmsg);
  sqlite3_free(query);

#undef Q_TMPL
}

void
db_pl_delete(int id)
{
#define Q_TMPL "DELETE FROM playlists WHERE id = %d;"
  char *query;
  char *errmsg;
  int ret;

  if (id == 1)
    return;

  query = sqlite3_mprintf(Q_TMPL, id);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error deleting playlist %d: %s\n", id, errmsg);

  sqlite3_free(errmsg);
  sqlite3_free(query);

  db_pl_clear_items(id);

#undef Q_TMPL
}

void
db_pl_delete_bypath(char *path)
{
  int id;
  int ret;

  ret = db_pl_id_bypath(path, &id);
  if (ret < 0)
    return;

  db_pl_delete(id);
}

static void
db_pl_disable_byquery(char *query)
{
  char *errmsg;
  int ret;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error disabling playlist: %s\n", errmsg);

  sqlite3_free(errmsg);
}

void
db_pl_disable_bypath(char *path, char *strip, uint32_t cookie)
{
#define Q_TMPL "UPDATE playlists SET path = substr(path, %d), disabled = %" PRIi64 " WHERE path = '%q';"
  char *query;
  int64_t disabled;
  int striplen;

  disabled = (cookie != 0) ? cookie : INOTIFY_FAKE_COOKIE;
  striplen = strlen(strip) + 1;

  query = sqlite3_mprintf(Q_TMPL, striplen, disabled, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  db_pl_disable_byquery(query);

  sqlite3_free(query);

#undef Q_TMPL
}

void
db_pl_disable_bymatch(char *path, char *strip, uint32_t cookie)
{
#define Q_TMPL "UPDATE playlists SET path = substr(path, %d), disabled = %" PRIi64 " WHERE path LIKE '%q/%%';"
  char *query;
  int64_t disabled;
  int striplen;

  disabled = (cookie != 0) ? cookie : INOTIFY_FAKE_COOKIE;
  striplen = strlen(strip) + 1;

  query = sqlite3_mprintf(Q_TMPL, striplen, disabled, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  db_pl_disable_byquery(query);

  sqlite3_free(query);

#undef Q_TMPL
}

int
db_pl_enable_bycookie(uint32_t cookie, char *path)
{
#define Q_TMPL "UPDATE playlists SET path = '%q' || path, disabled = 0 WHERE disabled = %" PRIi64 ";"
  char *query;
  char *errmsg;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, path, (int64_t)cookie);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Error enabling playlists: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  return sqlite3_changes(pool_hdl->hdl);

#undef Q_TMPL
}


/* Groups */
int
db_groups_clear(void)
{
  char *query = "DELETE FROM groups;";
  char *errmsg;
  int ret;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Query error: %s\n", errmsg);

      sqlite3_free(errmsg);
      return -1;
    }

  return 0;
}

enum group_type
db_group_type_byid(int id)
{
#define Q_TMPL "SELECT g.type FROM groups g WHERE g.id = '%d';"
  char *query;
  sqlite3_stmt *stmt;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, id);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return 0;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_blocking_prepare_v2(query, strlen(query) + 1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_free(query);
      return 0;
    }

  ret = db_blocking_step(stmt);
  if (ret != SQLITE_ROW)
    {
      if (ret == SQLITE_DONE)
	DPRINTF(E_INFO, L_DB, "No results\n");
      else
	DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);
      sqlite3_free(query);
      return 0;
    }

  ret = sqlite3_column_int(stmt, 0);

#ifdef DB_PROFILE
  while (db_blocking_step(stmt) == SQLITE_ROW)
    ; /* EMPTY */
#endif

  sqlite3_finalize(stmt);
  sqlite3_free(query);

  return ret;

#undef Q_TMPL
}

/* Remotes */
static int
db_pairing_delete_byremote(char *remote_id)
{
#define Q_TMPL "DELETE FROM pairings WHERE remote = '%q';"
  char *query;
  char *errmsg;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, remote_id);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Error deleting pairing: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  return 0;

#undef Q_TMPL
}

int
db_pairing_add(struct pairing_info *pi)
{
#define Q_TMPL "INSERT INTO pairings (remote, name, guid) VALUES ('%q', '%q', '%q');"
  char *query;
  char *errmsg;
  int ret;

  ret = db_pairing_delete_byremote(pi->remote_id);
  if (ret < 0)
    return ret;

  query = sqlite3_mprintf(Q_TMPL, pi->remote_id, pi->name, pi->guid);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Error adding pairing: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  return 0;

#undef Q_TMPL
}

int
db_pairing_fetch_byguid(struct pairing_info *pi)
{
#define Q_TMPL "SELECT p.* FROM pairings p WHERE p.guid = '%q';"
  char *query;
  sqlite3_stmt *stmt;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, pi->guid);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_blocking_prepare_v2(query, -1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));
      return -1;
    }

  ret = db_blocking_step(stmt);
  if (ret != SQLITE_ROW)
    {
      if (ret == SQLITE_DONE)
	DPRINTF(E_INFO, L_DB, "Pairing GUID %s not found\n", pi->guid);
      else
	DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);
      sqlite3_free(query);
      return -1;
    }

  pi->remote_id = strdup((char *)sqlite3_column_text(stmt, 0));
  pi->name = strdup((char *)sqlite3_column_text(stmt, 1));

#ifdef DB_PROFILE
  while (db_blocking_step(stmt) == SQLITE_ROW)
    ; /* EMPTY */
#endif

  sqlite3_finalize(stmt);
  sqlite3_free(query);

  return 0;

#undef Q_TMPL
}


/* Speakers */
int
db_speaker_save(uint64_t id, int selected, int volume)
{
#define Q_TMPL "INSERT OR REPLACE INTO speakers (id, selected, volume) VALUES (%" PRIi64 ", %d, %d);"
  char *query;
  char *errmsg;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, id, selected, volume);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  errmsg = NULL;
  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Error saving speaker state: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  return 0;

#undef Q_TMPL
}

int
db_speaker_get(uint64_t id, int *selected, int *volume)
{
#define Q_TMPL "SELECT s.selected, s.volume FROM speakers s WHERE s.id = %" PRIi64 ";"
  sqlite3_stmt *stmt;
  char *query;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, id);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_blocking_prepare_v2(query, -1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      ret = -1;
      goto out;
    }

  ret = db_blocking_step(stmt);
  if (ret != SQLITE_ROW)
    {
      if (ret != SQLITE_DONE)
	DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);

      ret = -1;
      goto out;
    }

  *selected = sqlite3_column_int(stmt, 0);
  *volume = sqlite3_column_int(stmt, 1);

#ifdef DB_PROFILE
  while (db_blocking_step(stmt) == SQLITE_ROW)
    ; /* EMPTY */
#endif

  sqlite3_finalize(stmt);

  ret = 0;

 out:
  sqlite3_free(query);
  return ret;

#undef Q_TMPL
}

void
db_speaker_clear_all(void)
{
  char *query = "UPDATE speakers SET selected = 0;";
  char *errmsg;
  int ret;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Query error: %s\n", errmsg);

      sqlite3_free(errmsg);
    }
}


/* Inotify */
int
db_watch_clear(void)
{
  char *query = "DELETE FROM inotify;";
  char *errmsg;
  int ret;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Query error: %s\n", errmsg);

      sqlite3_free(errmsg);
      return -1;
    }

  return 0;
}

int
db_watch_add(struct watch_info *wi)
{
#define Q_TMPL "INSERT INTO inotify (wd, cookie, path) VALUES (%d, 0, '%q');"
  char *query;
  char *errmsg;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, wi->wd, wi->path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Error adding watch: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  return 0;

#undef Q_TMPL
}

static int
db_watch_delete_byquery(char *query)
{
  char *errmsg;
  int ret;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Error deleting watch: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
      return -1;
    }

  return 0;
}

int
db_watch_delete_bywd(uint32_t wd)
{
#define Q_TMPL "DELETE FROM inotify WHERE wd = %d;"
  char *query;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, wd);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  ret = db_watch_delete_byquery(query);

  sqlite3_free(query);

  return ret;

#undef Q_TMPL
}

int
db_watch_delete_bypath(char *path)
{
#define Q_TMPL "DELETE FROM inotify WHERE path = '%q';"
  char *query;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  ret = db_watch_delete_byquery(query);

  sqlite3_free(query);

  return ret;

#undef Q_TMPL
}

int
db_watch_delete_bymatch(char *path)
{
#define Q_TMPL "DELETE FROM inotify WHERE path LIKE '%q/%%';"
  char *query;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  ret = db_watch_delete_byquery(query);

  sqlite3_free(query);

  return ret;

#undef Q_TMPL
}

int
db_watch_delete_bycookie(uint32_t cookie)
{
#define Q_TMPL "DELETE FROM inotify WHERE cookie = %" PRIi64 ";"
  char *query;
  int ret;

  if (cookie == 0)
    return -1;

  query = sqlite3_mprintf(Q_TMPL, (int64_t)cookie);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  ret = db_watch_delete_byquery(query);

  sqlite3_free(query);

  return ret;

#undef Q_TMPL
}

int
db_watch_get_bywd(struct watch_info *wi)
{
#define Q_TMPL "SELECT * FROM inotify WHERE wd = %d;"
  char *query;
  sqlite3_stmt *stmt;
  char **strval;
  char *cval;
  uint32_t *ival;
  int64_t cookie;
  int ncols;
  int i;
  int ret;

  query = sqlite3_mprintf(Q_TMPL, wi->wd);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");
      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_blocking_prepare_v2(query, -1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));
      return -1;
    }

  ret = db_blocking_step(stmt);
  if (ret != SQLITE_ROW)
    {
      DPRINTF(E_LOG, L_DB, "Watch wd %d not found\n", wi->wd);

      sqlite3_finalize(stmt);
      sqlite3_free(query);
      return -1;
    }

  ncols = sqlite3_column_count(stmt);

  if (sizeof(wi_cols_map) / sizeof(wi_cols_map[0]) != ncols)
    {
      DPRINTF(E_LOG, L_DB, "BUG: wi column map out of sync with schema\n");

      sqlite3_finalize(stmt);
      sqlite3_free(query);
      return -1;
    }

  for (i = 0; i < ncols; i++)
    {
      switch (wi_cols_map[i].type)
	{
	  case DB_TYPE_INT:
	    ival = (uint32_t *) ((char *)wi + wi_cols_map[i].offset);

	    if (wi_cols_map[i].offset == wi_offsetof(cookie))
	      {
		cookie = sqlite3_column_int64(stmt, i);
		*ival = (cookie == INOTIFY_FAKE_COOKIE) ? 0 : cookie;
	      }
	    else
	      *ival = sqlite3_column_int(stmt, i);
	    break;

	  case DB_TYPE_STRING:
	    strval = (char **) ((char *)wi + wi_cols_map[i].offset);

	    cval = (char *)sqlite3_column_text(stmt, i);
	    if (cval)
	      *strval = strdup(cval);
	    break;

	  default:
	    DPRINTF(E_LOG, L_DB, "BUG: Unknown type %d in wi column map\n", wi_cols_map[i].type);
	    sqlite3_finalize(stmt);
	    sqlite3_free(query);
	    return -1;
	}
    }

#ifdef DB_PROFILE
  while (db_blocking_step(stmt) == SQLITE_ROW)
    ; /* EMPTY */
#endif

  sqlite3_finalize(stmt);
  sqlite3_free(query);

  return 0;

#undef Q_TMPL
}

static void
db_watch_mark_byquery(char *query)
{
  char *errmsg;
  int ret;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error marking watch: %s\n", errmsg);

  sqlite3_free(errmsg);
}

void
db_watch_mark_bypath(char *path, char *strip, uint32_t cookie)
{
#define Q_TMPL "UPDATE inotify SET path = substr(path, %d), cookie = %" PRIi64 " WHERE path = '%q';"
  char *query;
  int64_t disabled;
  int striplen;

  disabled = (cookie != 0) ? cookie : INOTIFY_FAKE_COOKIE;
  striplen = strlen(strip) + 1;

  query = sqlite3_mprintf(Q_TMPL, striplen, disabled, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  db_watch_mark_byquery(query);

  sqlite3_free(query);

#undef Q_TMPL
}

void
db_watch_mark_bymatch(char *path, char *strip, uint32_t cookie)
{
#define Q_TMPL "UPDATE inotify SET path = substr(path, %d), cookie = %" PRIi64 " WHERE path LIKE '%q/%%';"
  char *query;
  int64_t disabled;
  int striplen;

  disabled = (cookie != 0) ? cookie : INOTIFY_FAKE_COOKIE;
  striplen = strlen(strip) + 1;

  query = sqlite3_mprintf(Q_TMPL, striplen, disabled, path);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  db_watch_mark_byquery(query);

  sqlite3_free(query);

#undef Q_TMPL
}

void
db_watch_move_bycookie(uint32_t cookie, char *path)
{
#define Q_TMPL "UPDATE inotify SET path = '%q' || path, cookie = 0 WHERE cookie = %" PRIi64 ";"
  char *query;
  char *errmsg;
  int ret;

  if (cookie == 0)
    return;

  query = sqlite3_mprintf(Q_TMPL, path, (int64_t)cookie);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = db_exec(query, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error moving watch: %s\n", errmsg);

  sqlite3_free(errmsg);
  sqlite3_free(query);

#undef Q_TMPL
}

int
db_watch_cookie_known(uint32_t cookie)
{
#define Q_TMPL "SELECT COUNT(*) FROM inotify WHERE cookie = %" PRIi64 ";"
  char *query;
  int ret;

  if (cookie == 0)
    return 0;

  query = sqlite3_mprintf(Q_TMPL, (int64_t)cookie);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return 0;
    }

  ret = db_get_count(query);

  sqlite3_free(query);

  return (ret > 0);

#undef Q_TMPL
}

int
db_watch_enum_start(struct watch_enum *we)
{
#define Q_MATCH_TMPL "SELECT wd FROM inotify WHERE path LIKE '%q/%%';"
#define Q_COOKIE_TMPL "SELECT wd FROM inotify WHERE cookie = %" PRIi64 ";"
  char *query;
  int ret;

  we->stmt = NULL;

  if (we->match)
    query = sqlite3_mprintf(Q_MATCH_TMPL, we->match);
  else if (we->cookie != 0)
    query = sqlite3_mprintf(Q_COOKIE_TMPL, we->cookie);
  else
    {
      DPRINTF(E_LOG, L_DB, "Could not start enum, no parameter given\n");
      return -1;
    }

  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Starting enum '%s'\n", query);

  ret = db_blocking_prepare_v2(query, -1, &we->stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_free(query);
      return -1;
    }

  sqlite3_free(query);

  return 0;

#undef Q_MATCH_TMPL
#undef Q_COOKIE_TMPL
}

void
db_watch_enum_end(struct watch_enum *we)
{
  if (!we->stmt)
    return;

  sqlite3_finalize(we->stmt);
  we->stmt = NULL;
}

int
db_watch_enum_fetchwd(struct watch_enum *we, uint32_t *wd)
{
  int ret;

  *wd = 0;

  if (!we->stmt)
    {
      DPRINTF(E_LOG, L_DB, "Watch enum not started!\n");
      return -1;
    }

  ret = db_blocking_step(we->stmt);
  if (ret == SQLITE_DONE)
    {
      DPRINTF(E_INFO, L_DB, "End of watch enum results\n");
      return 0;
    }
  else if (ret != SQLITE_ROW)
    {
      DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));
      return -1;
    }

  *wd = (uint32_t)sqlite3_column_int(we->stmt, 0);

  return 0;
}


#ifdef DB_PROFILE
static void
db_xprofile(void *notused, const char *pquery, sqlite3_uint64 ptime)
{
  sqlite3_stmt *stmt;
  char *query;
  int ret;

  DPRINTF(E_DBG, L_DBPERF, "SQL PROFILE query: %s\n", pquery);
  DPRINTF(E_DBG, L_DBPERF, "SQL PROFILE time: %" PRIu64 " ms\n", ((uint64_t)ptime / 1000000));

  if ((strncmp(pquery, "SELECT", 6) != 0)
       && (strncmp(pquery, "UPDATE", 6) != 0)
       && (strncmp(pquery, "DELETE", 6) != 0))
      return;

  /* Disable profiling callback */
  sqlite3_profile(pool_hdl->hdl, NULL, NULL);

  query = sqlite3_mprintf("EXPLAIN QUERY PLAN %s", pquery);
  if (!query)
    {
      DPRINTF(E_DBG, L_DBPERF, "Query plan: Out of memory\n");

      goto out;
    }

  ret = db_blocking_prepare_v2(query, -1, &stmt, NULL);
  sqlite3_free(query);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_DBG, L_DBPERF, "Query plan: Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      goto out;
    }

  DPRINTF(E_DBG, L_DBPERF, "Query plan:\n");

  while ((ret = db_blocking_step(stmt)) == SQLITE_ROW)
    {
      DPRINTF(E_DBG, L_DBPERF, "(%d,%d,%d) %s\n",
	      sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1), sqlite3_column_int(stmt, 2),
	      sqlite3_column_text(stmt, 3));
    }

  if (ret != SQLITE_DONE)
    DPRINTF(E_DBG, L_DBPERF, "Query plan: Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

  DPRINTF(E_DBG, L_DBPERF, "---\n");

  sqlite3_finalize(stmt);

 out:
  /* Reenable profiling callback */
  sqlite3_profile(pool_hdl->hdl, db_xprofile, NULL);
}
#endif


/* Database connections */
static sqlite3 *
db_conn_open(void)
{
  sqlite3 *conn;
  char *errmsg;
  int ret;

  ret = sqlite3_open(db_path, &conn);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not open database: %s\n", sqlite3_errmsg(conn));

      goto fail;
    }

  ret = sqlite3_enable_load_extension(conn, 1);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not enable extension loading\n");

      goto fail;
    }

  errmsg = NULL;
  ret = sqlite3_load_extension(conn, PKGLIBDIR "/forked-daapd-sqlext.so", NULL, &errmsg);
  if (ret != SQLITE_OK)
    {
      if (errmsg)
	{
	  DPRINTF(E_LOG, L_DB, "Could not load SQLite extension: %s\n", errmsg);
	  sqlite3_free(errmsg);
	}
      else
	DPRINTF(E_LOG, L_DB, "Could not load SQLite extension: %s\n", sqlite3_errmsg(conn));

      goto fail;
    }

  ret = sqlite3_enable_load_extension(conn, 0);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not disable extension loading\n");

      goto fail;
    }

#ifdef DB_PROFILE
  sqlite3_profile(conn, db_xprofile, NULL);
#endif

  return conn;

 fail:
  sqlite3_close(conn);

  return NULL;
}

static void
db_conn_close(sqlite3 *conn)
{
  sqlite3_stmt *stmt;

  /* Tear down anything that's in flight */
  while ((stmt = sqlite3_next_stmt(conn, 0)))
    sqlite3_finalize(stmt);

  sqlite3_close(conn);
}


/* Database connection pool */
static int
db_pool_open(void)
{
  struct db_pool_hdl *ph;

  ph = (struct db_pool_hdl *)malloc(sizeof(struct db_pool_hdl));
  if (!ph)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for database connection pool\n");

      return -1;
    }

  memset(ph, 0, sizeof(struct db_pool_hdl));

  ph->hdl = db_conn_open();
  if (!ph->hdl)
    {
      free(ph);
      return -1;
    }

  pool_size++;

  ph->next = pool_free;
  pool_free = ph;

  return 0;
}

static void
db_pool_close(struct db_pool_hdl *ph)
{
  pool_size--;

  db_conn_close(ph->hdl);
  free(ph);
}

static void
db_pool_reclaim(void *arg)
{
  struct db_pool_hdl *ph;
  struct db_pool_hdl *ph_prev;
  time_t threshold;
  int reclaimed;

  DPRINTF(E_DBG, L_DB, "DB pool status: size %d free %d\n", pool_size, pool_free_size);

  if (pool_free_size <= DB_POOL_MIN_FREE)
    return;

  threshold = time(NULL) - DB_POOL_MAX_AGE;
  reclaimed = 0;

  ph_prev = NULL;
  for (ph = pool_free; ph && (pool_free_size > DB_POOL_MIN_FREE); /* EMPTY */)
    {
      if (ph->last <= threshold)
	{
	  if (ph_prev)
	    ph_prev->next = ph->next;
	  else
	    pool_free = ph->next;

	  db_pool_close(ph);

	  reclaimed++;
	  pool_free_size--;

	  if (ph_prev)
	    ph = ph_prev->next;
	  else
	    ph = pool_free;
	}
      else
	{
	  ph_prev = ph;
	  ph = ph->next;
	}
    }

  DPRINTF(E_DBG, L_DB, "DB pool status: reclaimed %d size %d free %d\n", reclaimed, pool_size, pool_free_size);
}

static void
db_pool_get_task(void *arg)
{
  struct db_pool_hdl *ph;
  struct db_pool_hdl **my_pool_hdl;
  int ret;

  my_pool_hdl = (struct db_pool_hdl **)arg;

  if (!pool_free)
    {
      ret = db_pool_open();
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DB, "Could not open a new database connection; no free connections available\n");

	  return;
	}
    }
  else
    pool_free_size--;

  /* Remove from free list */
  ph = pool_free;
  pool_free = ph->next;

  /* Add to used list */
  ph->next = pool_used;
  pool_used = ph;

  ph->saved = *my_pool_hdl;
  *my_pool_hdl = ph;
}

int
db_pool_get(void)
{
  struct db_pool_hdl *my_pool_hdl;

  my_pool_hdl = pool_hdl;

  dispatch_sync_f(dbpool_sq, &my_pool_hdl, db_pool_get_task);

  /* Failed to get a new pool_hdl */
  if (my_pool_hdl == pool_hdl)
    return -1;

  /* Set thread-local database handle */
  pool_hdl = my_pool_hdl;

  return 0;
}

static void
db_pool_release_task(void *arg)
{
  struct db_pool_hdl *ph;
  struct db_pool_hdl *ph_prev;
  struct db_pool_hdl *my_pool_hdl;

  my_pool_hdl = (struct db_pool_hdl *)arg;

  ph_prev = NULL;

  for (ph = pool_used; ph; ph = ph->next)
    {
      if (ph == my_pool_hdl)
	break;

      ph_prev = ph;
    }

  if (!ph)
    return;

  /* Remove from used list */
  if (!ph_prev)
    pool_used = ph->next;
  else
    ph_prev->next = ph->next;

  /* Add to free list */
  ph->next = pool_free;
  pool_free = ph;

  ph->last = time(NULL);
  pool_free_size++;
}

void
db_pool_release(void)
{
  struct db_pool_hdl *my_pool_hdl;

  /* Copy thread-local database handle */
  my_pool_hdl = pool_hdl;

  /* Restore thread-local database handle to previous value */
  pool_hdl = my_pool_hdl->saved;

  dispatch_async_f(dbpool_sq, my_pool_hdl, db_pool_release_task);
}

static int
db_pool_init(void)
{
  time_t now;
  int ret;

  pool_size = 0;
  pool_free_size = 0;
  pool_free = 0;
  pool_used = 0;

  dbpool_sq = dispatch_queue_create("org.forked-daapd.db-pool", NULL);
  if (!dbpool_sq)
    {
      DPRINTF(E_LOG, L_DB, "Could not create dispatch queue for database pool\n");

      return -1;
    }

  now = time(NULL);

  for (pool_size = 0; pool_size < DB_POOL_MIN_SIZE; pool_free_size++)
    {
      ret = db_pool_open();
      if (ret < 0)
	return -1;

      pool_free->last = now;
    }

  pool_reclaim_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dbpool_sq);
  if (!pool_reclaim_timer)
    {
      DPRINTF(E_LOG, L_DB, "Could not create timer for database pool reclaim\n");

      return -1;
    }

  dispatch_source_set_timer(pool_reclaim_timer,
			    dispatch_time(DISPATCH_TIME_NOW, DB_POOL_MAX_AGE_NSEC),
			    DB_POOL_MAX_AGE_NSEC, 30 * NSEC_PER_SEC);
  dispatch_source_set_event_handler_f(pool_reclaim_timer, db_pool_reclaim);
  dispatch_resume(pool_reclaim_timer);

  return 0;
}

static void
db_pool_deinit(void)
{
  struct db_pool_hdl *ph;

  dispatch_source_cancel(pool_reclaim_timer);
  dispatch_release(pool_reclaim_timer);

  dispatch_sync(dbpool_sq,
		^{
		  /* Nothing to do, just resynching with the queue */
		});

  dispatch_release(dbpool_sq);

  if (pool_used)
    DPRINTF(E_LOG, L_DB, "db_pool_deinit: some connections are still in use!\n");

  for (ph = pool_free; pool_free; ph = pool_free)
    {
      pool_free = ph->next;

      db_conn_close(ph->hdl);
      free(ph);
    }
}


/* Per-thread database handles */

static int
db_perthread_init(void)
{
  pool_hdl = (struct db_pool_hdl *)malloc(sizeof(struct db_pool_hdl));
  if (!pool_hdl)
    return -1;

  memset(pool_hdl, 0, sizeof(struct db_pool_hdl));

  pool_hdl->hdl = db_conn_open();
  if (!pool_hdl->hdl)
    {
      free(pool_hdl);
      pool_hdl = NULL;

      return -1;
    }

  return 0;
}

static void
db_perthread_deinit(void)
{
  if (!pool_hdl)
    return;

  db_conn_close(pool_hdl->hdl);

  free(pool_hdl);
  pool_hdl = NULL;
}


#define T_ADMIN					\
  "CREATE TABLE IF NOT EXISTS admin("		\
  "   key   VARCHAR(32) NOT NULL,"		\
  "   value VARCHAR(32) NOT NULL"		\
  ");"

#define T_FILES						\
  "CREATE TABLE IF NOT EXISTS files ("			\
  "   id                 INTEGER PRIMARY KEY NOT NULL,"	\
  "   path               VARCHAR(4096) NOT NULL,"	\
  "   fname              VARCHAR(255) NOT NULL,"	\
  "   title              VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   artist             VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   album              VARCHAR(1024) NOT NULL COLLATE DAAP,"		\
  "   genre              VARCHAR(255) DEFAULT NULL COLLATE DAAP,"	\
  "   comment            VARCHAR(4096) DEFAULT NULL COLLATE DAAP,"	\
  "   type               VARCHAR(255) DEFAULT NULL COLLATE DAAP,"	\
  "   composer           VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   orchestra          VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   conductor          VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   grouping           VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   url                VARCHAR(1024) DEFAULT NULL,"	\
  "   bitrate            INTEGER DEFAULT 0,"		\
  "   samplerate         INTEGER DEFAULT 0,"		\
  "   song_length        INTEGER DEFAULT 0,"		\
  "   file_size          INTEGER DEFAULT 0,"		\
  "   year               INTEGER DEFAULT 0,"		\
  "   track              INTEGER DEFAULT 0,"		\
  "   total_tracks       INTEGER DEFAULT 0,"		\
  "   disc               INTEGER DEFAULT 0,"		\
  "   total_discs        INTEGER DEFAULT 0,"		\
  "   bpm                INTEGER DEFAULT 0,"		\
  "   compilation        INTEGER DEFAULT 0,"		\
  "   rating             INTEGER DEFAULT 0,"		\
  "   play_count         INTEGER DEFAULT 0,"		\
  "   data_kind          INTEGER DEFAULT 0,"		\
  "   item_kind          INTEGER DEFAULT 0,"		\
  "   description        INTEGER DEFAULT 0,"		\
  "   time_added         INTEGER DEFAULT 0,"		\
  "   time_modified      INTEGER DEFAULT 0,"		\
  "   time_played        INTEGER DEFAULT 0,"		\
  "   db_timestamp       INTEGER DEFAULT 0,"		\
  "   disabled           INTEGER DEFAULT 0,"		\
  "   sample_count       INTEGER DEFAULT 0,"		\
  "   codectype          VARCHAR(5) DEFAULT NULL,"	\
  "   idx                INTEGER NOT NULL,"		\
  "   has_video          INTEGER DEFAULT 0,"		\
  "   contentrating      INTEGER DEFAULT 0,"		\
  "   bits_per_sample    INTEGER DEFAULT 0,"		\
  "   album_artist       VARCHAR(1024) NOT NULL COLLATE DAAP,"		\
  "   media_kind         INTEGER NOT NULL,"		\
  "   tv_series_name     VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   tv_episode_num_str VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   tv_network_name    VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   tv_episode_sort    INTEGER NOT NULL,"		\
  "   tv_season_num      INTEGER NOT NULL,"		\
  "   songalbumid        INTEGER NOT NULL,"		\
  "   title_sort         VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   artist_sort        VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   album_sort         VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   composer_sort      VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   album_artist_sort  VARCHAR(1024) DEFAULT NULL COLLATE DAAP"	\
  ");"

#define T_PL					\
  "CREATE TABLE IF NOT EXISTS playlists ("		\
  "   id             INTEGER PRIMARY KEY NOT NULL,"	\
  "   title          VARCHAR(255) NOT NULL COLLATE DAAP,"	\
  "   type           INTEGER NOT NULL,"			\
  "   query          VARCHAR(1024),"			\
  "   db_timestamp   INTEGER NOT NULL,"			\
  "   disabled       INTEGER DEFAULT 0,"		\
  "   path           VARCHAR(4096),"			\
  "   idx            INTEGER NOT NULL,"			\
  "   special_id     INTEGER DEFAULT 0"			\
  ");"

#define T_PLITEMS				\
  "CREATE TABLE IF NOT EXISTS playlistitems ("		\
  "   id             INTEGER PRIMARY KEY NOT NULL,"	\
  "   playlistid     INTEGER NOT NULL,"			\
  "   filepath       VARCHAR(4096) NOT NULL"		\
  ");"

#define T_GROUPS							\
  "CREATE TABLE IF NOT EXISTS groups ("					\
  "   id             INTEGER PRIMARY KEY NOT NULL,"			\
  "   type           INTEGER NOT NULL,"					\
  "   name           VARCHAR(1024) NOT NULL COLLATE DAAP,"		\
  "   persistentid   INTEGER NOT NULL,"					\
  "CONSTRAINT groups_type_unique_persistentid UNIQUE (type, persistentid)" \
  ");"

#define T_PAIRINGS					\
  "CREATE TABLE IF NOT EXISTS pairings("		\
  "   remote         VARCHAR(64) PRIMARY KEY NOT NULL,"	\
  "   name           VARCHAR(255) NOT NULL,"		\
  "   guid           VARCHAR(16) NOT NULL"		\
  ");"

#define T_SPEAKERS					\
  "CREATE TABLE IF NOT EXISTS speakers("		\
  "   id             INTEGER PRIMARY KEY NOT NULL,"	\
  "   selected       INTEGER NOT NULL,"			\
  "   volume         INTEGER NOT NULL"			\
  ");"

#define T_INOTIFY					\
  "CREATE TABLE IF NOT EXISTS inotify ("		\
  "   wd          INTEGER PRIMARY KEY NOT NULL,"	\
  "   cookie      INTEGER NOT NULL,"			\
  "   path        VARCHAR(4096) NOT NULL"		\
  ");"

#define I_RESCAN				\
  "CREATE INDEX IF NOT EXISTS idx_rescan ON files(path, db_timestamp);"

#define I_SONGALBUMID				\
  "CREATE INDEX IF NOT EXISTS idx_sai ON files(songalbumid);"

#define I_STATEMKINDSAI				\
  "CREATE INDEX IF NOT EXISTS idx_state_mkind_sai ON files(disabled, media_kind, songalbumid);"

#define I_ARTIST				\
  "CREATE INDEX IF NOT EXISTS idx_artist ON files(artist, artist_sort);"

#define I_ALBUMARTIST				\
  "CREATE INDEX IF NOT EXISTS idx_albumartist ON files(album_artist, album_artist_sort);"

#define I_COMPOSER				\
  "CREATE INDEX IF NOT EXISTS idx_composer ON files(composer, composer_sort);"

#define I_TITLE					\
  "CREATE INDEX IF NOT EXISTS idx_title ON files(title, title_sort);"

#define I_ALBUM					\
  "CREATE INDEX IF NOT EXISTS idx_album ON files(album, album_sort);"

#define I_PL_PATH				\
  "CREATE INDEX IF NOT EXISTS idx_pl_path ON playlists(path);"

#define I_PL_DISABLED				\
  "CREATE INDEX IF NOT EXISTS idx_pl_disabled ON playlists(disabled);"

#define I_FILEPATH							\
  "CREATE INDEX IF NOT EXISTS idx_filepath ON playlistitems(filepath ASC);"

#define I_PLITEMID							\
  "CREATE INDEX IF NOT EXISTS idx_playlistid ON playlistitems(playlistid, filepath);"

#define I_GRP_TYPE_PERSIST				\
  "CREATE INDEX IF NOT EXISTS idx_grp_type_persist ON groups(type, persistentid);"

#define I_PAIRING				\
  "CREATE INDEX IF NOT EXISTS idx_pairingguid ON pairings(guid);"


#define TRG_GROUPS_INSERT_FILES						\
  "CREATE TRIGGER update_groups_new_file AFTER INSERT ON files FOR EACH ROW" \
  " BEGIN"								\
  "   INSERT OR IGNORE INTO groups (type, name, persistentid) VALUES (1, NEW.album, NEW.songalbumid);" \
  " END;"

#define TRG_GROUPS_UPDATE_FILES						\
  "CREATE TRIGGER update_groups_update_file AFTER UPDATE OF songalbumid ON files FOR EACH ROW" \
  " BEGIN"								\
  "   INSERT OR IGNORE INTO groups (type, name, persistentid) VALUES (1, NEW.album, NEW.songalbumid);" \
  " END;"

#define Q_PL1								\
  "INSERT INTO playlists (id, title, type, query, db_timestamp, path, idx, special_id)" \
  " VALUES(1, 'Library', 1, '1 = 1', 0, '', 0, 0);"

#define Q_PL2								\
  "INSERT INTO playlists (id, title, type, query, db_timestamp, path, idx, special_id)" \
  " VALUES(2, 'Music', 1, 'f.media_kind = 1', 0, '', 0, 6);"

#define Q_PL3								\
  "INSERT INTO playlists (id, title, type, query, db_timestamp, path, idx, special_id)" \
  " VALUES(3, 'Movies', 1, 'f.media_kind = 2', 0, '', 0, 4);"

#define Q_PL4								\
  "INSERT INTO playlists (id, title, type, query, db_timestamp, path, idx, special_id)" \
  " VALUES(4, 'TV Shows', 1, 'f.media_kind = 64', 0, '', 0, 5);"

/* These are the remaining automatically-created iTunes playlists, but
 * their query is unknown
  " VALUES(5, 'Podcasts', 0, 'media_kind = 128 ', 0, '', 0, 1);"
  " VALUES(6, 'iTunes U', 0, 'media_kind = 256', 0, '', 0, 13);"
  " VALUES(7, 'Audiobooks', 0, 'media_kind = 512', 0, '', 0, 7);"
  " VALUES(8, 'Purchased', 0, 'media_kind = 1024', 0, '', 0, 8);"
 */

#define SCHEMA_VERSION 13
#define Q_SCVER					\
  "INSERT INTO admin (key, value) VALUES ('schema_version', '13');"

struct db_init_query {
  char *query;
  char *desc;
};

static const struct db_init_query db_init_queries[] =
  {
    { T_ADMIN,     "create table admin" },
    { T_FILES,     "create table files" },
    { T_PL,        "create table playlists" },
    { T_PLITEMS,   "create table playlistitems" },
    { T_GROUPS,    "create table groups" },
    { T_PAIRINGS,  "create table pairings" },
    { T_SPEAKERS,  "create table speakers" },
    { T_INOTIFY,   "create table inotify" },

    { I_RESCAN,    "create rescan index" },
    { I_SONGALBUMID, "create songalbumid index" },
    { I_STATEMKINDSAI, "create state/mkind/sai index" },

    { I_ARTIST,    "create artist index" },
    { I_ALBUMARTIST, "create album_artist index" },
    { I_COMPOSER,  "create composer index" },
    { I_TITLE,     "create title index" },
    { I_ALBUM,     "create album index" },

    { I_PL_PATH,   "create playlist path index" },
    { I_PL_DISABLED, "create playlist state index" },

    { I_FILEPATH,  "create file path index" },
    { I_PLITEMID,  "create playlist id index" },

    { I_GRP_TYPE_PERSIST, "create groups type/persistentid index" },

    { I_PAIRING,   "create pairing guid index" },

    { TRG_GROUPS_INSERT_FILES,    "create trigger update_groups_new_file" },
    { TRG_GROUPS_UPDATE_FILES,    "create trigger update_groups_update_file" },

    { Q_PL1,       "create default playlist" },
    { Q_PL2,       "create default smart playlist 'Music'" },
    { Q_PL3,       "create default smart playlist 'Movies'" },
    { Q_PL4,       "create default smart playlist 'TV Shows'" },

    { Q_SCVER,     "set schema version" },
  };

static int
db_create_tables(void)
{
  char *errmsg;
  int i;
  int ret;

  for (i = 0; i < (sizeof(db_init_queries) / sizeof(db_init_queries[0])); i++)
    {
      DPRINTF(E_DBG, L_DB, "DB init query: %s\n", db_init_queries[i].desc);

      ret = sqlite3_exec(pool_hdl->hdl, db_init_queries[i].query, NULL, NULL, &errmsg);
      if (ret != SQLITE_OK)
	{
	  DPRINTF(E_FATAL, L_DB, "DB init error: %s\n", errmsg);

	  sqlite3_free(errmsg);
	  return -1;
	}
    }

  return 0;
}

static int
db_generic_upgrade(const struct db_init_query *queries, int nqueries)
{
  char *errmsg;
  int i;
  int ret;

  for (i = 0; i < nqueries; i++, queries++)
    {
      DPRINTF(E_DBG, L_DB, "DB upgrade query: %s\n", queries->desc);

      ret = sqlite3_exec(pool_hdl->hdl, queries->query, NULL, NULL, &errmsg);
      if (ret != SQLITE_OK)
	{
	  DPRINTF(E_FATAL, L_DB, "DB upgrade error: %s\n", errmsg);

	  sqlite3_free(errmsg);
	  return -1;
	}
    }

  return 0;
}


/* Upgrade from schema v10 to v11 */

#define U_V11_SPEAKERS					\
  "CREATE TABLE speakers("				\
  "   id             INTEGER PRIMARY KEY NOT NULL,"	\
  "   selected       INTEGER NOT NULL,"			\
  "   volume         INTEGER NOT NULL"			\
  ");"

#define U_V11_SCVER					\
  "UPDATE admin SET value = '11' WHERE key = 'schema_version';"

static const struct db_init_query db_upgrade_v11_queries[] =
  {
    { U_V11_SPEAKERS,  "create new table speakers" },
    { U_V11_SCVER,     "set schema_version to 11" },
  };

static int
db_upgrade_v11(void)
{
#define Q_NEWSPK "INSERT INTO speakers (id, selected, volume) VALUES (%" PRIi64 ", 1, 75);"
#define Q_SPKVOL "UPDATE speakers SET volume = %d;"
  sqlite3_stmt *stmt;
  char *query;
  char *errmsg;
  const char *strid;
  uint64_t *spkids;
  int volume;
  int count;
  int i;
  int qret;
  int ret;

  /* Get saved speakers */
  count = db_get_count("SELECT COUNT(*) FROM admin WHERE key = 'player:active-spk';");
  if (count == 0)
    goto clear_vars;
  else if (count < 0)
    return -1;

  spkids = (uint64_t *)malloc(count * sizeof(uint64_t));
  if (!spkids)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for speaker IDs\n");

      return -1;
    }

  query = "SELECT value FROM admin WHERE key = 'player:active-spk';";

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = sqlite3_prepare_v2(pool_hdl->hdl, query, -1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      goto out_free_ids;
    }

  i = 0;
  ret = 0;
  while ((qret = sqlite3_step(stmt)) == SQLITE_ROW)
    {
      strid = (const char *)sqlite3_column_text(stmt, 0);

      ret = safe_hextou64(strid, spkids + i);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DB, "Could not convert speaker ID: %s\n", strid);
	  break;
	}

      i++;
    }

  sqlite3_finalize(stmt);

  if ((ret == 0) && (qret != SQLITE_DONE))
    {
      DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      goto out_free_ids;
    }
  else if (ret < 0)
    goto out_free_ids;

  /* Get saved volume */
  query = "SELECT value FROM admin WHERE key = 'player:volume';";

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = sqlite3_prepare_v2(pool_hdl->hdl, query, -1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      goto out_free_ids;
    }

  ret = sqlite3_step(stmt);
  if (ret != SQLITE_ROW)
    {
      DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);
      goto out_free_ids;
    }

  volume = sqlite3_column_int(stmt, 0);

  sqlite3_finalize(stmt);

  /* Add speakers to the table */
  for (i = 0; i < count; i++)
    {
      query = sqlite3_mprintf(Q_NEWSPK, spkids[i]);
      if (!query)
	{
	  DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

	  goto out_free_ids;
	}

      DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

      ret = sqlite3_exec(pool_hdl->hdl, query, NULL, NULL, &errmsg);
      if (ret != SQLITE_OK)
	DPRINTF(E_LOG, L_DB, "Error adding speaker: %s\n", errmsg);

      sqlite3_free(errmsg);
      sqlite3_free(query);
    }

  free(spkids);

  /* Update with volume */
  query = sqlite3_mprintf(Q_SPKVOL, volume);
  if (!query)
    {
      DPRINTF(E_LOG, L_DB, "Out of memory for query string\n");

      return -1;
    }

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = sqlite3_exec(pool_hdl->hdl, query, NULL, NULL, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error adding speaker: %s\n", errmsg);

  sqlite3_free(errmsg);
  sqlite3_free(query);

  /* Clear old config keys */
 clear_vars:
  query = "DELETE FROM admin WHERE key = 'player:volume' OR key = 'player:active-spk';";

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", query);

  ret = sqlite3_exec(pool_hdl->hdl, query, NULL, NULL, &errmsg);
  if (ret != SQLITE_OK)
    DPRINTF(E_LOG, L_DB, "Error adding speaker: %s\n", errmsg);

  sqlite3_free(errmsg);

  return 0;

 out_free_ids:
  free(spkids);

  return -1;

#undef Q_NEWSPK
#undef Q_SPKVOL
}

/* Upgrade from schema v11 to v12 */

#define U_V12_NEW_FILES_TABLE				\
  "CREATE TABLE IF NOT EXISTS files ("			\
  "   id                 INTEGER PRIMARY KEY NOT NULL,"	\
  "   path               VARCHAR(4096) NOT NULL,"	\
  "   fname              VARCHAR(255) NOT NULL,"	\
  "   title              VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   artist             VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   album              VARCHAR(1024) NOT NULL COLLATE DAAP,"		\
  "   genre              VARCHAR(255) DEFAULT NULL COLLATE DAAP,"	\
  "   comment            VARCHAR(4096) DEFAULT NULL COLLATE DAAP,"	\
  "   type               VARCHAR(255) DEFAULT NULL COLLATE DAAP,"	\
  "   composer           VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   orchestra          VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   conductor          VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   grouping           VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   url                VARCHAR(1024) DEFAULT NULL,"	\
  "   bitrate            INTEGER DEFAULT 0,"		\
  "   samplerate         INTEGER DEFAULT 0,"		\
  "   song_length        INTEGER DEFAULT 0,"		\
  "   file_size          INTEGER DEFAULT 0,"		\
  "   year               INTEGER DEFAULT 0,"		\
  "   track              INTEGER DEFAULT 0,"		\
  "   total_tracks       INTEGER DEFAULT 0,"		\
  "   disc               INTEGER DEFAULT 0,"		\
  "   total_discs        INTEGER DEFAULT 0,"		\
  "   bpm                INTEGER DEFAULT 0,"		\
  "   compilation        INTEGER DEFAULT 0,"		\
  "   rating             INTEGER DEFAULT 0,"		\
  "   play_count         INTEGER DEFAULT 0,"		\
  "   data_kind          INTEGER DEFAULT 0,"		\
  "   item_kind          INTEGER DEFAULT 0,"		\
  "   description        INTEGER DEFAULT 0,"		\
  "   time_added         INTEGER DEFAULT 0,"		\
  "   time_modified      INTEGER DEFAULT 0,"		\
  "   time_played        INTEGER DEFAULT 0,"		\
  "   db_timestamp       INTEGER DEFAULT 0,"		\
  "   disabled           INTEGER DEFAULT 0,"		\
  "   sample_count       INTEGER DEFAULT 0,"		\
  "   codectype          VARCHAR(5) DEFAULT NULL,"	\
  "   idx                INTEGER NOT NULL,"		\
  "   has_video          INTEGER DEFAULT 0,"		\
  "   contentrating      INTEGER DEFAULT 0,"		\
  "   bits_per_sample    INTEGER DEFAULT 0,"		\
  "   album_artist       VARCHAR(1024) NOT NULL COLLATE DAAP,"		\
  "   media_kind         INTEGER NOT NULL,"		\
  "   tv_series_name     VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   tv_episode_num_str VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   tv_network_name    VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   tv_episode_sort    INTEGER NOT NULL,"		\
  "   tv_season_num      INTEGER NOT NULL,"		\
  "   songalbumid        INTEGER NOT NULL,"		\
  "   title_sort         VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   artist_sort        VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   album_sort         VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   composer_sort      VARCHAR(1024) DEFAULT NULL COLLATE DAAP,"	\
  "   album_artist_sort  VARCHAR(1024) DEFAULT NULL COLLATE DAAP"	\
  ");"

#define U_V12_IDX_PATH						\
  "CREATE INDEX IF NOT EXISTS idx_path ON files(path, idx);"

#define U_V12_IDX_TS							\
  "CREATE INDEX IF NOT EXISTS idx_titlesort ON files(title_sort);"

#define U_V12_IDX_AS							\
  "CREATE INDEX IF NOT EXISTS idx_artistsort ON files(artist_sort);"

#define U_V12_IDX_BS							\
  "CREATE INDEX IF NOT EXISTS idx_albumsort ON files(album_sort);"

#define U_V12_TRG1							\
  "CREATE TRIGGER update_groups_new_file AFTER INSERT ON files FOR EACH ROW" \
  " BEGIN"								\
  "   INSERT OR IGNORE INTO groups (type, name, persistentid) VALUES (1, NEW.album, NEW.songalbumid);" \
  " END;"

#define U_V12_TRG2							\
  "CREATE TRIGGER update_groups_update_file AFTER UPDATE OF songalbumid ON files FOR EACH ROW" \
  " BEGIN"								\
  "   INSERT OR IGNORE INTO groups (type, name, persistentid) VALUES (1, NEW.album, NEW.songalbumid);" \
  " END;"

#define U_V12_SCVER				\
  "UPDATE admin SET value = '12' WHERE key = 'schema_version';"

static const struct db_init_query db_upgrade_v12_queries[] =
  {
    { U_V12_IDX_PATH, "create index path table files" },
    { U_V12_IDX_TS,   "create index titlesort table files" },
    { U_V12_IDX_AS,   "create index artistsort table files" },
    { U_V12_IDX_BS,   "create index albumsort table files" },

    { U_V12_TRG1,     "create trigger update_groups_new_file" },
    { U_V12_TRG2,     "create trigger update_groups_update_file" },

    { U_V12_SCVER,    "set schema_version to 12" },
  };

/* Upgrade the files table to the new schema by dumping and reloading the
 * table. A bit tedious.
 */
static int
db_upgrade_v12(void)
{
#define Q_DUMP "SELECT 'INSERT INTO files " \
    "(id, path, fname, title, artist, album, genre, comment, type, composer," \
    " orchestra, conductor, grouping, url, bitrate, samplerate, song_length, file_size, year, track," \
    " total_tracks, disc, total_discs, bpm, compilation, rating, play_count, data_kind, item_kind," \
    " description, time_added, time_modified, time_played, db_timestamp, disabled, sample_count," \
    " codectype, idx, has_video, contentrating, bits_per_sample, album_artist," \
    " media_kind, tv_series_name, tv_episode_num_str, tv_network_name, tv_episode_sort, tv_season_num, " \
    " songalbumid, title_sort, artist_sort, album_sort, composer_sort, album_artist_sort)" \
    " VALUES (' || id || ', ' || QUOTE(path) || ', ' || QUOTE(fname) || ', ' || QUOTE(title) || ', '" \
    " || QUOTE(artist) || ', ' || QUOTE(album) || ', ' || QUOTE(genre) || ', ' || QUOTE(comment) || ', '" \
    " || QUOTE(type) || ', ' || QUOTE(composer) || ', ' || QUOTE(orchestra) || ', ' || QUOTE(conductor) || ', '" \
    " || QUOTE(grouping) || ', ' || QUOTE(url) || ', ' || bitrate || ', ' || samplerate || ', '" \
    " || song_length || ', ' || file_size || ', ' || year || ', ' || track || ', ' || total_tracks || ', '" \
    " || disc || ', ' || total_discs || ', ' || bpm || ', ' || compilation || ', ' || rating || ', '" \
    " || play_count || ', ' || data_kind || ', ' || item_kind || ', ' ||  QUOTE(description) || ', '" \
    " || time_added || ', ' || time_modified || ', ' || time_played || ', 1, '" \
    " || disabled || ', ' || sample_count || ', ' || QUOTE(codectype) || ', ' || idx || ', '" \
    " || has_video || ', ' || contentrating || ', ' || bits_per_sample || ', ' || QUOTE(album_artist) || ', '" \
    " || media_kind || ', ' || QUOTE(tv_series_name) || ', ' || QUOTE(tv_episode_num_str) || ', '" \
    " || QUOTE(tv_network_name) || ', ' || tv_episode_sort || ', ' || tv_season_num || ', '" \
    " || songalbumid || ', ' || QUOTE(title) || ', ' || QUOTE(artist) || ', ' || QUOTE(album) || ', '" \
    " || QUOTE(composer) || ', ' || QUOTE(album_artist) || ');' FROM files;"

  struct stat sb;
  FILE *fp;
  sqlite3_stmt *stmt;
  const unsigned char *dumprow;
  char *dump;
  char *errmsg;
  int fd;
  int ret;

  fp = tmpfile();
  if (!fp)
    {
      DPRINTF(E_LOG, L_DB, "Could not create temporary file for files table dump: %s\n", strerror(errno));
      return -1;
    }

  DPRINTF(E_LOG, L_DB, "Dumping old files table...\n");

  /* dump */
  ret = sqlite3_prepare_v2(pool_hdl->hdl, Q_DUMP, strlen(Q_DUMP) + 1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      ret = -1;
      goto out_fclose;
    }

  while ((ret = sqlite3_step(stmt)) == SQLITE_ROW)
    {
      dumprow = sqlite3_column_text(stmt, 0);

      ret = fprintf(fp, "%s\n", dumprow);
      if (ret < 0)
	{
	  DPRINTF(E_LOG, L_DB, "Could not write dump: %s\n", strerror(errno));

	  sqlite3_finalize(stmt);

	  ret = -1;
	  goto out_fclose;
	}
    }

  if (ret != SQLITE_DONE)
    {
      DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);

      ret = -1;
      goto out_fclose;
    }

  sqlite3_finalize(stmt);

  /* Seek back to start of dump file */
  ret = fseek(fp, 0, SEEK_SET);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DB, "Could not seek back to start of dump: %s\n", strerror(errno));

      ret = -1;
      goto out_fclose;
    }

  /* Map dump file */
  fd = fileno(fp);
  if (fd < 0)
    {
      DPRINTF(E_LOG, L_DB, "Could not obtain file descriptor: %s\n", strerror(errno));

      ret = -1;
      goto out_fclose;
    }

  ret = fstat(fd, &sb);
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_DB, "Could not stat dump file: %s\n", strerror(errno));

      ret = -1;
      goto out_fclose;
    }

  if (sb.st_size == 0)
    dump = NULL;
  else
    {
      dump = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
      if (dump == MAP_FAILED)
	{
	  DPRINTF(E_LOG, L_DB, "Could not map dump file: %s\n", strerror(errno));

	  ret = -1;
	  goto out_fclose;
	}
    }

  /* Move old table out of the way */
  DPRINTF(E_LOG, L_DB, "Moving old files table out of the way...\n");

  ret = sqlite3_exec(pool_hdl->hdl, "ALTER TABLE files RENAME TO oldfilesv11;", NULL, NULL, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Error renaming old files table: %s\n", errmsg);

      sqlite3_free(errmsg);

      ret = -1;
      goto out_munmap;
    }

  /* Create new table */
  DPRINTF(E_LOG, L_DB, "Creating new files table...\n");

  ret = sqlite3_exec(pool_hdl->hdl, U_V12_NEW_FILES_TABLE, NULL, NULL, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Error creating new files table: %s\n", errmsg);

      sqlite3_free(errmsg);

      ret = -1;
      goto out_munmap;
    }

  /* Reload dump */
  DPRINTF(E_LOG, L_DB, "Reloading new files table...\n");

  if (dump)
    {
      ret = sqlite3_exec(pool_hdl->hdl, dump, NULL, NULL, &errmsg);
      if (ret != SQLITE_OK)
	{
	  DPRINTF(E_LOG, L_DB, "Error reloading files table data: %s\n", errmsg);

	  sqlite3_free(errmsg);

	  ret = -1;
	  goto out_munmap;
	}
    }

  /* Delete old files table */
  DPRINTF(E_LOG, L_DB, "Deleting old files table...\n");

  ret = sqlite3_exec(pool_hdl->hdl, "DROP TABLE oldfilesv11;", NULL, NULL, &errmsg);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Error dropping old files table: %s\n", errmsg);

      sqlite3_free(errmsg);
      /* Not an issue, but takes up space in the database */
    }

 out_munmap:
  if (dump)
    {
      if (munmap(dump, sb.st_size) < 0)
	DPRINTF(E_LOG, L_DB, "Could not unmap dump file: %s\n", strerror(errno));
    }

 out_fclose:
  fclose(fp);

  return ret;

#undef Q_DUMP
}

/* Upgrade from schema v12 to v13 */

#define U_V13_DROP_IDX_PATH						\
  "DROP INDEX idx_path;"

#define U_V13_DROP_IDX_TS						\
  "DROP INDEX idx_titlesort;"

#define U_V13_DROP_IDX_AS						\
  "DROP INDEX idx_artistsort;"

#define U_V13_DROP_IDX_BS						\
  "DROP INDEX idx_albumsort;"

#define U_V13_IDX_RESCAN						\
  "CREATE INDEX IF NOT EXISTS idx_rescan ON files(path, db_timestamp);"

#define U_V13_IDX_SONGALBUMID					\
  "CREATE INDEX IF NOT EXISTS idx_sai ON files(songalbumid);"

#define U_V13_IDX_STATEMKINDSAI						\
  "CREATE INDEX IF NOT EXISTS idx_state_mkind_sai ON files(disabled, media_kind, songalbumid);"

#define U_V13_IDX_ARTIST				\
  "CREATE INDEX IF NOT EXISTS idx_artist ON files(artist, artist_sort);"

#define U_V13_IDX_ALBUMARTIST				\
  "CREATE INDEX IF NOT EXISTS idx_albumartist ON files(album_artist, album_artist_sort);"

#define U_V13_IDX_COMPOSER				\
  "CREATE INDEX IF NOT EXISTS idx_composer ON files(composer, composer_sort);"

#define U_V13_IDX_TITLE					\
  "CREATE INDEX IF NOT EXISTS idx_title ON files(title, title_sort);"

#define U_V13_IDX_ALBUM					\
  "CREATE INDEX IF NOT EXISTS idx_album ON files(album, album_sort);"

#define U_V13_IDX_GRP_TYPE_PERSIST					\
  "CREATE INDEX IF NOT EXISTS idx_grp_type_persist ON groups(type, persistentid);"

#define U_V13_IDX_PL_PATH				\
  "CREATE INDEX IF NOT EXISTS idx_pl_path ON playlists(path);"

#define U_V13_IDX_PL_DISABLED				\
  "CREATE INDEX IF NOT EXISTS idx_pl_disabled ON playlists(disabled);"

#define U_V13_PL2							\
  "UPDATE playlists SET query = 'f.media_kind = 1' where id = 2;"

#define U_V13_PL3							\
  "UPDATE playlists SET query = 'f.media_kind = 2' where id = 3;"

#define U_V13_PL4							\
  "UPDATE playlists SET query = 'f.media_kind = 64' where id = 4;"

#define U_V13_SCVER				\
  "UPDATE admin SET value = '13' WHERE key = 'schema_version';"

static const struct db_init_query db_upgrade_v13_queries[] =
  {
    { U_V13_DROP_IDX_PATH, "drop index path table files" },
    { U_V13_DROP_IDX_TS,   "drop index titlesort table files" },
    { U_V13_DROP_IDX_AS,   "drop index artistsort table files" },
    { U_V13_DROP_IDX_BS,   "drop index albumsort table files" },

    { U_V13_IDX_RESCAN,    "create rescan index" },
    { U_V13_IDX_SONGALBUMID, "create songalbumid index" },
    { U_V13_IDX_STATEMKINDSAI, "create state/mkind/sai index" },
    { U_V13_IDX_ARTIST,    "create artist index" },
    { U_V13_IDX_ALBUMARTIST, "create album_artist index" },
    { U_V13_IDX_COMPOSER,  "create composer index" },
    { U_V13_IDX_TITLE,     "create title index" },
    { U_V13_IDX_ALBUM,     "create album index" },

    { U_V13_IDX_GRP_TYPE_PERSIST, "create groups type/persistentid index" },

    { U_V13_IDX_PL_PATH,   "create playlist path index" },
    { U_V13_IDX_PL_DISABLED, "create playlist state index" },

    { U_V13_PL2,           "update default smart playlist 'Music'" },
    { U_V13_PL3,           "update default smart playlist 'Movies'" },
    { U_V13_PL4,           "update default smart playlist 'TV Shows'" },

    { U_V13_SCVER,    "set schema_version to 13" },
  };

static int
db_check_version(void)
{
#define Q_VER "SELECT value FROM admin WHERE key = 'schema_version';"
#define Q_VACUUM "VACUUM;"
  sqlite3_stmt *stmt;
  char *errmsg;
  int cur_ver;
  int ret;

  DPRINTF(E_DBG, L_DB, "Running query '%s'\n", Q_VER);

  ret = sqlite3_prepare_v2(pool_hdl->hdl, Q_VER, strlen(Q_VER) + 1, &stmt, NULL);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_LOG, L_DB, "Could not prepare statement: %s\n", sqlite3_errmsg(pool_hdl->hdl));
      return 1;
    }

  ret = sqlite3_step(stmt);
  if (ret != SQLITE_ROW)
    {
      DPRINTF(E_LOG, L_DB, "Could not step: %s\n", sqlite3_errmsg(pool_hdl->hdl));

      sqlite3_finalize(stmt);
      return -1;
    }

  cur_ver = sqlite3_column_int(stmt, 0);

  sqlite3_finalize(stmt);

  if (cur_ver < 10)
    {
      DPRINTF(E_FATAL, L_DB, "Database schema v%d too old, cannot upgrade\n", cur_ver);

      return -1;
    }
  else if (cur_ver < SCHEMA_VERSION)
    {
      DPRINTF(E_LOG, L_DB, "Database schema outdated, schema upgrade needed v%d -> v%d\n", cur_ver, SCHEMA_VERSION);

      switch (cur_ver)
	{
	  case 10:
	    ret = db_generic_upgrade(db_upgrade_v11_queries, sizeof(db_upgrade_v11_queries) / sizeof(db_upgrade_v11_queries[0]));
	    if (ret < 0)
	      return -1;

	    ret = db_upgrade_v11();
	    if (ret < 0)
	      return -1;

	    /* FALLTHROUGH */

	  case 11:
	    ret = db_upgrade_v12();
	    if (ret < 0)
	      return -1;

	    ret = db_generic_upgrade(db_upgrade_v12_queries, sizeof(db_upgrade_v12_queries) / sizeof(db_upgrade_v12_queries[0]));
	    if (ret < 0)
	      return -1;

	    /* FALLTHROUGH */

	  case 12:
	    ret = db_generic_upgrade(db_upgrade_v13_queries, sizeof(db_upgrade_v13_queries) / sizeof(db_upgrade_v13_queries[0]));
	    if (ret < 0)
	      return -1;

	    break;

	  default:
	    DPRINTF(E_LOG, L_DB, "No upgrade path from DB schema v%d to v%d\n", cur_ver, SCHEMA_VERSION);
	    return -1;
	}

      /* What about some housekeeping work, eh? */
      DPRINTF(E_INFO, L_DB, "Now vacuuming database, this may take some time...\n");

      ret = sqlite3_exec(pool_hdl->hdl, Q_VACUUM, NULL, NULL, &errmsg);
      if (ret != SQLITE_OK)
	{
	  DPRINTF(E_LOG, L_DB, "Could not VACUUM database: %s\n", errmsg);

	  sqlite3_free(errmsg);
	  return -1;
	}
    }
  else if (cur_ver > SCHEMA_VERSION)
    {
      DPRINTF(E_LOG, L_DB, "Database schema is newer than the supported version\n");
      return -1;
    }

  return 0;

#undef Q_VER
#undef Q_VACUUM
}


int
db_init(void)
{
  int files;
  int pls;
  int ret;

  db_path = cfg_getstr(cfg_getsec(cfg, "general"), "db_path");

  ret = sqlite3_config(SQLITE_CONFIG_MULTITHREAD);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_FATAL, L_DB, "Could not switch SQLite3 to multithread mode\n");
      DPRINTF(E_FATAL, L_DB, "Check that SQLite3 has been configured for thread-safe operations\n");
      return -1;
    }

  ret = sqlite3_enable_shared_cache(1);
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_FATAL, L_DB, "Could not enable SQLite3 shared-cache mode\n");
      return -1;
    }

  ret = sqlite3_initialize();
  if (ret != SQLITE_OK)
    {
      DPRINTF(E_FATAL, L_DB, "SQLite3 failed to initialize\n");
      return -1;
    }

  ret = db_perthread_init();
  if (ret < 0)
    return ret;

  ret = db_check_version();
  if (ret < 0)
    {
      DPRINTF(E_FATAL, L_DB, "Database version check errored out, incompatible database\n");

      db_perthread_deinit();
      return -1;
    }
  else if (ret > 0)
    {
      DPRINTF(E_FATAL, L_DB, "Could not check database version, trying DB init\n");

      ret = db_create_tables();
      if (ret < 0)
	{
	  DPRINTF(E_FATAL, L_DB, "Could not create tables\n");
	  db_perthread_deinit();
	  return -1;
	}
    }

  db_analyze();

  files = db_files_get_count();
  pls = db_pl_get_count();

  db_perthread_deinit();

  DPRINTF(E_INFO, L_DB, "Database OK with %d active files and %d active playlists\n", files, pls);

  ret = db_pool_init();
  if (ret < 0)
    {
      DPRINTF(E_FATAL, L_DB, "Could not initialize database connection pool\n");

      db_pool_deinit();
      return -1;
    }

  return 0;
}

void
db_deinit(void)
{
  db_pool_deinit();

  sqlite3_shutdown();
}
