/*
 * Copyright (C) 2009-2011 Julien BLACHE <jb@jblache.org>
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
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>

#include <dispatch/dispatch.h>
#include <event.h>

#include <libavutil/log.h>

#include "conffile.h"
#include "logger.h"


static dispatch_queue_t logger_sq;
static int logsync;
static int logdomains;
static int threshold;
static int console;
static char *logfilename;
static FILE *logfile;
static char *labels[] = { "config", "daap", "db", "httpd", "main", "mdns", "misc", "rsp", "scan", "xcode", "event", "remote", "dacp", "ffmpeg", "artwork", "player", "raop", "laudio", "dmap", "dbperf", "http" };


static int
set_logdomains(char *domains)
{
  char *ptr;
  char *d;
  int i;

  logdomains = 0;

  while ((d = strtok_r(domains, " ,", &ptr)))
    {
      domains = NULL;

      for (i = 0; i < N_LOGDOMAINS; i++)
	{
	  if (strcmp(d, labels[i]) == 0)
	    {
	      logdomains |= (1 << i);
	      break;
	    }
	}

      if (i == N_LOGDOMAINS)
	{
	  fprintf(stderr, "Error: unknown log domain '%s'\n", d);
	  return -1;
	}
    }

  return 0;
}

static void
vlogger(int severity, int domain, const char *fmt, va_list args)
{
  va_list ap;
  char *msg;
  time_t t;
  int ret;
  dispatch_block_t logblock;

  if (!((1 << domain) & logdomains) || (severity > threshold))
    return;

  t = time(NULL);

  va_copy(ap, args);
  ret = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);

  if (ret <= 0)
    return;

  msg = (char *)malloc(ret + 1);
  if (!msg)
    return;

  va_copy(ap, args);
  ret = vsnprintf(msg, ret + 1, fmt, ap);
  va_end(ap);

  if (ret < 0)
    {
      free(msg);
      return;
    }


  logblock = ^{
    char stamp[32];
    int ret;

    if (!logfile && !console)
      {
	free(msg);
	return;
      }

    if (logfile)
      {
	ret = strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", localtime(&t));
	if (ret == 0)
	  stamp[0] = '\0';

	fprintf(logfile, "[%s] %8s: %s", stamp, labels[domain], msg);

	fflush(logfile);
      }

    if (console)
      fprintf(stderr, "%8s: %s", labels[domain], msg);

    free(msg);
  };

  if (logsync)
    dispatch_sync(logger_sq, logblock);
  else
    dispatch_async(logger_sq, logblock);
}

static void
vlogger_early(int severity, int domain, const char *fmt, va_list args)
{
  va_list ap;
  char stamp[32];
  time_t t;
  int ret;

  if (!((1 << domain) & logdomains) || (severity > threshold))
    return;

  if (!logfile && !console)
    return;

  if (logfile)
    {
      t = time(NULL);
      ret = strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", localtime(&t));
      if (ret == 0)
	stamp[0] = '\0';

      fprintf(logfile, "[%s] %8s: ", stamp, labels[domain]);

      va_copy(ap, args);
      vfprintf(logfile, fmt, ap);
      va_end(ap);

      fflush(logfile);
    }

  if (console)
    {
      fprintf(stderr, "%8s: ", labels[domain]);

      va_copy(ap, args);
      vfprintf(stderr, fmt, ap);
      va_end(ap);
    }
}

void
DPRINTF(int severity, int domain, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);

  if (!logger_sq)
    vlogger_early(severity, domain, fmt, ap);
  else
    vlogger(severity, domain, fmt, ap);

  va_end(ap);
}

void
logger_ffmpeg(void *ptr, int level, const char *fmt, va_list ap)
{
  int severity;

  /* Can't use a switch() because some definitions have the same value */
  if ((level == AV_LOG_FATAL) || (level == AV_LOG_ERROR))
    severity = E_LOG;
  else if ((level == AV_LOG_WARNING) || (level == AV_LOG_INFO) || (level == AV_LOG_VERBOSE))
    severity = E_WARN;
  else if (level == AV_LOG_DEBUG)
    severity = E_DBG;
  else if (level == AV_LOG_QUIET)
    severity = E_SPAM;
  else
    severity = E_LOG;

  vlogger(severity, L_FFMPEG, fmt, ap);
}

void
logger_libevent(int severity, const char *msg)
{
  switch (severity)
    {
      case _EVENT_LOG_DEBUG:
	severity = E_DBG;
	break;

      case _EVENT_LOG_ERR:
	severity = E_LOG;
	break;

      case _EVENT_LOG_WARN:
	severity = E_WARN;
	break;

      case _EVENT_LOG_MSG:
	severity = E_INFO;
	break;

      default:
	severity = E_LOG;
	break;
    }

  DPRINTF(severity, L_EVENT, "%s\n", msg);
}

#ifdef LAUDIO_USE_ALSA
void
logger_alsa(const char *file, int line, const char *function, int err, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vlogger(E_LOG, L_LAUDIO, fmt, ap);
  va_end(ap);
}
#endif /* LAUDIO_USE_ALSA */

/* Queue: logger_sq */
static void
logger_reinit_task(void *arg)
{
  FILE *fp;

  if (!logfile)
    return;

  fp = fopen(logfilename, "a");
  if (!fp)
    {
      DPRINTF(E_LOG, L_MAIN, "Could not reopen logfile: %s\n", strerror(errno));
      return;
    }

  fclose(logfile);
  logfile = fp;
}

void
logger_reinit(void)
{
  if (!logger_sq)
    return;

  dispatch_sync_f(logger_sq, NULL, logger_reinit_task);
}


/* The functions below are used at init time before switching to dispatch mode */
void
logger_domains(void)
{
  int i;

  fprintf(stdout, "%s", labels[0]);

  for (i = 1; i < N_LOGDOMAINS; i++)
    fprintf(stdout, ", %s", labels[i]);

  fprintf(stdout, "\n");
}

void
logger_detach(void)
{
  console = 0;
}

int
logger_start_dispatch(int sync)
{
  logger_sq = dispatch_queue_create("org.forked-daapd.logger", NULL);
  if (!logger_sq)
    return -1;

  logsync = sync;

  return 0;
}

int
logger_init(char *file, char *domains, int severity)
{
  int ret;

  if ((sizeof(labels) / sizeof(labels[0])) != N_LOGDOMAINS)
    {
      fprintf(stderr, "WARNING: log domains do not match\n");

      return -1;
    }

  logger_sq = NULL;
  console = 1;
  threshold = severity;

  if (domains)
    {
      ret = set_logdomains(domains);
      if (ret < 0)
	return ret;
    }
  else
    logdomains = ~0;

  if (!file)
    return 0;

  logfile = fopen(file, "a");
  if (!logfile)
    {
      fprintf(stderr, "Could not open logfile %s: %s\n", file, strerror(errno));

      return -1;
    }

  ret = fchown(fileno(logfile), runas_uid, 0);
  if (ret < 0)
    fprintf(stderr, "Failed to set ownership on logfile: %s\n", strerror(errno));

  ret = fchmod(fileno(logfile), 0644);
  if (ret < 0)
    fprintf(stderr, "Failed to set permissions on logfile: %s\n", strerror(errno));

  logfilename = file;

  return 0;
}

void
logger_deinit(void)
{
  if (logger_sq)
    {
      dispatch_sync(logger_sq,
		     ^{
		       if (logfile)
			 fclose(logfile);
		     });

      dispatch_release(logger_sq);
      logger_sq = NULL;
    }
  else
    {
      if (logfile)
	fclose(logfile);
    }
}
