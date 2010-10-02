/*
 * Copyright (C) 2009-2011 Julien BLACHE <jb@jblache.org>
 *
 * Pieces from mt-daapd:
 * Copyright (C) 2003 Ron Pedde (ron@pedde.com)
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
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include <grp.h>
#include <stdint.h>

#include <pthread.h>

#include <dispatch/dispatch.h>

#include <getopt.h>
#include <libavutil/log.h>
#include <libavformat/avformat.h>

#include <gcrypt.h>
GCRY_THREAD_OPTION_PTHREAD_IMPL;

#include "conffile.h"
#include "db.h"
#include "logger.h"
#include "misc.h"
#include "filescanner.h"
#include "httpd.h"
#include "mdns.h"
#include "remote_pairing.h"
#include "player.h"
#if LIBAVFORMAT_VERSION_MAJOR < 53
# include "ffmpeg_url_evbuffer.h"
#endif


#define PIDFILE   STATEDIR "/run/" PACKAGE ".pid"

typedef enum {
  SHUTDOWN_SIG_INT = -2,
  SHUTDOWN_SIG_TERM = -1,

  SHUTDOWN_PLAN_NOMINAL = 0,

  SHUTDOWN_FAIL_SIGNAL,
  SHUTDOWN_FAIL_MDNSREG,
  SHUTDOWN_FAIL_REMOTE,
  SHUTDOWN_FAIL_HTTPD,
  SHUTDOWN_FAIL_PLAYER,
  SHUTDOWN_FAIL_FILESCANNER,
  SHUTDOWN_FAIL_DB,
  SHUTDOWN_FAIL_MDNS,
  SHUTDOWN_FAIL_LOGGER,
  SHUTDOWN_FAIL_DAEMON,
  SHUTDOWN_FAIL_GCRYPT,
  SHUTDOWN_FAIL_FFMPEG,
} shutdown_plan_t;


static dispatch_source_t chld_src;
static dispatch_source_t term_src;
static dispatch_source_t int_src;
static dispatch_source_t hup_src;

static char *pidfile;
static int background;


static void
version(void)
{
  fprintf(stdout, "Forked Media Server: Version %s\n", VERSION);
  fprintf(stdout, "Copyright (C) 2009-2011 Julien BLACHE <jb@jblache.org>\n");
  fprintf(stdout, "Based on mt-daapd, Copyright (C) 2003-2007 Ron Pedde <ron@pedde.com>\n");
  fprintf(stdout, "Released under the GNU General Public License version 2 or later\n");
}

static void
usage(char *program)
{
  version();
  printf("\n");
  printf("Usage: %s [options]\n\n", program);
  printf("Options:\n");
  printf("  -d <number>    Log level (0-5)\n");
  printf("  -D <dom,dom..> Log domains\n");
  printf("  -c <file>      Use <file> as the configfile\n");
  printf("  -P <file>      Write PID to specified file\n");
  printf("  -f             Run in foreground\n");
  printf("  -b <id>        ffid to be broadcast\n");
  printf("  -v             Display version information\n");
  printf("\n\n");
  printf("Available log domains:\n");
  logger_domains();
  printf("\n\n");
}

static int
daemonize(void)
{
  FILE *fp;
  pid_t childpid;
  pid_t pid_ret;
  int fd;
  int ret;
  char *runas;

  if (background)
    {
      fp = fopen(pidfile, "w");
      if (!fp)
	{
	  DPRINTF(E_LOG, L_MAIN, "Error opening pidfile (%s): %s\n", pidfile, strerror(errno));

	  return -1;
	}

      fd = open("/dev/null", O_RDWR, 0);
      if (fd < 0)
	{
	  DPRINTF(E_LOG, L_MAIN, "Error opening /dev/null: %s\n", strerror(errno));

	  fclose(fp);
	  return -1;
	}

      signal(SIGTTOU, SIG_IGN);
      signal(SIGTTIN, SIG_IGN);
      signal(SIGTSTP, SIG_IGN);

      childpid = fork();

      if (childpid > 0)
	exit(EXIT_SUCCESS);
      else if (childpid < 0)
	{
	  DPRINTF(E_FATAL, L_MAIN, "Fork failed: %s\n", strerror(errno));

	  close(fd);
	  fclose(fp);
	  return -1;
	}

      pid_ret = setsid();
      if (pid_ret == (pid_t) -1)
	{
	  DPRINTF(E_FATAL, L_MAIN, "setsid() failed: %s\n", strerror(errno));

	  close(fd);
	  fclose(fp);
	  return -1;
	}

      logger_detach();

      dup2(fd, STDIN_FILENO);
      dup2(fd, STDOUT_FILENO);
      dup2(fd, STDERR_FILENO);

      if (fd > 2)
	close(fd);

      ret = chdir("/");
      if (ret < 0)
        DPRINTF(E_WARN, L_MAIN, "chdir() failed: %s\n", strerror(errno));

      umask(0);

      fprintf(fp, "%d\n", getpid());
      fclose(fp);

      DPRINTF(E_DBG, L_MAIN, "PID: %d\n", getpid());
    }

  if (geteuid() == (uid_t) 0)
    {
      runas = cfg_getstr(cfg_getsec(cfg, "general"), "uid");

      ret = initgroups(runas, runas_gid);
      if (ret != 0)
	{
	  DPRINTF(E_FATAL, L_MAIN, "initgroups() failed: %s\n", strerror(errno));

	  return -1;
	}

      ret = setegid(runas_gid);
      if (ret != 0)
	{
	  DPRINTF(E_FATAL, L_MAIN, "setegid() failed: %s\n", strerror(errno));

	  return -1;
	}

      ret = seteuid(runas_uid);
      if (ret != 0)
	{
	  DPRINTF(E_FATAL, L_MAIN, "seteuid() failed: %s\n", strerror(errno));

	  return -1;
	}
    }

  return 0;
}

static int
register_services(char *ffid, int no_rsp, int no_daap)
{
  cfg_t *lib;
  char *libname;
  char *password;
  char *txtrecord[10];
  char records[9][128];
  int port;
  uint32_t hash;
  int i;
  int ret;

  srand((unsigned int)time(NULL));

  lib = cfg_getsec(cfg, "library");

  libname = cfg_getstr(lib, "name");
  hash = djb_hash(libname, strlen(libname));

  for (i = 0; i < (sizeof(records) / sizeof(records[0])); i++)
    {
      memset(records[i], 0, 128);
      txtrecord[i] = records[i];
    }

  txtrecord[9] = NULL;

  snprintf(txtrecord[0], 128, "txtvers=1");
  snprintf(txtrecord[1], 128, "Database ID=%0X", hash);
  snprintf(txtrecord[2], 128, "Machine ID=%0X", hash);
  snprintf(txtrecord[3], 128, "Machine Name=%s", libname);
  snprintf(txtrecord[4], 128, "mtd-version=%s", VERSION);
  snprintf(txtrecord[5], 128, "iTSh Version=131073"); /* iTunes 6.0.4 */
  snprintf(txtrecord[6], 128, "Version=196610");      /* iTunes 6.0.4 */

  password = cfg_getstr(lib, "password");
  snprintf(txtrecord[7], 128, "Password=%s", (password) ? "true" : "false");

  if (ffid)
    snprintf(txtrecord[8], 128, "ffid=%s", ffid);
  else
    snprintf(txtrecord[8], 128, "ffid=%08x", rand());

  DPRINTF(E_INFO, L_MAIN, "Registering rendezvous names\n");

  port = cfg_getint(lib, "port");

  /* Register web server service */
  ret = mdns_register(libname, "_http._tcp", port, txtrecord);
  if (ret < 0)
    return ret;

  /* Register RSP service */
  if (!no_rsp)
    {
      ret = mdns_register(libname, "_rsp._tcp", port, txtrecord);
      if (ret < 0)
	return ret;
    }

  /* Register DAAP service */
  if (!no_daap)
    {
      ret = mdns_register(libname, "_daap._tcp", port, txtrecord);
      if (ret < 0)
	return ret;
    }

  for (i = 0; i < (sizeof(records) / sizeof(records[0])); i++)
    {
      memset(records[i], 0, 128);
    }

  snprintf(txtrecord[0], 128, "txtvers=1");
  snprintf(txtrecord[1], 128, "DbId=%016" PRIX64, libhash);
  snprintf(txtrecord[2], 128, "DvTy=iTunes");
  snprintf(txtrecord[3], 128, "DvSv=2306"); /* Magic number! Yay! */
  snprintf(txtrecord[4], 128, "Ver=131073"); /* iTunes 6.0.4 */
  snprintf(txtrecord[5], 128, "OSsi=0x1F5"); /* Magic number! Yay! */
  snprintf(txtrecord[6], 128, "CtlN=%s", libname);

  /* Terminator */
  txtrecord[7] = NULL;

  /* The group name for the touch-able service advertising is a 64bit hash
   * but is different from the DbId in iTunes. For now we'll use a hash of
   * the library name for both, and we'll change that if needed.
   */

  /* Use as scratch space for the hash */
  snprintf(records[7], 128, "%016" PRIX64, libhash);

  /* Register touch-able service, for Remote.app */
  ret = mdns_register(records[7], "_touch-able._tcp", port, txtrecord);
  if (ret < 0)
    return ret;

  return 0;
}


static int
ffmpeg_lockmgr(void **mutex, enum AVLockOp op)
{
  dispatch_semaphore_t dsem;

  dsem = (dispatch_semaphore_t)*mutex;

  switch (op)
    {
      case AV_LOCK_CREATE:
	dsem = dispatch_semaphore_create(1);
	if (!dsem)
	  return 1;

	*mutex = dsem;
	return 0;

      case AV_LOCK_OBTAIN:
	dispatch_semaphore_wait(dsem, DISPATCH_TIME_FOREVER);
	return 0;

      case AV_LOCK_RELEASE:
	dispatch_semaphore_signal(dsem);
	return 0;

      case AV_LOCK_DESTROY:
	dispatch_release(dsem);
	return 0;
    }

  return 1;
}


static void
app_startup(int logsync, int mdns_no_rsp, int mdns_no_daap, char *ffid);

static void
app_shutdown(shutdown_plan_t plan);

int
main(int argc, char **argv)
{
  int option;
  char *configfile;
  int mdns_no_rsp;
  int mdns_no_daap;
  int loglevel;
  int logsync;
  char *logdomains;
  char *logfile;
  char *ffid;
  const char *gcry_version;
  dispatch_queue_t main_q;
  shutdown_plan_t shutdown_plan;
  int ret;

  struct option option_map[] =
    {
      { "ffid",         1, NULL, 'b' },
      { "debug",        1, NULL, 'd' },
      { "synclog",      0, NULL, 's' },
      { "logdomains",   1, NULL, 'D' },
      { "foreground",   0, NULL, 'f' },
      { "config",       1, NULL, 'c' },
      { "pidfile",      1, NULL, 'P' },
      { "version",      0, NULL, 'v' },

      { "mdns-no-rsp",  0, NULL, 512 },
      { "mdns-no-daap", 0, NULL, 513 },

      { NULL,           0, NULL, 0 }
    };

  configfile = CONFFILE;
  pidfile = PIDFILE;
  loglevel = -1;
  logsync = 0;
  logdomains = NULL;
  logfile = NULL;
  background = 1;
  ffid = NULL;
  mdns_no_rsp = 0;
  mdns_no_daap = 0;

  int_src = NULL;
  term_src = NULL;
  hup_src = NULL;
  chld_src = NULL;

  while ((option = getopt_long(argc, argv, "D:d:sc:P:fb:v", option_map, NULL)) != -1)
    {
      switch (option)
	{
	  case 512:
	    mdns_no_rsp = 1;
	    break;

	  case 513:
	    mdns_no_daap = 1;
	    break;

	  case 'b':
            ffid = optarg;
            break;

	  case 'd':
	    ret = safe_atoi32(optarg, &option);
	    if (ret < 0)
	      fprintf(stderr, "Error: loglevel must be an integer in '-d %s'\n", optarg);
	    else
	      loglevel = option;
            break;

	  case 'D':
	    logdomains = optarg;
            break;

	  case 's':
	    logsync = 1;
	    break;

          case 'f':
            background = 0;
            break;

          case 'c':
            configfile = optarg;
            break;

          case 'P':
	    pidfile = optarg;
            break;

          case 'v':
	    version();
            return EXIT_SUCCESS;
            break;

          default:
            usage(argv[0]);
            return EXIT_FAILURE;
            break;
        }
    }

  ret = logger_init(NULL, NULL, (loglevel < 0) ? E_LOG : loglevel);
  if (ret != 0)
    {
      fprintf(stderr, "Could not initialize log facility\n");

      return EXIT_FAILURE;
    }

  ret = conffile_load(configfile);
  if (ret != 0)
    {
      DPRINTF(E_FATAL, L_MAIN, "Config file errors; please fix your config\n");

      logger_deinit();
      return EXIT_FAILURE;
    }

  logger_deinit();

  /* Reinit log facility with configfile values */
  if (loglevel < 0)
    loglevel = cfg_getint(cfg_getsec(cfg, "general"), "loglevel");

  logfile = cfg_getstr(cfg_getsec(cfg, "general"), "logfile");

  ret = logger_init(logfile, logdomains, loglevel);
  if (ret != 0)
    {
      fprintf(stderr, "Could not reinitialize log facility with config file settings\n");

      conffile_unload();
      return EXIT_FAILURE;
    }

  DPRINTF(E_LOG, L_MAIN, "Forked Media Server Version %s taking off\n", VERSION);

  /* Initialize ffmpeg */
  avcodec_init();

  ret = av_lockmgr_register(ffmpeg_lockmgr);
  if (ret < 0)
    {
      DPRINTF(E_FATAL, L_MAIN, "Could not register ffmpeg lock manager callback\n");

      shutdown_plan = SHUTDOWN_FAIL_FFMPEG;
      goto startup_fail;
    }

  av_register_all();
  av_log_set_callback(logger_ffmpeg);
#if LIBAVFORMAT_VERSION_MAJOR < 53
  register_ffmpeg_evbuffer_url_protocol();
#endif

  /* Initialize libgcrypt */
  gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

  gcry_version = gcry_check_version(GCRYPT_VERSION);
  if (!gcry_version)
    {
      DPRINTF(E_FATAL, L_MAIN, "libgcrypt version mismatch\n");

      shutdown_plan = SHUTDOWN_FAIL_GCRYPT;
      goto startup_fail;
    }

  /* We aren't handling anything sensitive, so give up on secure
   * memory, which is a scarce system resource.
   */
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);

  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

  DPRINTF(E_DBG, L_MAIN, "Initialized with gcrypt %s\n", gcry_version);

  /* Daemonize and drop privileges */
  ret = daemonize();
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_MAIN, "Could not initialize server\n");

      shutdown_plan = SHUTDOWN_FAIL_DAEMON;
      goto startup_fail;
    }

  main_q = dispatch_get_main_queue();
  if (!main_q)
    {
      DPRINTF(E_FATAL, L_MAIN, "Could not get main dispatch queue\n");

      shutdown_plan = SHUTDOWN_FAIL_DAEMON;
      goto startup_fail;
    }

  dispatch_async(main_q, ^{
      app_startup(logsync, mdns_no_rsp, mdns_no_daap, ffid);
    });

  dispatch_main();

  /* NOT REACHED */

 startup_fail:
  app_shutdown(shutdown_plan);

  /* NOT REACHED */

  exit(EXIT_FAILURE);

  return 0;
}

static void
app_startup(int logsync, int mdns_no_rsp, int mdns_no_daap, char *ffid)
{
  dispatch_queue_t main_q;
  shutdown_plan_t shutdown_plan;
  int ret;

  main_q = dispatch_get_current_queue();

  /* Switch logger into dispatch mode (after forking) */
  ret = logger_start_dispatch(logsync);
  if (ret < 0)
    {
      DPRINTF(E_FATAL, L_MAIN, "Could not switch logger to dispatch mode\n");

      shutdown_plan = SHUTDOWN_FAIL_LOGGER;
      goto startup_fail;
    }

  DPRINTF(E_DBG, L_MAIN, "Logger switched to dispatch mode\n");

  DPRINTF(E_LOG, L_MAIN, "mDNS init\n");
  ret = mdns_init();
  if (ret != 0)
    {
      DPRINTF(E_FATAL, L_MAIN, "mDNS init failed\n");

      shutdown_plan = SHUTDOWN_FAIL_MDNS;
      goto startup_fail;
    }

  /* Initialize the database before starting */
  DPRINTF(E_INFO, L_MAIN, "Initializing database\n");
  ret = db_init();
  if (ret < 0)
    {
      DPRINTF(E_FATAL, L_MAIN, "Database init failed\n");

      shutdown_plan = SHUTDOWN_FAIL_DB;
      goto startup_fail;
    }

  /* Spawn file scanner thread */
  ret = filescanner_init();
  if (ret != 0)
    {
      DPRINTF(E_FATAL, L_MAIN, "File scanner thread failed to start\n");

      shutdown_plan = SHUTDOWN_FAIL_FILESCANNER;
      goto startup_fail;
    }

  /* Spawn player thread */
  ret = player_init();
  if (ret != 0)
    {
      DPRINTF(E_FATAL, L_MAIN, "Player thread failed to start\n");

      shutdown_plan = SHUTDOWN_FAIL_PLAYER;
      goto startup_fail;
    }

  /* Spawn HTTPd thread */
  ret = httpd_init();
  if (ret != 0)
    {
      DPRINTF(E_FATAL, L_MAIN, "HTTPd thread failed to start\n");

      shutdown_plan = SHUTDOWN_FAIL_HTTPD;
      goto startup_fail;
    }

  /* Start Remote pairing service */
  ret = remote_pairing_init();
  if (ret != 0)
    {
      DPRINTF(E_FATAL, L_MAIN, "Remote pairing service failed to start\n");

      shutdown_plan = SHUTDOWN_FAIL_REMOTE;
      goto startup_fail;
    }

  /* Register mDNS services */
  ret = register_services(ffid, mdns_no_rsp, mdns_no_daap);
  if (ret < 0)
    {
      shutdown_plan = SHUTDOWN_FAIL_MDNSREG;
      goto startup_fail;
    }

  /* Set up signal dispatch sources */
  signal(SIGINT, SIG_IGN);

  int_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, main_q);
  if (!int_src)
    {
      DPRINTF(E_FATAL, L_MAIN, "Could not create dispatch source for SIGINT\n");

      shutdown_plan = SHUTDOWN_FAIL_SIGNAL;
      goto startup_fail;
    }

  dispatch_source_set_event_handler(int_src, ^{
      app_shutdown(SHUTDOWN_SIG_INT);
    });

  dispatch_resume(int_src);

  signal(SIGTERM, SIG_IGN);

  term_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, main_q);
  if (!term_src)
    {
      DPRINTF(E_FATAL, L_MAIN, "Could not create dispatch source for SIGTERM\n");

      shutdown_plan = SHUTDOWN_FAIL_SIGNAL;
      goto startup_fail;
    }

  dispatch_source_set_event_handler(term_src, ^{
      app_shutdown(SHUTDOWN_SIG_TERM);
    });

  dispatch_resume(term_src);

  signal(SIGHUP, SIG_IGN);

  hup_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGHUP, 0, main_q);
  if (!hup_src)
    {
      DPRINTF(E_FATAL, L_MAIN, "Could not create dispatch source for SIGHUP\n");

      shutdown_plan = SHUTDOWN_FAIL_SIGNAL;
      goto startup_fail;
    }

  dispatch_source_set_event_handler(hup_src, ^{
      DPRINTF(E_LOG, L_MAIN, "Got SIGHUP\n");

      logger_reinit();
    });

  dispatch_resume(hup_src);

  signal(SIGCHLD, SIG_IGN);

  chld_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGCHLD, 0, main_q);
  if (!chld_src)
    {
      DPRINTF(E_FATAL, L_MAIN, "Could not create dispatch source for SIGCHLD\n");

      shutdown_plan = SHUTDOWN_FAIL_SIGNAL;
      goto startup_fail;
    }

  dispatch_source_set_event_handler(chld_src, ^{
      int status;

      DPRINTF(E_LOG, L_MAIN, "Got SIGCHLD, reaping children\n");

      while (wait3(&status, WNOHANG, NULL) > 0)
	/* Nothing. */ ;
    });

  dispatch_resume(chld_src);

  return;

 startup_fail:
  app_shutdown(shutdown_plan);

  /* NOT REACHED */

  exit(EXIT_FAILURE);
}

static void
app_shutdown(shutdown_plan_t plan)
{
  int ret;

  if (int_src)
    dispatch_source_cancel(int_src);
  if (term_src)
    dispatch_source_cancel(term_src);
  if (hup_src)
    dispatch_source_cancel(hup_src);
  if (chld_src)
    dispatch_source_cancel(chld_src);

  if (int_src)
    dispatch_release(int_src);
  if (term_src)
    dispatch_release(term_src);
  if (hup_src)
    dispatch_release(hup_src);
  if (chld_src)
    dispatch_release(chld_src);

  ret = EXIT_FAILURE;

  switch (plan)
    {
      case SHUTDOWN_SIG_INT:
      case SHUTDOWN_SIG_TERM:
	DPRINTF(E_LOG, L_MAIN, "Got SIGTERM or SIGINT\n");

	/* FALLTHROUGH */

      case SHUTDOWN_PLAN_NOMINAL:
	DPRINTF(E_LOG, L_MAIN, "Stopping gracefully\n");
	ret = EXIT_SUCCESS;

	/*
	 * On a clean shutdown, bring mDNS down first to give a chance
	 * to the clients to perform a clean shutdown on their end
	 */
	DPRINTF(E_LOG, L_MAIN, "mDNS deinit\n");
	mdns_deinit();

	/* FALLTHROUGH */

      case SHUTDOWN_FAIL_SIGNAL:
      case SHUTDOWN_FAIL_MDNSREG:
	DPRINTF(E_LOG, L_MAIN, "Remote pairing deinit\n");
	remote_pairing_deinit();

	/* FALLTHROUGH */

      case SHUTDOWN_FAIL_REMOTE:
	DPRINTF(E_LOG, L_MAIN, "HTTPd deinit\n");
	httpd_deinit();

	/* FALLTHROUGH */

      case SHUTDOWN_FAIL_HTTPD:
	DPRINTF(E_LOG, L_MAIN, "Player deinit\n");
	player_deinit();

	/* FALLTHROUGH */

      case SHUTDOWN_FAIL_PLAYER:
	DPRINTF(E_LOG, L_MAIN, "File scanner deinit\n");
	filescanner_deinit();

	/* FALLTHROUGH */

      case SHUTDOWN_FAIL_FILESCANNER:
	DPRINTF(E_LOG, L_MAIN, "Database deinit\n");
	db_deinit();

	/* FALLTHROUGH */

      case SHUTDOWN_FAIL_DB:
	if (ret == EXIT_FAILURE)
	  {
	    DPRINTF(E_LOG, L_MAIN, "mDNS deinit\n");
	    mdns_deinit();
	  }

	/* FALLTHROUGH */

      case SHUTDOWN_FAIL_MDNS:
      case SHUTDOWN_FAIL_LOGGER:
      case SHUTDOWN_FAIL_DAEMON:
	if (background)
	  {
	    ret = seteuid(0);
	    if (ret < 0)
	      DPRINTF(E_LOG, L_MAIN, "seteuid() failed: %s\n", strerror(errno));
	    else
	      {
		ret = unlink(pidfile);
		if (ret < 0)
		  DPRINTF(E_LOG, L_MAIN, "Could not unlink PID file %s: %s\n", pidfile, strerror(errno));
	      }
	  }

	/* FALLTHROUGH */

      case SHUTDOWN_FAIL_GCRYPT:
	av_lockmgr_register(NULL);

	/* FALLTHROUGH */

      case SHUTDOWN_FAIL_FFMPEG:
	DPRINTF(E_LOG, L_MAIN, "Exiting.\n");
	conffile_unload();
	logger_deinit();

	break;
    }

  exit(ret);
}
