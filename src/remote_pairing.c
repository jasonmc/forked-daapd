/*
 * Copyright (C) 2010 Julien BLACHE <jb@jblache.org>
 *
 * iTunes - Remote pairing hash function published by Michael Paul Bailey
 *   <http://jinxidoru.blogspot.com/2009/06/itunes-remote-pairing-code.html>
 * Simplified version using standard MD5 published by Jeff Sharkey
 *   <http://jsharkey.org/blog/2009/06/21/itunes-dacp-pairing-hash-is-broken/>
 *
 * Pairing process based on the work by
 *  - Michael Croes
 *    <http://blog.mycroes.nl/2008/08/pairing-itunes-remote-app-with-your-own.html>
 *  - Jeffrey Sharkey
 *    <http://dacp.jsharkey.org/>
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
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>

#include <dispatch/dispatch.h>

#include <gcrypt.h>

#include "evbuffer/evbuffer.h"
#include "logger.h"
#include "conffile.h"
#include "mdns.h"
#include "http.h"
#include "misc.h"
#include "db.h"
#include "remote_pairing.h"


struct remote_info {
  struct pairing_info pi;

  char *paircode;
  char *pin;

  unsigned short v4_port;
  unsigned short v6_port;
  char *v4_address;
  char *v6_address;

  struct remote_info *next;
};


static dispatch_queue_t pairing_sq;
static struct remote_info *remote_list;


/* iTunes - Remote pairing hash */
static char *
itunes_pairing_hash(char *paircode, char *pin)
{
  char hash[33];
  char ebuf[64];
  uint8_t *hash_bytes;
  size_t hashlen;
  gcry_md_hd_t hd;
  gpg_error_t gc_err;
  int i;

  if (strlen(paircode) != 16)
    {
      DPRINTF(E_LOG, L_REMOTE, "Paircode length != 16, cannot compute pairing hash\n");
      return NULL;
    }

  if (strlen(pin) != 4)
    {
      DPRINTF(E_LOG, L_REMOTE, "Pin length != 4, cannot compute pairing hash\n");
      return NULL;
    }

  gc_err = gcry_md_open(&hd, GCRY_MD_MD5, 0);
  if (gc_err != GPG_ERR_NO_ERROR)
    {
      gpg_strerror_r(gc_err, ebuf, sizeof(ebuf));
      DPRINTF(E_LOG, L_REMOTE, "Could not open MD5: %s\n", ebuf);

      return NULL;
    }

  gcry_md_write(hd, paircode, 16);
  /* Add pin code characters on 16 bits - remember Mac OS X is
   * all UTF-16 (wchar_t).
   */
  for (i = 0; i < 4; i++)
    {
      gcry_md_write(hd, pin + i, 1);
      gcry_md_write(hd, "\0", 1);
    }

  hash_bytes = gcry_md_read(hd, GCRY_MD_MD5);
  if (!hash_bytes)
    {
      DPRINTF(E_LOG, L_REMOTE, "Could not read MD5 hash\n");

      return NULL;
    }

  hashlen = gcry_md_get_algo_dlen(GCRY_MD_MD5);

  for (i = 0; i < hashlen; i++)
    sprintf(hash + (2 * i), "%02X", hash_bytes[i]);

  gcry_md_close(hd);

  return strdup(hash);
}


/* Operations on the remote list must happen
 * with the list lock held by the caller
 */
static struct remote_info *
add_remote(void)
{
  struct remote_info *ri;

  ri = (struct remote_info *)malloc(sizeof(struct remote_info));
  if (!ri)
    {
      DPRINTF(E_WARN, L_REMOTE, "Out of memory for struct remote_info\n");
      return NULL;
    }

  memset(ri, 0, sizeof(struct remote_info));

  ri->next = remote_list;
  remote_list = ri;

  return ri;
}

static void
unlink_remote(struct remote_info *ri)
{
  struct remote_info *p;

  if (ri == remote_list)
    remote_list = ri->next;
  else
    {
      for (p = remote_list; p && (p->next != ri); p = p->next)
	; /* EMPTY */

      if (!p)
	{
	  DPRINTF(E_LOG, L_REMOTE, "WARNING: struct remote_info not found in list; BUG!\n");
	  return;
	}

      p->next = ri->next;
    }
}

static void
free_remote(struct remote_info *ri)
{
  if (ri->paircode)
    free(ri->paircode);

  if (ri->pin)
    free(ri->pin);

  if (ri->v4_address)
    free(ri->v4_address);

  if (ri->v6_address)
    free(ri->v6_address);

  free_pi(&ri->pi, 1);

  free(ri);
}

static void
remove_remote(struct remote_info *ri)
{
  unlink_remote(ri);

  free_remote(ri);
}

static void
remove_remote_address_byid(const char *id, int family)
{
  struct remote_info *ri;

  for (ri = remote_list; ri; ri = ri->next)
    {
      if (!ri->pi.remote_id)
	continue;

      if (strcmp(ri->pi.remote_id, id) == 0)
	break;
    }

  if (!ri)
    {
      DPRINTF(E_WARN, L_REMOTE, "Remote %s not found in list\n", id);
      return;
    }

  switch (family)
    {
      case AF_INET:
	if (ri->v4_address)
	  {
	    free(ri->v4_address);
	    ri->v4_address = NULL;
	  }
	break;

      case AF_INET6:
	if (ri->v6_address)
	  {
	    free(ri->v6_address);
	    ri->v6_address = NULL;
	  }
	break;
    }

  if (!ri->v4_address && !ri->v6_address)
    remove_remote(ri);
}

static int
add_remote_mdns_data(const char *id, int family, const char *address, int port, char *name, char *paircode)
{
  struct remote_info *ri;
  char *check_addr;
  int ret;

  for (ri = remote_list; ri; ri = ri->next)
    {
      if (!ri->pi.remote_id)
	continue;

      if (strcmp(ri->pi.remote_id, id) == 0)
	break;
    }

  if (!ri)
    {
      DPRINTF(E_DBG, L_REMOTE, "Remote id %s not known, adding\n", id);

      ri = add_remote();
      if (!ri)
	return -1;

      ret = 0;
    }
  else
    {
      DPRINTF(E_DBG, L_REMOTE, "Remote id %s found\n", id);

      free_pi(&ri->pi, 1);

      switch (family)
	{
	  case AF_INET:
	    if (ri->v4_address)
	      free(ri->v4_address);
	    break;

	  case AF_INET6:
	    if (ri->v6_address)
	      free(ri->v6_address);
	    break;
	}

      if (ri->paircode)
	free(ri->paircode);

      ret = 1;
    }

  ri->pi.remote_id = strdup(id);

  switch (family)
    {
      case AF_INET:
	ri->v4_address = strdup(address);
	ri->v4_port = port;

	check_addr = ri->v4_address;
	break;

      case AF_INET6:
	ri->v6_address = strdup(address);
	ri->v6_port = port;

	check_addr = ri->v6_address;
	break;

      default:
	DPRINTF(E_LOG, L_REMOTE, "Unknown address family %d\n", family);

	check_addr = NULL;
	break;
    }

  if (!ri->pi.remote_id || !check_addr)
    {
      DPRINTF(E_LOG, L_REMOTE, "Out of memory for remote pairing data\n");

      remove_remote(ri);
      return -1;
    }

  ri->pi.name = name;
  ri->paircode = paircode;

  return ret;
}

static int
add_remote_pin_data(char *devname, char *pin)
{
  struct remote_info *ri;

  for (ri = remote_list; ri; ri = ri->next)
    {
      if (strcmp(ri->pi.name, devname) == 0)
	break;
    }

  if (!ri)
    {
      DPRINTF(E_LOG, L_REMOTE, "Remote '%s' not known from mDNS, ignoring\n", devname);

      free(pin);
      return -1;
    }

  DPRINTF(E_DBG, L_REMOTE, "Remote '%s' found\n", devname);

  if (ri->pin)
    free(ri->pin);

  ri->pin = pin;

  return 0;
}


/* Queue: pairing */
static int
pairing_request_cb(struct http_connection *c, struct http_request *req, struct http_response *r, void *arg)
{
  struct remote_info *ri;
  struct evbuffer *body;
  char guid[17];
  const char *reason;
  uint8_t *response;
  size_t bodylen;
  int code;
  int len;
  int i;
  int ret;

  ri = (struct remote_info *)arg;

  code = http_response_get_status(r, &reason);
  if (code != HTTP_OK)
    {
      DPRINTF(E_LOG, L_REMOTE, "Pairing failed with Remote %s/%s, HTTP response code %d (%s)\n", ri->pi.remote_id, ri->pi.name, code, reason);

      goto cleanup;
    }

  body = http_response_get_body(r);
  if (!body || (EVBUFFER_LENGTH(body) < 8))
    {
      DPRINTF(E_LOG, L_REMOTE, "Remote %s/%s: pairing response too short\n", ri->pi.remote_id, ri->pi.name);

      goto cleanup;
    }

  bodylen = EVBUFFER_LENGTH(body);
  response = EVBUFFER_DATA(body);

  if ((response[0] != 'c') || (response[1] != 'm') || (response[2] != 'p') || (response[3] != 'a'))
    {
      DPRINTF(E_LOG, L_REMOTE, "Remote %s/%s: unknown pairing response, expected cmpa\n", ri->pi.remote_id, ri->pi.name);

      goto cleanup;
    }

  len = (response[4] << 24) | (response[5] << 16) | (response[6] << 8) | (response[7]);
  if (bodylen < 8 + len)
    {
      DPRINTF(E_LOG, L_REMOTE, "Remote %s/%s: pairing response truncated (got %d expected %d)\n",
	      ri->pi.remote_id, ri->pi.name, (int)bodylen, len + 8);

      goto cleanup;
    }

  response += 8;

  for (; len > 0; len--, response++)
    {
      if ((response[0] != 'c') || (response[1] != 'm') || (response[2] != 'p') || (response[3] != 'g'))
	continue;
      else
	{
	  len -= 8;
	  response += 8;

	  break;
	}
    }

  if (len < 8)
    {
      DPRINTF(E_LOG, L_REMOTE, "Remote %s/%s: cmpg truncated in pairing response\n", ri->pi.remote_id, ri->pi.name);

      goto cleanup;
    }

  for (i = 0; i < 8; i++)
    sprintf(guid + (2 * i), "%02X", response[i]);

  ri->pi.guid = strdup(guid);

  DPRINTF(E_INFO, L_REMOTE, "Pairing succeeded with Remote '%s' (id %s), GUID: %s\n", ri->pi.name, ri->pi.remote_id, guid);

  ret = db_pool_get();
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_REMOTE, "Could not acquire database connection; cannot register pairing with %s\n", ri->pi.name);

      goto cleanup;
    }

  ret = db_pairing_add(&ri->pi);
  db_pool_release();
  if (ret < 0)
    {
      DPRINTF(E_LOG, L_REMOTE, "Failed to register pairing!\n");

      goto cleanup;
    }

 cleanup:
  http_request_free(req);
  http_client_free(c);

  return 0;
}

static void
pairing_free_cb(void *arg)
{
  struct remote_info *ri;

  ri = (struct remote_info *)arg;

  free_remote(ri);
}

static void
pairing_fail_cb(struct http_connection *c, void *arg)
{
  struct remote_info *ri;

  ri = (struct remote_info *)arg;

  DPRINTF(E_LOG, L_REMOTE, "HTTP client failure while pairing with %s\n", ri->pi.name);

  /* free_cb takes care of ri */
  http_client_free(c);
}

/* Queue: pairing */
static int
send_pairing_request(struct remote_info *ri, char *req_uri, int family)
{
  struct http_connection *c;
  struct http_request *req;
  char *address;
  unsigned short port;
  int ret;

  switch (family)
    {
      case AF_INET:
	if (!ri->v4_address)
	  return -1;

	address = ri->v4_address;
	port = ri->v4_port;
	break;

      case AF_INET6:
	if (!ri->v6_address)
	  return -1;

	address = ri->v6_address;
	port = ri->v6_port;
	break;

      default:
	return -1;
    }

  c = http_client_new(L_REMOTE, address, port, pairing_fail_cb, pairing_free_cb, ri);
  if (!c)
    {
      DPRINTF(E_LOG, L_REMOTE, "Could not create HTTP client for pairing with %s\n", ri->pi.name);

      return -1;
    }

  req = http_client_request_new(HTTP_GET, P_VER_1_1, req_uri, pairing_request_cb);
  if (!req)
    {
      DPRINTF(E_WARN, L_REMOTE, "Could not create HTTP request for pairing\n");

      goto request_fail;
    }

  ret = http_request_add_header(req, "Connection", "close");
  if (ret < 0)
    DPRINTF(E_WARN, L_REMOTE, "Could not add Connection: close header\n");

  ret = http_client_request_run(c, req);
  if (ret < 0)
    {
      DPRINTF(E_WARN, L_REMOTE, "Could not run pairing request\n");

      goto run_fail;
    }

  return 0;

 run_fail:
  http_request_free(req);
 request_fail:
  http_client_free(c);

  return -1;
}


static void
do_pairing(struct remote_info *ri)
{
  char req_uri[128];
  char *pairing_hash;
  int ret;

  pairing_hash = itunes_pairing_hash(ri->paircode, ri->pin);
  if (!pairing_hash)
    {
      DPRINTF(E_LOG, L_REMOTE, "Could not compute pairing hash!\n");

      goto hash_fail;
    }

  DPRINTF(E_DBG, L_REMOTE, "Pairing hash for %s/%s: %s\n", ri->pi.remote_id, ri->pi.name, pairing_hash);

  /* Prepare request URI */
  /* The servicename variable is the mDNS service group name; currently it's
   * a hash of the library name, but in iTunes the service name and the library
   * ID (DbId) are different (see comment in main.c).
   * Remote uses the service name to perform mDNS lookups.
   */
  ret = snprintf(req_uri, sizeof(req_uri), "/pair?pairingcode=%s&servicename=%016" PRIX64, pairing_hash, libhash);
  free(pairing_hash);
  if ((ret < 0) || (ret >= sizeof(req_uri)))
    {
      DPRINTF(E_WARN, L_REMOTE, "Request URI for pairing exceeds buffer size\n");

      goto req_uri_fail;
    }

  /* Fire up the request */
  if (ri->v6_address)
    {
      ret = send_pairing_request(ri, req_uri, AF_INET6);
      if (ret == 0)
	return;

      DPRINTF(E_WARN, L_REMOTE, "Could not send pairing request on IPv6\n");
    }

  ret = send_pairing_request(ri, req_uri, AF_INET);
  if (ret < 0)
    {
      DPRINTF(E_WARN, L_REMOTE, "Could not send pairing request on IPv4\n");

      goto pairing_fail;
    }

  return;

 pairing_fail:
 req_uri_fail:
 hash_fail:
  free_remote(ri);
}

/* Queue: pairing */
static void
try_pairing(void)
{
  struct remote_info *ri;

  for (ri = remote_list; ri; ri = ri->next)
    {
      /* We've got both the mDNS data and the pin */
      if (ri->paircode && ri->pin)
	{
	  unlink_remote(ri);

	  do_pairing(ri);
	}
    }
}


/* Queue: mdns_sq */
static void
touch_remote_cb(const char *name, const char *type, const char *domain, const char *hostname, int family, const char *address, int port, struct keyval *txt)
{
  const char *p;
  char *bname;
  char *baddress;
  char *devname;
  char *paircode;

  bname = strdup(name);
  if (!bname)
    {
      DPRINTF(E_LOG, L_REMOTE, "Out of memory for name copy\n");

      return;
    }

  if (port < 0)
    {
      /* If Remote stops advertising itself, the pairing either succeeded or
       * failed; any subsequent attempt will need a new pairing pin, so
       * we can just forget everything we know about the remote.
       */
      dispatch_async(pairing_sq, ^{
	  remove_remote_address_byid(bname, family);

	  free(bname);
	});
    }
  else
    {
      /* Get device name (DvNm field in TXT record) */
      p = keyval_get(txt, "DvNm");
      if (!p)
	{
	  DPRINTF(E_LOG, L_REMOTE, "Remote %s: no DvNm in TXT record!\n", name);

	  goto out_free_bname;
	}

      if (*p == '\0')
	{
	  DPRINTF(E_LOG, L_REMOTE, "Remote %s: DvNm has no value\n", name);

	  goto out_free_bname;
	}

      devname = strdup(p);
      if (!devname)
	{
	  DPRINTF(E_LOG, L_REMOTE, "Out of memory for device name\n");

	  goto out_free_bname;
	}

      /* Get pairing code (Pair field in TXT record) */
      p = keyval_get(txt, "Pair");
      if (!p)
	{
	  DPRINTF(E_LOG, L_REMOTE, "Remote %s: no Pair in TXT record!\n", name);

	  goto out_free_devname;
	}

      if (*p == '\0')
	{
	  DPRINTF(E_LOG, L_REMOTE, "Remote %s: Pair has no value\n", name);

	  goto out_free_devname;
	}

      paircode = strdup(p);
      if (!paircode)
	{
	  DPRINTF(E_LOG, L_REMOTE, "Out of memory for paircode\n");

	  goto out_free_devname;
	}

      baddress = strdup(address);
      if (!baddress)
	{
	  DPRINTF(E_LOG, L_REMOTE, "Out of memory for address copy\n");

	  free(paircode);
	  goto out_free_devname;
	}

      /* Add the data to the list, adding the remote to the list if needed */
      dispatch_async(pairing_sq, ^{
	  int bret;

	  DPRINTF(E_DBG, L_REMOTE, "Discovered remote %s (id %s) at [%s]:%d, paircode %s\n", devname, bname, baddress, port, paircode);

	  bret = add_remote_mdns_data(bname, family, baddress, port, devname, paircode);
	  if (bret == 1)
	    try_pairing();
	  else if (bret < 0)
	    {
	      DPRINTF(E_WARN, L_REMOTE, "Could not add Remote mDNS data, id %s\n", bname);

	      free(devname);
	      free(paircode);
	    }

	  free(bname);
	  free(baddress);
	});
    }

  return;

 out_free_devname:
  free(devname);
 out_free_bname:
  free(bname);
}

/* Queue: global (filescanner.c) */
void
remote_pairing_read_pin(char *path)
{
  char buf[256];
  FILE *fp;
  char *devname;
  char *pin;
  int len;

  fp = fopen(path, "rb");
  if (!fp)
    {
      DPRINTF(E_LOG, L_REMOTE, "Could not open Remote pairing file %s: %s\n", path, strerror(errno));
      return;
    }

  devname = fgets(buf, sizeof(buf), fp);
  if (!devname)
    {
      DPRINTF(E_LOG, L_REMOTE, "Empty Remote pairing file %s\n", path);

      fclose(fp);
      return;
    }

  len = strlen(devname);
  if (buf[len - 1] != '\n')
    {
      DPRINTF(E_LOG, L_REMOTE, "Invalid Remote pairing file %s: device name too long or missing pin\n", path);

      fclose(fp);
      return;
    }

  while (len)
    {
      if ((buf[len - 1] == '\r') || (buf[len - 1] == '\n'))
	{
	  buf[len - 1] = '\0';
	  len--;
	}
      else
	break;
    }

  if (!len)
    {
      DPRINTF(E_LOG, L_REMOTE, "Invalid Remote pairing file %s: empty line where device name expected\n", path);

      fclose(fp);
      return;
    }

  devname = strdup(buf);
  if (!devname)
    {
      DPRINTF(E_LOG, L_REMOTE, "Out of memory for device name while reading %s\n", path);

      fclose(fp);
      return;
    }

  pin = fgets(buf, sizeof(buf), fp);
  fclose(fp);
  if (!pin)
    {
      DPRINTF(E_LOG, L_REMOTE, "Invalid Remote pairing file %s: no pin\n", path);

      free(devname);
      return;
    }

  len = strlen(pin);

  while (len)
    {
      if ((buf[len - 1] == '\r') || (buf[len - 1] == '\n'))
	{
	  buf[len - 1] = '\0';
	  len--;
	}
      else
	break;
    }

  if (len != 4)
    {
      DPRINTF(E_LOG, L_REMOTE, "Invalid pin in Remote pairing file %s: pin length should be 4, got %d\n", path, len);

      free(devname);
      return;
    }

  pin = strdup(buf);
  if (!pin)
    {
      DPRINTF(E_LOG, L_REMOTE, "Out of memory for device pin while reading %s\n", path);

      free(devname);
      return;
    }

  dispatch_async(pairing_sq, ^{
      int bret;

      DPRINTF(E_DBG, L_REMOTE, "Adding Remote pin data: name '%s', pin '%s'\n", devname, pin);

      bret = add_remote_pin_data(devname, pin);
      free(devname);
      /* pin retained or freed in add_remote_pin_data() */

      if (bret < 0)
	return;

      try_pairing();
    });
}


/* Thread: main */
int
remote_pairing_init(void)
{
  int ret;

  remote_list = NULL;

  pairing_sq = dispatch_queue_create("org.forked-daapd.pairing", NULL);
  if (!pairing_sq)
    {
      DPRINTF(E_FATAL, L_REMOTE, "Could not create dispatch queue for pairing\n");

      return -1;
    }

  ret = mdns_browse("_touch-remote._tcp", MDNS_WANT_V4, touch_remote_cb);
  if (ret < 0)
    {
      DPRINTF(E_FATAL, L_REMOTE, "Could not browse for Remote services\n");

      goto mdns_browse_fail;
    }

  return 0;

 mdns_browse_fail:
  dispatch_release(pairing_sq);

  return -1;
}

static void
remote_pairing_deinit_task(void *arg)
{
  struct remote_info *ri;

  for (ri = remote_list; remote_list; ri = remote_list)
    {
      remote_list = ri->next;

      free_remote(ri);
    }
}

/* Thread: main */
void
remote_pairing_deinit(void)
{
  dispatch_sync_f(pairing_sq, NULL, remote_pairing_deinit_task);

  dispatch_release(pairing_sq);
}
