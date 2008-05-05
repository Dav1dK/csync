/*
 * libcsync -- a library to sync a directory with another
 *
 * Copyright (c) 2008      by Andreas Schneider <mail@cynapses.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * vim: ts=2 sw=2 et cindent
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdio.h>
#include <time.h>

#include "csync_time.h"
#include "vio/csync_vio.h"

#define CSYNC_LOG_CATEGORY_NAME "csync.time"
#include "csync_log.h"

/* check time difference between the replicas */
time_t csync_timediff(CSYNC *ctx) {
  time_t timediff = -1;
  char *luri, *ruri;
  csync_vio_handle_t *fp = NULL;
  csync_vio_file_stat_t *st = NULL;

  if (asprintf(&luri, "%s/csync_timediff.ctmp", ctx->local.uri) < 0) {
    goto out;
  }

  /* create temporary file on local */
  ctx->replica = ctx->local.type;
  fp = csync_vio_creat(ctx, luri, 0644);
  if (fp == NULL) {
    CSYNC_LOG(CSYNC_LOG_PRIORITY_FATAL, "Unable to create temporary file: %s - %s", luri, strerror(errno));
    goto out;
  }
  csync_vio_close(ctx, fp);

  /* Get the modification time */
  st = csync_vio_file_stat_new();
  if (csync_vio_stat(ctx, luri, st) < 0) {
    CSYNC_LOG(CSYNC_LOG_PRIORITY_FATAL, "Synchronisation is not possible! %s - %s", luri, strerror(errno));
    goto out;
  }
  timediff = st->mtime;
  csync_vio_file_stat_destroy(st);

  /* create temporary file on remote replica */
  ctx->replica = ctx->remote.type;
  fp = csync_vio_creat(ctx, luri, 0644);
  if (fp == NULL) {
    CSYNC_LOG(CSYNC_LOG_PRIORITY_FATAL, "Unable to create temporary file: %s - %s", luri, strerror(errno));
    goto out;
  }
  csync_vio_close(ctx, fp);

  /* Get the modification time */
  st = csync_vio_file_stat_new();
  if (csync_vio_stat(ctx, luri, st) < 0) {
    CSYNC_LOG(CSYNC_LOG_PRIORITY_FATAL, "Synchronisation is not possible! %s - %s", luri, strerror(errno));
    goto out;
  }

  /* calc time difference */
  timediff = abs(timediff - st->mtime);
  CSYNC_LOG(CSYNC_LOG_PRIORITY_DEBUG, "Time difference: %ld seconds", timediff);

out:
  csync_vio_file_stat_destroy(st);
  csync_vio_unlink(ctx, luri);
  SAFE_FREE(luri);
  csync_vio_unlink(ctx, ruri);
  SAFE_FREE(ruri);
  return timediff;
}
