/*
 * libcsync -- a library to sync a directory with another
 *
 * Copyright (c) 2008-2013 by Andreas Schneider <asn@cryptomilk.org>
 * Copyright (c) 2012-2013 by Klaas Freitag <freitag@owncloud.com>wie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "c_lib.h"
#include "c_jhash.h"
#include "c_path.h"

#include "csync_private.h"
#include "csync_exclude.h"
#include "csync_statedb.h"
#include "csync_update.h"
#include "csync_util.h"
#include "csync_misc.h"

#include "vio/csync_vio.h"

#define CSYNC_LOG_CATEGORY_NAME "csync.updater"
#include "csync_log.h"
#include "c_strerror.h"

static int _csync_detect_update(CSYNC *ctx, const char *file,
    const csync_vio_file_stat_t *fs, const int type) {
  uint64_t h = 0;
  size_t len = 0;
  size_t size = 0;
  const char *path = NULL;
  csync_file_stat_t *st = NULL;
  csync_file_stat_t *tmp = NULL;

  if ((file == NULL) || (fs == NULL)) {
    errno = EINVAL;
    ctx->status_code = CSYNC_STATUS_PARAM_ERROR;
    return -1;
  }

  path = file;
  switch (ctx->current) {
    case LOCAL_REPLICA:
      if (strlen(path) <= strlen(ctx->local.uri)) {
        ctx->status_code = CSYNC_STATUS_PARAM_ERROR;
        return -1;
      }
      path += strlen(ctx->local.uri) + 1;
      break;
    case REMOTE_REPLICA:
      if (strlen(path) <= strlen(ctx->remote.uri)) {
        ctx->status_code = CSYNC_STATUS_PARAM_ERROR;
        return -1;
      }
      path += strlen(ctx->remote.uri) + 1;
      break;
    default:
      path = NULL;
      ctx->status_code = CSYNC_STATUS_PARAM_ERROR;
      return -1;
      break;
  }
  len = strlen(path);

  h = c_jhash64((uint8_t *) path, len, 0);
  size = sizeof(csync_file_stat_t) + len + 1;

  st = c_malloc(size);
  if (st == NULL) {
    ctx->status_code = CSYNC_STATUS_MEMORY_ERROR;
    return -1;
  }
  CSYNC_LOG(CSYNC_LOG_PRIORITY_TRACE, "file: %s - hash %llu, st size: %zu",
      path, (long long unsigned int) h, size);

  /* Set instruction by default to none */
  st->instruction = CSYNC_INSTRUCTION_NONE;

  /* check hardlink count */
  if (type == CSYNC_FTW_TYPE_FILE && fs->nlink > 1) {
    st->instruction = CSYNC_INSTRUCTION_IGNORE;
    goto out;
  }

  /* Update detection */
  if (csync_get_statedb_exists(ctx)) {
    tmp = csync_statedb_get_stat_by_hash(ctx->statedb.db, h);
    if (tmp && tmp->phash == h) {
      /* we have an update! */
      if (fs->mtime > tmp->modtime) {
        st->instruction = CSYNC_INSTRUCTION_EVAL;
      } else {
        st->instruction = CSYNC_INSTRUCTION_NONE;
      }
    } else {
      /* check if the file has been renamed */
      if (ctx->current == LOCAL_REPLICA) {
        SAFE_FREE(tmp);
        tmp = csync_statedb_get_stat_by_inode(ctx->statedb.db, fs->inode);
        if (tmp && tmp->inode == fs->inode) {
          /* inode found so the file has been renamed */
          st->instruction = CSYNC_INSTRUCTION_RENAME;
        } else {
          /* file not found in statedb */
          st->instruction = CSYNC_INSTRUCTION_NEW;
        }
      } else {
        /* remote and file not found in statedb */
        st->instruction = CSYNC_INSTRUCTION_NEW;
      }
    }
  } else  {
    st->instruction = CSYNC_INSTRUCTION_NEW;
  }

out:
  SAFE_FREE(tmp);
  st->inode = fs->inode;
  st->mode = fs->mode;
  st->size = fs->size;
  st->modtime = fs->mtime;
  st->uid = fs->uid;
  st->gid = fs->gid;
  st->nlink = fs->nlink;
  st->type = type;

  st->phash = h;
  st->pathlen = len;
  memcpy(st->path, (len ? path : ""), len + 1);

  switch (ctx->current) {
    case LOCAL_REPLICA:
      if (c_rbtree_insert(ctx->local.tree, (void *) st) < 0) {
        SAFE_FREE(st);
        ctx->status_code = CSYNC_STATUS_TREE_ERROR;
        return -1;
      }
      break;
    case REMOTE_REPLICA:
      if (c_rbtree_insert(ctx->remote.tree, (void *) st) < 0) {
        SAFE_FREE(st);
        ctx->status_code = CSYNC_STATUS_TREE_ERROR;
        return -1;
      }
      break;
    default:
      break;
  }
  CSYNC_LOG(CSYNC_LOG_PRIORITY_DEBUG, "file: %s, instruction: %s", st->path,
      csync_instruction_str(st->instruction));

  return 0;
}

int csync_walker(CSYNC *ctx, const char *file, const csync_vio_file_stat_t *fs,
    enum csync_ftw_flags_e flag) {
  switch (flag) {
    case CSYNC_FTW_FLAG_FILE:
      CSYNC_LOG(CSYNC_LOG_PRIORITY_TRACE, "file: %s", file);

      return _csync_detect_update(ctx, file, fs, CSYNC_FTW_TYPE_FILE);
      break;
    case CSYNC_FTW_FLAG_SLINK:
      if (ctx->options.sync_symbolic_links) {
        CSYNC_LOG(CSYNC_LOG_PRIORITY_TRACE, "symlink: %s", file);
        return _csync_detect_update(ctx, file, fs, CSYNC_FTW_TYPE_SLINK);
      }
      break;
    case CSYNC_FTW_FLAG_DIR: /* enter directory */
      CSYNC_LOG(CSYNC_LOG_PRIORITY_TRACE, "directory: %s", file);

      return _csync_detect_update(ctx, file, fs, CSYNC_FTW_TYPE_DIR);
    case CSYNC_FTW_FLAG_NSTAT: /* not statable file */
    case CSYNC_FTW_FLAG_DNR:
    case CSYNC_FTW_FLAG_DP:
    case CSYNC_FTW_FLAG_SLN:
      break;
    default:
      break;
  }

  return 0;
}

/**
 * @brief Check whether a path is inside of the root path we are syncronising
 *
 * @param uri The uri to check. It needs to be an absolute path.
 *
 * @return -1 on error, 0 if uri isn't in the root path and 1 if it is in the root path
 */
static int _is_in_root(CSYNC *ctx, char *uri) {
  char *abs_root;
  int ret;

  if (!ctx || !uri) {
    errno = EINVAL;
    return -1;
  }
  abs_root = NULL;

  switch (ctx->current) {
    case LOCAL_REPLICA:
      if (! csync_vio_is_absolute(ctx, uri)) {
        /* make it absolute */
        char tmp[PATH_MAX + 1];
#ifdef _WIN32
#error Getting an absolute path is not yet implemented on windows.
#endif
        if (getcwd(tmp, PATH_MAX + 1) == NULL)
          return -1;
        if (snprintf(tmp, PATH_MAX + 1, "%s/%s", tmp, ctx->local.uri) == -1)
          return -1;
        abs_root = c_canonicalize_path(tmp);
      } else {
        abs_root = c_canonicalize_path(ctx->local.uri);
      }
      break;
    case REMOTE_REPLICA:
      /* Remote uri's are always absolute */
      abs_root = c_canonicalize_path(ctx->remote.uri);
      break;
    default:
      return -1;
  }
  if (! abs_root)
    return -1;

  uri = c_canonicalize_path(uri);
  if (! uri) {
    SAFE_FREE(abs_root);
    return -1;
  }

  uri[strlen(abs_root)] = '\0';
  if (strcmp(abs_root, uri) != 0)
    ret = 0;
  else
    ret = 1;

  SAFE_FREE(abs_root);
  SAFE_FREE(uri);
  return ret;
}

/* File tree walker */
int csync_ftw(CSYNC *ctx, const char *uri, csync_walker_fn fn,
    unsigned int depth) {
  char errbuf[256] = {0};
  char *filename = NULL;
  char *d_name = NULL;
  csync_vio_handle_t *dh = NULL;
  csync_vio_file_stat_t *dirent = NULL;
  csync_vio_file_stat_t *fs = NULL;
  int rc = 0;
  char *link_target;

  if (uri[0] == '\0') {
    errno = ENOENT;
    ctx->status_code = CSYNC_STATUS_PARAM_ERROR;
    goto error;
  }

  if ((dh = csync_vio_opendir(ctx, uri)) == NULL) {
    /* permission denied */
    ctx->status_code = csync_errno_to_status(errno, CSYNC_STATUS_OPENDIR_ERROR);
    if (errno == EACCES) {
      return 0;
    } else {
      c_strerror_r(errno, errbuf, sizeof(errbuf));
      CSYNC_LOG(CSYNC_LOG_PRIORITY_ERROR,
          "opendir failed for %s - %s",
          uri,
          errbuf);
      goto error;
    }
  }

  while ((dirent = csync_vio_readdir(ctx, dh))) {
    const char *path = NULL;
    size_t ulen = 0;
    int flen;
    int flag;

    d_name = dirent->name;
    if (d_name == NULL) {
      ctx->status_code = CSYNC_STATUS_READDIR_ERROR;
      goto error;
    }

    /* skip "." and ".." */
    if (d_name[0] == '.' && (d_name[1] == '\0'
          || (d_name[1] == '.' && d_name[2] == '\0'))) {
      csync_vio_file_stat_destroy(dirent);
      dirent = NULL;
      continue;
    }

    flen = asprintf(&filename, "%s/%s", uri, d_name);
    if (flen < 0) {
      csync_vio_file_stat_destroy(dirent);
      dirent = NULL;
      ctx->status_code = CSYNC_STATUS_MEMORY_ERROR;
      goto error;
    }

    /* Create relative path for checking the exclude list */
    switch (ctx->current) {
      case LOCAL_REPLICA:
        ulen = strlen(ctx->local.uri) + 1;
        break;
      case REMOTE_REPLICA:
        ulen = strlen(ctx->remote.uri) + 1;
        break;
      default:
        break;
    }

    if (((size_t)flen) < ulen) {
      csync_vio_file_stat_destroy(dirent);
      dirent = NULL;
      ctx->status_code = CSYNC_STATUS_UNSUCCESSFUL;
      goto error;
    }

    path = filename + ulen;

    /* Check if file is excluded */
    if (csync_excluded(ctx, path)) {
      CSYNC_LOG(CSYNC_LOG_PRIORITY_TRACE, "%s excluded", path);
      SAFE_FREE(filename);
      csync_vio_file_stat_destroy(dirent);
      dirent = NULL;
      continue;
    }

    fs = csync_vio_file_stat_new();
    if (csync_vio_stat(ctx, filename, fs) == 0) {
      switch (fs->type) {
        case CSYNC_VIO_FILE_TYPE_SYMBOLIC_LINK:
          if (! (fs->fields & CSYNC_VIO_FILE_STAT_FIELDS_SYMLINK_NAME)) {
            flag = CSYNC_FTW_FLAG_NSTAT;
            break;
          }

          /* We don't sync absolute symlinks */
          if (csync_vio_is_absolute(ctx, fs->u.symlink_name)) {
            flag = CSYNC_FTW_FLAG_SLN;
            break;
          }

          if (asprintf(&link_target, "%s/%s", uri, fs->u.symlink_name) == -1) {
            ctx->status_code = CSYNC_STATUS_ERROR;
            csync_vio_file_stat_destroy(fs);
            goto error;
          }
          rc = _is_in_root(ctx, link_target);
          free(link_target);
          if (rc == 1)
            /* The link points inside our syncronisation filesystem tree */
            flag = CSYNC_FTW_FLAG_SLINK;
          else if (rc == 0)
            /* We don't sync links which point to outside of the directory tree we
               are syncing */
            flag = CSYNC_FTW_FLAG_SLN;
          else {
            ctx->status_code = CSYNC_STATUS_ERROR;
            csync_vio_file_stat_destroy(fs);
            goto error;
          }
          break;
        case CSYNC_VIO_FILE_TYPE_DIRECTORY:
          flag = CSYNC_FTW_FLAG_DIR;
          break;
        case CSYNC_VIO_FILE_TYPE_BLOCK_DEVICE:
        case CSYNC_VIO_FILE_TYPE_CHARACTER_DEVICE:
        case CSYNC_VIO_FILE_TYPE_SOCKET:
        case CSYNC_VIO_FILE_TYPE_FIFO:
          flag = CSYNC_FTW_FLAG_SPEC;
          break;
        default:
          flag = CSYNC_FTW_FLAG_FILE;
          break;
      };
    } else {
      flag = CSYNC_FTW_FLAG_NSTAT;
    }

    CSYNC_LOG(CSYNC_LOG_PRIORITY_TRACE, "walk: %s", filename);

    /* Call walker function for each file */
    rc = fn(ctx, filename, fs, flag);
    csync_vio_file_stat_destroy(fs);

    if (rc < 0) {
      if (!CSYNC_STATUS_IS_OK(ctx->status_code)) {
          ctx->status_code = CSYNC_STATUS_UPDATE_ERROR;
      }

      csync_vio_closedir(ctx, dh);
      goto done;
    }

    if (flag == CSYNC_FTW_FLAG_DIR && depth) {
      rc = csync_ftw(ctx, filename, fn, depth - 1);
      if (rc < 0) {
        csync_vio_closedir(ctx, dh);
        goto done;
      }
    }
    SAFE_FREE(filename);
    csync_vio_file_stat_destroy(dirent);
    dirent = NULL;
  }
  csync_vio_closedir(ctx, dh);

done:
  csync_vio_file_stat_destroy(dirent);
  SAFE_FREE(filename);
  return rc;
error:
  if (dh != NULL) {
    csync_vio_closedir(ctx, dh);
  }
  SAFE_FREE(filename);
  return -1;
}

/* vim: set ts=8 sw=2 et cindent: */
