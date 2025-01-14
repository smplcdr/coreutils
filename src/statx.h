/* statx -- stat conversion functions for coreutils
   Copyright (C) 2019 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#ifndef _STATX_H
#define _STATX_H 1

#if HAVE_STATX && defined(STATX_INO)
/* Much of the format printing requires a struct stat or timespec */
static inline struct timespec
statx_timestamp_to_timespec (struct statx_timestamp tsx)
{
  struct timespec ts = { .tv_sec = tsx.tv_sec, .tv_nsec = tsx.tv_nsec };
  return ts;
}

static inline void
statx_to_stat (struct statx *stx, struct stat *st)
{
  st->st_dev = makedev (stx->stx_dev_major, stx->stx_dev_minor);
  st->st_ino = stx->stx_ino;
  st->st_mode = stx->stx_mode;
  st->st_nlink = stx->stx_nlink;
  st->st_uid = stx->stx_uid;
  st->st_gid = stx->stx_gid;
  st->st_rdev = makedev (stx->stx_rdev_major, stx->stx_rdev_minor);
  st->st_size = stx->stx_size;
  st->st_blksize = stx->stx_blksize;
/* define to avoid sc_prohibit_stat_st_blocks.  */
# define SC_ST_BLOCKS st_blocks
  st->SC_ST_BLOCKS = stx->stx_blocks;
  st->st_atim = statx_timestamp_to_timespec (stx->stx_atime);
  st->st_mtim = statx_timestamp_to_timespec (stx->stx_mtime);
  st->st_ctim = statx_timestamp_to_timespec (stx->stx_ctime);
}
#endif /* HAVE_STATX && defined(STATX_INO) */
#endif /* COREUTILS_STATX_H */
