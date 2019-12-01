/* selinux - core functions for maintaining SELinux labeling
   Copyright (C) 2012-2019 Free Software Foundation, Inc.

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

/* Written by Daniel Walsh <dwalsh@redhat.com> */

#ifndef _COREUTILS_SELINUX_H
#define _COREUTILS_SELINUX_H 1

/* Return true if ERR corresponds to an unsupported request,
   or if there is no context or it is inaccessible.  */
static inline bool
ignorable_ctx_err (int err)
{
  return err == ENOTSUP || err == ENODATA;
}

#if HAVE_SELINUX_SELINUX_H
extern bool restorecon (const char *path, bool recurse, bool preserve);
extern int defaultcon (const char *path, mode_t mode);
#else /* !HAVE_SELINUX_SELINUX_H */
static inline bool
restorecon (const char *path, bool recurse, bool preserve)
{
  errno = ENOTSUP;
  return false;
}
static inline int
defaultcon (const char *path, mode_t mode)
{
  errno = ENOTSUP;
  return -1;
}
#endif /* HAVE_SELINUX_SELINUX_H */

#endif /* _COREUTILS_SELINUX_H */
