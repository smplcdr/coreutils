/* Copyright (C) 2019 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#if !HAVE_STRLCPY
# include <config.h>

# include <string.h>

# include "strlcpy.h"

# undef strlcpy

/*
 * Safe strncpy, the result is always a valid
 * NUL-terminated string that fits in the buffer
 * (unless, of course, the buffer size is zero).
 */
size_t
strlcpy (char *dst, const char *src, size_t n)
{
  if (n != 0 && *src != '\0')
    {
      size_t len = strnlen (src, n);
      memcpy (dst, src, len);
      dst[len] = '\0';
      return len;
    }
  return 0;
}
#else
typedef int dummy;
#endif
