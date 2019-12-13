/* memxor-internal.h

   Copyright (C) 2010, 2014 Niels Möller
   Copyright (C) 2019 Sergey Sushilin

   This file is part of GNU Coreutils.

   GNU Coreutils is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Coreutils is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#ifndef _MEMXOR_INTERNAL_H
#define _MEMXOR_INTERNAL_H 1

#include <stdint.h>
#include "verify.h"

/* The word_t type is intended to be the native word size. */
#if 0
#if defined(__x86_64__) || defined(__arch64__)
/* Including on M$ Windows, where unsigned long is only 32 bits */
typedef uint64_t word_t;
#else
typedef unsigned long int word_t;
#endif
#endif

/* Native word size == sizeof (pointer).  */
typedef uintptr_t word_t;

#define ALIGN_OFFSET(p) ((uintptr_t) (p) % sizeof (word_t))

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__
# define MERGE(w0, sh_1, w1, sh_2) (((w0) >> (sh_1)) | ((w1) << (sh_2)))
#else
# define MERGE(w0, sh_1, w1, sh_2) (((w0) << (sh_1)) | ((w1) >> (sh_2)))
#endif

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__
# define READ_PARTIAL(r, p, n) \
  do \
    { \
      word_t __rp_x__; \
      unsigned int __rp_i__; \
      for (__rp_i__ = (n), __rp_x__ = (p)[--__rp_i__]; __rp_i__ > 0;) \
        __rp_x__ = (__rp_x__ << CHAR_BIT) | (p)[--__rp_i__]; \
      (r) = __rp_x__; \
    } \
  while (0)
#else
# define READ_PARTIAL(r, p, n) \
  do \
    { \
      word_t __rp_x__; \
      unsigned int __rp_i__; \
      for (__rp_x__ = (p)[0], __rp_i__ = 1; __rp_i__ < (n); __rp_i__++) \
        __rp_x__ = (__rp_x__ << CHAR_BIT) | (p)[__rp_i__]; \
      (r) = __rp_x__; \
    } \
  while (0)
#endif

#endif /* _MEMXOR_INTERNAL_H */
