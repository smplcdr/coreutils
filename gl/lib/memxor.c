/* memxor.c

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

/* Implementation inspired by memcmp in glibc, contributed to the FSF
   by Torbjorn Granlund.  */

#include <config.h>

#include <assert.h>
#include <limits.h>

#include "memxor.h"
#include "memxor-internal.h"

#define WORD_T_THRESH 16

/* XOR word-aligned areas. N is the number of words, not bytes.  */
static void
memxor_common_alignment (word_t *dst, const word_t *src, size_t n)
{
  /* FIXME: Unroll four times, like memcmp? Probably not worth the
     effort.  */

  assert (n > 0);

  if (n & 1)
    {
      n--;
      dst[n] ^= src[n];
    }
  while (n >= 2)
    {
      n -= 2;
      dst[n + 1] ^= src[n + 1];
      dst[n] ^= src[n];
    }
}

/* XOR *un-aligned* src-area onto aligned dst area.  N is number of
   words, not bytes.  Assumes we can read complete words at the start
   and end of the src operand.  */
static void
memxor_different_alignment (word_t *dst, const unsigned char *src, size_t n)
{
  int shl, shr;
  const word_t *src_word;
  unsigned offset = ALIGN_OFFSET (src);
  word_t s0, s1;

  assert (n > 0);
  shl = CHAR_BIT * offset;
  shr = CHAR_BIT * (sizeof(word_t) - offset);

  src_word = (const word_t *) ((uintptr_t) src & -sizeof (word_t));

  /* Read top offset bytes, in native byte order. */
  READ_PARTIAL (s0, (unsigned char *) &src_word[n], offset);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  s0 <<= shr; /* FIXME: Eliminate this shift? */
#endif

  /* Do n-1 regular iterations */
  if (n & 1)
    s1 = s0;
  else
    {
      n--;
      s1 = src_word[n];
      dst[n] ^= MERGE (s1, shl, s0, shr);
    }

  assert (n & 1);
  while (n > 2)
    {
      n -= 2;
      s0 = src_word[n+1];
      dst[n+1] ^= MERGE(s0, shl, s1, shr);
      s1 = src_word[n]; /* FIXME: Overread on last iteration.  */
      dst[n] ^= MERGE(s1, shl, s0, shr);
    }
  assert (n == 1);
  /* Read low wordsize -- offset bytes.  */
  READ_PARTIAL (s0, src, sizeof(word_t) - offset);
#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__
  s0 <<= shl; /* FIXME: eliminate shift? */
#endif /* !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__ */

  dst[0] ^= MERGE(s0, shl, s1, shr);
}

/* Performance, Intel SU1400 (x86_64): 0.25 cycles/byte aligned, 0.45
   cycles/byte unaligned.  */

/* XOR N bytes starting at SOURCE onto DESTINATION.  Result undefined
   if the source overlaps with the destination.  Return DESTINATION.  */
void *
memxor (void *destination, const void *source, size_t n)
{
  unsigned char *dst = destination;
  const unsigned char *src = source;

  if (n >= WORD_T_THRESH)
    {
      /* There are at least some bytes to compare.  No need to test
         for N == 0 in this alignment loop.  */
      for (unsigned int i = ALIGN_OFFSET(dst + n); i > 0; i--)
        {
          n--;
          dst[n] ^= src[n];
        }
      unsigned int offset = ALIGN_OFFSET (src + n);
      size_t nwords = n / sizeof (word_t);
      n %= sizeof (word_t);

      if (offset != 0)
        memxor_different_alignment ((word_t *) (dst + n), src + n, nwords);
      else
        memxor_common_alignment ((word_t *) (dst + n), (const word_t *) (src + n), nwords);
    }
  while (n > 0)
    {
      n--;
      dst[n] ^= src[n];
    }

  return dst;
}
