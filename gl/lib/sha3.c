/* sha3.c

   The SHA-3 hash function.

   Copyright (C) 2012 Niels Möller
   Copyright (C) 2019 Sergey Sushilin

   This file is part of GNU Coreutils.

   GNU Coreutils is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sha3.h"

#include "memxor.h"

#define LE_READ_UINT64(p) \
  ((((uint64_t) (p)[7]) << 56) \
 | (((uint64_t) (p)[6]) << 48) \
 | (((uint64_t) (p)[5]) << 40) \
 | (((uint64_t) (p)[4]) << 32) \
 | (((uint64_t) (p)[3]) << 24) \
 | (((uint64_t) (p)[2]) << 16) \
 | (((uint64_t) (p)[1]) << 8) \
 |  ((uint64_t) (p)[0]) << 0)

#define LE_WRITE_UINT64(p, i) \
  do \
    { \
      (p)[7] = ((i) >> 56) & 0xFF; \
      (p)[6] = ((i) >> 48) & 0xFF; \
      (p)[5] = ((i) >> 40) & 0xFF; \
      (p)[4] = ((i) >> 32) & 0xFF; \
      (p)[3] = ((i) >> 24) & 0xFF; \
      (p)[2] = ((i) >> 16) & 0xFF; \
      (p)[1] = ((i) >> 8)  & 0xFF; \
      (p)[0] = ((i) >> 0)  & 0xFF; \
    } \
  while (0)

static void
sha3_absorb (uint64_t A[SHA3_STATE_LENGTH], size_t length, const uint8_t *data)
{
  assert ((length & 7) == 0);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  {
    uint64_t *p;
    for (p = A; length != 0; p++, length -= 8, data += 8)
      *p ^= LE_READ_UINT64 (data);
  }
#else /* !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__ */
  memxor (A, data, length);
#endif

  sha3_permute (A);
}

size_t
sha3_update (uint64_t A[SHA3_STATE_LENGTH],
             size_t block_size,
             uint8_t *block,
             size_t pos,
             size_t length,
             const uint8_t *data)
{
  if (pos != 0)
    {
      size_t left = block_size - pos;
      if (length < left)
        {
          memcpy (block + pos, data, length);
          return pos + length;
        }
      else
        {
          memcpy (block + pos, data, left);
          data += left;
          length -= left;
          sha3_absorb (A, block_size, block);
        }
    }

  for (; length >= block_size; length -= block_size, data += block_size)
    sha3_absorb (A, block_size, data);

  memcpy (block, data, length);
  return length;
}

void
sha3_pad (uint64_t A[SHA3_STATE_LENGTH], size_t block_size, uint8_t *block, size_t pos)
{
  assert (pos < block_size);

  block[pos++] = 6;

  memset (block + pos, '\0', block_size - pos);
  block[block_size - 1] |= 0x80;

  sha3_absorb (A, block_size, block);
}

/* Write the word array at SRC to the byte array at DST, using little
   endian (le) byte order, and truncating the result to LENGTH bytes.  */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static inline void
write_le64 (size_t length, uint8_t *dst, const uint64_t *src)
{
  memcpy (dst, src, length);
}
#else
static inline void
write_le64 (size_t length, uint8_t *dst, const uint64_t *src)
{
  size_t words = length / 8;
  unsigned int leftover = length % 8;

  for (size_t i = 0; i < words; i++, dst += 8)
    LE_WRITE_UINT64 (dst, src[i]);

  if (leftover != 0)
    {
      uint64_t word = src[words];

      while (leftover--)
        {
          *dst++ = word & 0xFF;
          word >>= 8;
        }
    }
}
#endif /* defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ */

#define sha3_xxx_impl(bits)                                             \
  void                                                                  \
  sha3_##bits##_init (struct sha3_##bits##_ctx *ctx)                    \
  {                                                                     \
    memset (ctx, '\0', offsetof (struct sha3_##bits##_ctx, block));     \
  }                                                                     \
                                                                        \
  void                                                                  \
  sha3_##bits##_update (struct sha3_##bits##_ctx *ctx,                  \
                        size_t length,                                  \
                        const uint8_t *data)                            \
  {                                                                     \
    ctx->index = sha3_update (ctx->state.A, SHA3_##bits##_BLOCK_SIZE,   \
                              ctx->block, ctx->index, length,           \
                              data);                                    \
  }                                                                     \
                                                                        \
   void                                                                 \
   sha3_##bits##_final (struct sha3_##bits##_ctx *ctx,                  \
                        size_t length,                                  \
                        uint8_t *digest)                                \
   {                                                                    \
     sha3_pad (ctx->state.A, SHA3_##bits##_BLOCK_SIZE, ctx->block,      \
               ctx->index);                                             \
     write_le64 (length, digest, ctx->state.A);                         \
     sha3_##bits##_init (ctx);                                          \
   }                                                                    \
                                                                        \
   int                                                                  \
   sha3_##bits##_stream (FILE *stream, void *resblock)                  \
   {                                                                    \
     uint8_t *in = malloc (bits);                                       \
                                                                        \
     if (in == NULL)                                                    \
       return 1;                                                        \
                                                                        \
     size_t bytesread = 0;                                              \
     struct sha3_##bits##_ctx ctx;                                      \
                                                                        \
     sha3_##bits##_init (&ctx);                                         \
                                                                        \
     while ((bytesread = fread (in, sizeof (char), bits, stream)) != 0) \
       sha3_##bits##_update (&ctx, bytesread, in);                      \
                                                                        \
     sha3_##bits##_final (&ctx, bits / 8, resblock);                    \
                                                                        \
     free (in);                                                         \
                                                                        \
     return 0;                                                          \
   }

sha3_xxx_impl (224)
sha3_xxx_impl (256)
sha3_xxx_impl (384)
sha3_xxx_impl (512)

#undef sha3_xxx_impl

int
sha3_stream (FILE *stream, void *resblock, size_t datalen)
{
  int result = -1;

  switch (datalen)
    {
    case SHA3_224_DIGEST_SIZE:
      result = sha3_224_stream (stream, resblock);
      break;
    case SHA3_256_DIGEST_SIZE:
      result = sha3_256_stream (stream, resblock);
      break;
    case SHA3_384_DIGEST_SIZE:
      result = sha3_384_stream (stream, resblock);
      break;
    case SHA3_512_DIGEST_SIZE:
      result = sha3_512_stream (stream, resblock);
      break;
    default:
      assert (!"invalid digest size");
    }

  return result;
}
