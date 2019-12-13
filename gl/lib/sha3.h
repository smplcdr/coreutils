/* sha3.h

   The SHA-3 hash function (aka Keccak).

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

#ifndef _SHA3_H
#define _SHA3_H 1

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Indicates that SHA-3 is the NIST FIPS 202 version. */
#define SHA3_FIPS202 1

/* The SHA-3 state is a 5x5 matrix of 64-bit words. In the notation of
   Keccak description, S[x, y] is element X + 5 * Y, so if X is
   interpreted as the row index and Y the column index, it is stored
   in column-major order. */
#define SHA3_STATE_LENGTH 25

/* The "width" is 1600 bits or 200 octets */
struct sha3_state
{
  uint64_t A[SHA3_STATE_LENGTH];
};

extern void sha3_permute (uint64_t A[SHA3_STATE_LENGTH]);
extern size_t sha3_update (uint64_t A[SHA3_STATE_LENGTH],
                           size_t block_size,
                           uint8_t *block,
                           size_t pos,
                           size_t length,
                           const uint8_t *data);
extern void sha3_pad (uint64_t A[SHA3_STATE_LENGTH], size_t block_size, uint8_t *block, size_t pos);

/* The "capacity" is set to 2 * (digest size), 512 bits or 64 octets.
   The "rate" is the width - capacity, or width - 2 * (digest size).  */
#define SHA3_224_DIGEST_SIZE (224 / 8)
#define SHA3_224_BLOCK_SIZE  (1600 / 8 - 224 / 4)

#define SHA3_256_DIGEST_SIZE (256 / 8)
#define SHA3_256_BLOCK_SIZE  (1600 / 8 - 256 / 4)

#define SHA3_384_DIGEST_SIZE (384 / 8)
#define SHA3_384_BLOCK_SIZE  (1600 / 8 - 384 / 4)

#define SHA3_512_DIGEST_SIZE (512 / 8)
#define SHA3_512_BLOCK_SIZE  (1600 / 8 - 512 / 4)

#define sha3_xxx_decl(bits) \
  struct sha3_##bits##_ctx \
  { \
    struct sha3_state state; \
    size_t index; \
    uint8_t block[SHA3_##bits##_BLOCK_SIZE]; \
  }; \
  extern void sha3_##bits##_init (struct sha3_##bits##_ctx *ctx); \
  extern void sha3_##bits##_update (struct sha3_##bits##_ctx *ctx, size_t length, const uint8_t *data); \
  extern void sha3_##bits##_final (struct sha3_##bits##_ctx *ctx, size_t length, uint8_t *digest); \
  extern int  sha3_##bits##_stream (FILE *stream, void *resblock);

sha3_xxx_decl (224)
sha3_xxx_decl (256)
sha3_xxx_decl (384)
sha3_xxx_decl (512)

#undef sha3_xxx_decl

extern int sha3_stream (FILE *stream, void *resblock, size_t databitlen);

#ifdef __cplusplus
}
#endif

#endif /* _SHA3_H */
