/* sha3.h

   The SHA-3 hash function (aka Keccak).

   Copyright (C) 2012 Niels Möller
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

#ifndef _SHA3_H
#define _SHA3_H 1

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Indicates that SHA-3 is the NIST FIPS 202 version. */
#define COREUTILS_SHA3_FIPS202 1

/* The SHA-3 state is a 5x5 matrix of 64-bit words. In the notation of
   Keccak description, S[x,y] is element x + 5*y, so if x is
   interpreted as the row index and y the column index, it is stored
   in column-major order. */
#define SHA3_STATE_LENGTH 25

/* The "width" is 1600 bits or 200 octets */
struct sha3_state
{
  uint64_t a[SHA3_STATE_LENGTH];
};

void sha3_permute (struct sha3_state *state);
unsigned int sha3_update (struct sha3_state *state,
                          unsigned int block_size,
                          uint8_t *block,
                          unsigned int pos,
                          size_t length,
                          const uint8_t *data);
void sha3_pad (struct sha3_state *state, unsigned int block_size, uint8_t *block, unsigned int pos);

/* The "capacity" is set to 2*(digest size), 512 bits or 64 octets.
   The "rate" is the width - capacity, or width - 2 * (digest
   size).  */
#define SHA3_224_DIGEST_SIZE 28
#define SHA3_224_BLOCK_SIZE  144

#define SHA3_256_DIGEST_SIZE 32
#define SHA3_256_BLOCK_SIZE  136

#define SHA3_384_DIGEST_SIZE 48
#define SHA3_384_BLOCK_SIZE  104

#define SHA3_512_DIGEST_SIZE 64
#define SHA3_512_BLOCK_SIZE  72

#define sha3_xxx_decl(bits) \
  struct sha3_##bits##_ctx \
  { \
    struct sha3_state state; \
    unsigned int index; \
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
