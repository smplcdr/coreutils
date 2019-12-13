/* sha3-permute.c

   The sha3 permutation function (aka Keccak).

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

#include <stdint.h>

#include "sha3.h"

#define SHA3_ROUNDS 24

/* The masking of the right shift is needed to allow n == 0 (using
   just 64 - n result in undefined behaviour).  Most uses
   of this macros use a constant and non-zero rotation count. */
#if defined(_MSC_VER)
# define ROTL64(n, x) _rotl64 (n, offset)
#elif defined(__INTEL_COMPILER)
# define ROTL64(n, x) _lrotl (n, x)
#elif defined(__GNUC__) || defined(__TINYC__)
# define ROTL64(n, x) \
  ({ \
    register uint64_t __in = x, __out; \
    __asm__ __volatile__ ("shld %2,%0,%0" : "=r"(__out) : "0"(__in), "i"(n)); \
    __out; \
  })
#else
# define ROTL64(n, x) (((x) << (n)) | ((x) >> ((-(n)) & 63)))
#endif

void
sha3_permute (uint64_t A[SHA3_STATE_LENGTH])
{
  static const uint64_t rc[SHA3_ROUNDS] =
  {
    UINT64_C (0x0000000000000001), UINT64_C (0X0000000000008082),
    UINT64_C (0x800000000000808A), UINT64_C (0x8000000080008000),
    UINT64_C (0x000000000000808B), UINT64_C (0x0000000080000001),
    UINT64_C (0x8000000080008081), UINT64_C (0x8000000000008009),
    UINT64_C (0x000000000000008A), UINT64_C (0x0000000000000088),
    UINT64_C (0x0000000080008009), UINT64_C (0x000000008000000A),
    UINT64_C (0x000000008000808B), UINT64_C (0x800000000000008B),
    UINT64_C (0x8000000000008089), UINT64_C (0x8000000000008003),
    UINT64_C (0x8000000000008002), UINT64_C (0x8000000000000080),
    UINT64_C (0x000000000000800A), UINT64_C (0x800000008000000A),
    UINT64_C (0x8000000080008081), UINT64_C (0x8000000000008080),
    UINT64_C (0x0000000080000001), UINT64_C (0x8000000080008008),
  };

  /*
    Original permutation:

        0, 10, 20,  5, 15,
       16,  1, 11, 21,  6,
        7, 17,  2, 12, 22,
       23,  8, 18,  3, 13,
       14, 24,  9, 19,  4

     Rotation counts:

        0,  1, 62, 28, 27,
       36, 44,  6, 55, 20,
        3, 10, 43, 25, 39,
       41, 45, 15, 21,  8,
       18,  2, 61, 56, 14,
  */

  /*
    In-place implementation. Permutation done as a long sequence of
    25 moves "following" the permutation.

       T <--  1
       1 <--  6
       6 <--  9
       9 <-- 22
      22 <-- 14
      14 <-- 20
      20 <--  2
       2 <-- 12
      12 <-- 13
      13 <-- 19
      19 <-- 23
      23 <-- 15
      15 <--  4
       4 <-- 24
      24 <-- 21
      21 <--  8
       8 <-- 16
      16 <--  5
       5 <--  3
       3 <-- 18
      18 <-- 17
      17 <-- 11
      11 <--  7
       7 <-- 10
      10 <--  T
  */
  uint64_t C[5], D[5], T, X;

  C[0] = A[0+0] ^ A[5+0] ^ A[10+0] ^ A[15+0] ^ A[20+0];
  C[1] = A[0+1] ^ A[5+1] ^ A[10+1] ^ A[15+1] ^ A[20+1];
  C[2] = A[0+2] ^ A[5+2] ^ A[10+2] ^ A[15+2] ^ A[20+2];
  C[3] = A[0+3] ^ A[5+3] ^ A[10+3] ^ A[15+3] ^ A[20+3];
  C[4] = A[0+4] ^ A[5+4] ^ A[10+4] ^ A[15+4] ^ A[20+4];

  for (unsigned int i = 0; i < SHA3_ROUNDS; i++)
    {
      D[0] = C[4] ^ ROTL64(1, C[1]);
      D[1] = C[0] ^ ROTL64(1, C[2]);
      D[2] = C[1] ^ ROTL64(1, C[3]);
      D[3] = C[2] ^ ROTL64(1, C[4]);
      D[4] = C[3] ^ ROTL64(1, C[0]);

      A[0] ^= D[0];
      X = A[ 1] ^ D[1];     T = ROTL64 ( 1, X);
      X = A[ 6] ^ D[1]; A[ 1] = ROTL64 (44, X);
      X = A[ 9] ^ D[4]; A[ 6] = ROTL64 (20, X);
      X = A[22] ^ D[2]; A[ 9] = ROTL64 (61, X);
      X = A[14] ^ D[4]; A[22] = ROTL64 (39, X);
      X = A[20] ^ D[0]; A[14] = ROTL64 (18, X);
      X = A[ 2] ^ D[2]; A[20] = ROTL64 (62, X);
      X = A[12] ^ D[2]; A[ 2] = ROTL64 (43, X);
      X = A[13] ^ D[3]; A[12] = ROTL64 (25, X);
      X = A[19] ^ D[4]; A[13] = ROTL64 ( 8, X);
      X = A[23] ^ D[3]; A[19] = ROTL64 (56, X);
      X = A[15] ^ D[0]; A[23] = ROTL64 (41, X);
      X = A[ 4] ^ D[4]; A[15] = ROTL64 (27, X);
      X = A[24] ^ D[4]; A[ 4] = ROTL64 (14, X);
      X = A[21] ^ D[1]; A[24] = ROTL64 ( 2, X);
      X = A[ 8] ^ D[3]; A[21] = ROTL64 (55, X); /* Row 4 done.  */
      X = A[16] ^ D[1]; A[ 8] = ROTL64 (45, X);
      X = A[ 5] ^ D[0]; A[16] = ROTL64 (36, X);
      X = A[ 3] ^ D[3]; A[ 5] = ROTL64 (28, X);
      X = A[18] ^ D[3]; A[ 3] = ROTL64 (21, X); /* Row 0 done.  */
      X = A[17] ^ D[2]; A[18] = ROTL64 (15, X);
      X = A[11] ^ D[1]; A[17] = ROTL64 (10, X); /* Row 3 done.  */
      X = A[ 7] ^ D[2]; A[11] = ROTL64 ( 6, X); /* Row 1 done.  */
      X = A[10] ^ D[0]; A[ 7] = ROTL64 ( 3, X);
      A[10] = T; /* Row 2 done.  */

      D[0] = ~A[1] & A[2];
      D[1] = ~A[2] & A[3];
      D[2] = ~A[3] & A[4];
      D[3] = ~A[4] & A[0];
      D[4] = ~A[0] & A[1];

      A[0] ^= D[0] ^ rc[i]; C[0] = A[0];
      A[1] ^= D[1];         C[1] = A[1];
      A[2] ^= D[2];         C[2] = A[2];
      A[3] ^= D[3];         C[3] = A[3];
      A[4] ^= D[4];         C[4] = A[4];

      D[0] = ~A[5+1] & A[5+2];
      D[1] = ~A[5+2] & A[5+3];
      D[2] = ~A[5+3] & A[5+4];
      D[3] = ~A[5+4] & A[5+0];
      D[4] = ~A[5+0] & A[5+1];

      A[5+0] ^= D[0]; C[0] ^= A[5+0];
      A[5+1] ^= D[1]; C[1] ^= A[5+1];
      A[5+2] ^= D[2]; C[2] ^= A[5+2];
      A[5+3] ^= D[3]; C[3] ^= A[5+3];
      A[5+4] ^= D[4]; C[4] ^= A[5+4];

      D[0] = ~A[10+1] & A[10+2];
      D[1] = ~A[10+2] & A[10+3];
      D[2] = ~A[10+3] & A[10+4];
      D[3] = ~A[10+4] & A[10+0];
      D[4] = ~A[10+0] & A[10+1];

      A[10+0] ^= D[0]; C[0] ^= A[10+0];
      A[10+1] ^= D[1]; C[1] ^= A[10+1];
      A[10+2] ^= D[2]; C[2] ^= A[10+2];
      A[10+3] ^= D[3]; C[3] ^= A[10+3];
      A[10+4] ^= D[4]; C[4] ^= A[10+4];

      D[0] = ~A[15+1] & A[15+2];
      D[1] = ~A[15+2] & A[15+3];
      D[2] = ~A[15+3] & A[15+4];
      D[3] = ~A[15+4] & A[15+0];
      D[4] = ~A[15+0] & A[15+1];

      A[15+0] ^= D[0]; C[0] ^= A[15+0];
      A[15+1] ^= D[1]; C[1] ^= A[15+1];
      A[15+2] ^= D[2]; C[2] ^= A[15+2];
      A[15+3] ^= D[3]; C[3] ^= A[15+3];
      A[15+4] ^= D[4]; C[4] ^= A[15+4];

      D[0] = ~A[20+1] & A[20+2];
      D[1] = ~A[20+2] & A[20+3];
      D[2] = ~A[20+3] & A[20+4];
      D[3] = ~A[20+4] & A[20+0];
      D[4] = ~A[20+0] & A[20+1];

      A[20+0] ^= D[0]; C[0] ^= A[20+0];
      A[20+1] ^= D[1]; C[1] ^= A[20+1];
      A[20+2] ^= D[2]; C[2] ^= A[20+2];
      A[20+3] ^= D[3]; C[3] ^= A[20+3];
      A[20+4] ^= D[4]; C[4] ^= A[20+4];
    }
}
