
#ifndef POLY1305_H
#define POLY1305_H

#include <inttypes.h>

int crypto_onetimeauth(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *k);

/* Incrementally authenticating a long message */

typedef struct
{
  unsigned int r[17];
  unsigned int h[17];
  unsigned int c[17];
} poly1305_ctx;

enum {
    POLY1305_BLOCK_SIZE = 16,
    POLY1305_KEY_SIZE = 32,
    POLY1305_OUT_SIZE = 16
};

/* poly1305_init: Initialize with a key.
 */
void poly1305_init(poly1305_ctx* ctx, const uint8_t *key /* 32 bytes */);

/* poly1305_add_blocks: Add data blocks.
 * This can be called multiple times to provide data incrementally.
 * In case inlen is not a multiple of 16, it's brought to the nearest
 * multiple of 16 by padding n zero bytes, where n: (0 < n < 16).
 */
void poly1305_add_blocks(poly1305_ctx* ctx, const uint8_t *in, unsigned long long inlen);

/* poly1305_finish: Obtain the result.
 * The same key provided to poly1305_init should be provided here.
 */
void poly1305_finish(poly1305_ctx *ctx, uint8_t *out /* 16 bytes */, const uint8_t *key);

#endif
