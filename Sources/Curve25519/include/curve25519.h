#ifndef CURVE_25519_H
#define CURVE_25519_H

enum {
    CURVE25519_PRIVATE_KEY_SIZE = 32,
    CURVE25519_PUBLIC_KEY_SIZE = 32,
    CURVE25519_SHARED_KEY_SIZE = 32
};

/* Compute public key from private key */

int crypto_scalarmult_base(unsigned char *q,
  const unsigned char *n /* private key */);

/* Compute shared key from our private key and their public key */

int crypto_scalarmult(unsigned char *q,
  const unsigned char *n /* private key */,
  const unsigned char *p /* public key */);

#endif
