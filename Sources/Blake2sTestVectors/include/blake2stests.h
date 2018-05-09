#ifndef BLAKE2S_TESTS_H
#define BLAKE2S_TESTS_H

#include <stddef.h>
#include <stdint.h>

#define BLAKE2_KAT_LENGTH 256
#define BLAKE2S_OUTBYTES 32

#if defined(__cplusplus)
extern "C" {
#endif

  /* Test vectors */
  const uint8_t blake2s_test_vectors[BLAKE2_KAT_LENGTH][BLAKE2S_OUTBYTES];

#if defined(__cplusplus)
}
#endif

#endif
