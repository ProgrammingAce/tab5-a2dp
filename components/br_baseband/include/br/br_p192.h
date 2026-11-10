#pragma once
/* ECDH on NIST P-192 (secp192r1) for Secure Simple Pairing (Core Vol 2 Part H §7.6, P-192 variant).
 * All values are 24-byte little-endian arrays (index 0 = least significant octet), as LMP carries them.
 * Not constant-time (double-and-add): fine for Just Works pairing on a personal device, not for anything else.
 * Verified against Python `cryptography` vectors (tests/br/br_p192_test.c, tools/br_lab/gen_p192_vectors.py). */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* d must satisfy 1 <= d < n (see br_p192_private_ok). Returns 0. */
int br_p192_public(const uint8_t d[24], uint8_t x[24], uint8_t y[24]);
/* DHKey = x coordinate of d * (px, py). Returns -1 if (px, py) is not on the curve, else 0. */
int br_p192_dhkey(const uint8_t d[24], const uint8_t px[24], const uint8_t py[24], uint8_t out_x[24]);
int br_p192_on_curve(const uint8_t x[24], const uint8_t y[24]);
/* 1 if 1 <= d < n (the group order). Draw random 24 bytes until this holds. */
int br_p192_private_ok(const uint8_t d[24]);

#ifdef __cplusplus
}
#endif
