#pragma once
/* Secure Simple Pairing cryptographic functions f1, g, f2, f3. Core Vol 2 Part H §7.7.
 * Verified against Vol 2 Part G §7.2 (P-192 and P-256 sets).
 * All multi-octet values are little-endian byte arrays (index 0 = least significant octet), as on HCI; the
 * functions feed them to SHA-256 most significant octet first, as the spec requires.
 * key_len = 24 for P-192 (U, V, W are 192-bit), 32 for P-256. */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_SSP_KEYID_BTLK 0x62746C6Bu /* "btlk" */

/* Commitment: f1(U, V, X, Z) = HMAC-SHA-256_X(U || V || Z) / 2^128. */
void br_ssp_f1(const uint8_t* u, const uint8_t* v, size_t key_len, const uint8_t x[16], uint8_t z, uint8_t out[16]);
/* Numeric verification: g(U, V, X, Y) = SHA-256(U || V || X || Y) mod 2^32. Displayed value = result % 1000000. */
uint32_t br_ssp_g(const uint8_t* u, const uint8_t* v, size_t key_len, const uint8_t x[16], const uint8_t y[16]);
/* Link key: f2(W, N1, N2, keyID, A1, A2) = HMAC-SHA-256_W(N1 || N2 || keyID || A1 || A2) / 2^128. */
void br_ssp_f2(const uint8_t* w, size_t key_len, const uint8_t n1[16], const uint8_t n2[16], uint32_t key_id,
               const uint8_t a1[6], const uint8_t a2[6], uint8_t out[16]);
/* Check value: f3(W, N1, N2, R, IOcap, A1, A2) = HMAC-SHA-256_W(N1 || N2 || R || IOcap || A1 || A2) / 2^128. */
void br_ssp_f3(const uint8_t* w, size_t key_len, const uint8_t n1[16], const uint8_t n2[16], const uint8_t r[16],
               const uint8_t iocap[3], const uint8_t a1[6], const uint8_t a2[6], uint8_t out[16]);

/* SHA-256 / HMAC-SHA-256 over byte streams (FIPS 180-4, RFC 2104). */
void br_sha256(const uint8_t* msg, size_t len, uint8_t out[32]);
void br_hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t len, uint8_t out[32]);

#ifdef __cplusplus
}
#endif
