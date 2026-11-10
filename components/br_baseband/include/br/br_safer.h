#pragma once
/* SAFER+ based authentication and key generation functions. Core Vol 2 Part H §6 (E1 §6.3, E21/E22 §6.4,
 * E3 §6.5, Ar/A'r §6.1). Byte arrays: index 0 = least significant byte (as the spec's sample data). */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Round sub-keys K1..K17 for a 128-bit key (keys[0] = K1). */
void br_safer_keys(const uint8_t key[16], uint8_t keys[17][16]);
/* Ar (prime = 0) or A'r (prime = 1). `rounds` (may be NULL) receives the input of rounds 1..8 and, at index 8,
 * the round-3 input after A'r's addition of the original input (equal to rounds[2] for Ar). */
void br_safer_encrypt(const uint8_t key[16], const uint8_t in[16], int prime, uint8_t out[16], uint8_t rounds[9][16]);

/* E1: SRES (4 bytes) and ACO (12 bytes). bd_addr: 6 bytes, index 0 = LSB. */
void br_e1(const uint8_t key[16], const uint8_t rand[16], const uint8_t bd_addr[6], uint8_t sres[4], uint8_t aco[12]);
/* E21: unit/combination key contribution. */
void br_e21(const uint8_t rand[16], const uint8_t bd_addr[6], uint8_t out[16]);
/* E22: initialisation key from a PIN (1..16 bytes), augmented with bd_addr when shorter than 16. */
void br_e22(const uint8_t rand[16], const uint8_t* pin, size_t pin_len, const uint8_t bd_addr[6], uint8_t out[16]);
/* E3: encryption key K_C from the link key, EN_RAND and COF (the ACO for a point-to-point link). */
void br_e3(const uint8_t key[16], const uint8_t rand[16], const uint8_t cof[12], uint8_t kc[16]);

#ifdef __cplusplus
}
#endif
