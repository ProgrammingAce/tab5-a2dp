#pragma once
/* E0 encryption stream cipher and encryption key length reduction. Core Vol 2 Part H §4.
 * Verified bit-for-bit against the four E0 sample sets and the 16 key-reduction samples of Vol 2 Part G §1.1. */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct br_e0 {
    uint64_t r[4];   /* LFSR1..4; bit 0 = the most recently entered bit */
    uint8_t c, c1;   /* blend registers c_t and c_{t-1} (2 bits each) */
    uint8_t c2;      /* c_{t-2}: needed once, at the parallel load */
    uint8_t fresh;   /* 1 right after the parallel load */
} br_e0_t;

/* K_session = g2(L) * (K_enc mod g1(L)), L = effective key length in octets (1..16; 16 = unchanged). */
void br_e0_key_reduce(const uint8_t k_enc[16], int len_octets, uint8_t k_session[16]);

/* Initialises the generator for one packet: 200 mixing clocks and the parallel reload. bd_addr = BD_ADDR of the
 * central (index 0 = LSB); clk = the central's clock (CLK27..0) of the packet's first slot - CLK26..1 are used. */
void br_e0_init(br_e0_t* e, const uint8_t k_session[16], const uint8_t bd_addr[6], uint32_t clk);
/* Next keystream bit. */
int br_e0_bit(br_e0_t* e);
/* XORs `n` keystream bits into buf starting at bit `pos` (encrypt and decrypt are the same operation). */
void br_e0_apply(br_e0_t* e, uint8_t* buf, size_t pos, size_t n);

#ifdef __cplusplus
}
#endif
