#pragma once
/* Slot-time fast path for single-slot ACL packets (DM1, DH1), used by the C6 radio lab's TX FIFO and ARQ.
 *
 * The payload transform is CRC -> E0 -> whitening -> FEC 2/3 (DM1 only). E0 and whitening depend only on the slot
 * clock, and FEC 2/3 is linear, so a packet for any slot is
 *     DH1 air payload = P xor M(slot)          DM1 air payload = FEC23(P xor M(slot))
 * with P = plain payload bits (payload header + body + CRC) and M = whitening (bits 18.. of the slot's sequence,
 * after the 18 header bits) xor the E0 keystream. M is precomputed per slot by a task; building the packet at slot
 * time is a few XORs and table lookups. Verified bit-for-bit against br_packet_encode (tests/br/br_fast_test.c). */
#include <stddef.h>
#include <stdint.h>

#include "br/br_header.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(ESP_PLATFORM)
#include "esp_attr.h"
#define BR_FAST_ATTR IRAM_ATTR
#else
#define BR_FAST_ATTR
#endif

#define BR_FAST_PAYLOAD_BITS 240 /* DH1: (1 + 27 + 2) * 8; DM1: (1 + 17 + 2) * 8 = 160 before FEC */
#define BR_FAST_PAYLOAD_BYTES (BR_FAST_PAYLOAD_BITS / 8)

/* E0 keystream for one packet: the same bits as br_e0_init(k_session, bd_addr, clk) + nbits x br_e0_bit, written LSB
 * first into out (ceil(nbits / 8) bytes, unused high bits cleared). Word-parallel LFSRs + table combiner. */
void br_e0_keystream(const uint8_t k_session[16], const uint8_t bd_addr[6], uint32_t clk, uint8_t* out, size_t nbits);

/* Payload mask for a packet whose first slot has clock `clk` (CLK27..0): whitening from clk6 = CLK6..1, continued
 * after the 18 header bits, xor (if k_session != NULL) the E0 keystream for central `bd_addr` at `clk`. */
void br_fast_mask(uint32_t clk, const uint8_t* k_session, const uint8_t* bd_addr, uint8_t mask[BR_FAST_PAYLOAD_BYTES]);

/* Plain payload bits (1-byte payload header, body, CRC-16 with `uap`), LSB first. len <= 27 (DH1) / 17 (DM1).
 * Returns the number of bits (8 * (3 + len)). */
size_t br_fast_plain(uint8_t llid, uint8_t pflow, const uint8_t* data, size_t len, uint8_t uap,
                     uint8_t plain[BR_FAST_PAYLOAD_BYTES]);

/* The 54 header air bits (whitened with clk6, FEC 1/3), bit 0 = first on air. */
uint64_t br_fast_header(const br_header_t* h, uint8_t uap, uint8_t clk6);

/* The first 18 whitening bits (header) for clk6, bit i = whitening output i. */
uint32_t br_fast_header_whitening(uint8_t clk6);

/* table[d] = br_fec23_block(d) for all 10-bit d. */
void br_fast_fec23_table(uint16_t table[1024]);

/* Writes the air payload of `type` (BR_TYPE_DM1 or BR_TYPE_DH1) for plain bits P (nbits) and slot mask M into out at
 * bit `pos`, ORing into out (bits from pos on must be zero). Returns the number of air bits written. */
BR_FAST_ATTR size_t br_fast_payload(uint8_t type, const uint8_t* plain, size_t nbits, const uint8_t* mask,
                                    const uint16_t* fec23_table, uint8_t* out, size_t pos);

#ifdef __cplusplus
}
#endif
