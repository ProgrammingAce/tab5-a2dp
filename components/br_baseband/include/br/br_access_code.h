#pragma once
/* Access codes. Core Vol 2 Part B §6.3 (format) and §6.3.3.1 (sync word construction). */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* General Inquiry Access Code LAP. Core: Assigned Numbers, "Baseband". */
#define BR_GIAC_LAP 0x9E8B33u

/* 64-bit sync word for a 24-bit LAP. Bit 0 = first bit on air. Bits 34..57 equal the LAP, 58..63 the Barker. */
uint64_t br_sync_word(uint32_t lap);

/* Writes the access code at bit 0 of `buf`: preamble (4) + sync word (64) [+ trailer (4)].
 * with_trailer = 0 gives the 68-bit ID packet. Returns the number of bits written (68 or 72). */
size_t br_access_code_bits(uint32_t lap, int with_trailer, uint8_t* buf);

#ifdef __cplusplus
}
#endif
