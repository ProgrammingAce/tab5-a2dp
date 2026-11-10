#pragma once
/* Header Error Check and payload CRC. Core Vol 2 Part B §7.1. */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HEC over the 10 header bits (bit 0 = first on air: LT_ADDR0..2, TYPE0..3, FLOW, ARQN, SEQN).
 * LFSR g(D) = D^8+D^7+D^5+D^2+D+1 initialised with the UAP. Result bit j = j-th transmitted HEC bit. */
uint8_t br_hec(uint16_t header10, uint8_t uap);

/* CRC-16 over `nbits` bits of `buf` starting at bit `pos`. g(D) = D^16+D^12+D^5+1, initialised with the UAP
 * in the low 8 register positions. Result bit j = j-th transmitted CRC bit. */
uint16_t br_crc16(const uint8_t* buf, size_t pos, size_t nbits, uint8_t uap);

#ifdef __cplusplus
}
#endif
