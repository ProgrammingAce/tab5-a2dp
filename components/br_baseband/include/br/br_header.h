#pragma once
/* Packet header. Core Vol 2 Part B §6.4: LT_ADDR(3) TYPE(4) FLOW(1) ARQN(1) SEQN(1) HEC(8) = 18 bits,
 * whitened, then FEC 1/3 -> 54 bits on air. */
#include <stddef.h>
#include <stdint.h>

#include "br/br_whiten.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BR_HEADER_AIR_BITS 54

typedef struct {
    uint8_t lt_addr; /* 0..7 */
    uint8_t type;    /* 0..15, see br_packet.h */
    uint8_t flow, arqn, seqn;
} br_header_t;

uint16_t br_header_pack10(const br_header_t* h);
void br_header_unpack10(uint16_t v, br_header_t* h);

/* Writes the 54 air bits at `pos`. `w` (may be NULL = no whitening) advances 18 bits. */
void br_header_encode(const br_header_t* h, uint8_t uap, br_whiten_t* w, uint8_t* buf, size_t pos);
/* Reads 54 air bits at `pos`. Returns 0 if the HEC matches, -1 otherwise. `w` advances 18 bits. */
int br_header_decode(const uint8_t* buf, size_t pos, uint8_t uap, br_whiten_t* w, br_header_t* h);

#ifdef __cplusplus
}
#endif
