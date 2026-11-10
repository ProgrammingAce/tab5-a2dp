#pragma once
/* Packet types for the ACL logical transport (BR only). Core Vol 2 Part B §6.5, §6.6. */
#include <stddef.h>
#include <stdint.h>

#include "br/br_header.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    BR_TYPE_NULL = 0x0,
    BR_TYPE_POLL = 0x1,
    BR_TYPE_FHS = 0x2,
    BR_TYPE_DM1 = 0x3,
    BR_TYPE_DH1 = 0x4,
    BR_TYPE_DM3 = 0xA,
    BR_TYPE_DH3 = 0xB,
    BR_TYPE_DM5 = 0xE,
    BR_TYPE_DH5 = 0xF,
};

/* LLID values in the payload header. Core Vol 2 Part B §6.6.2. */
enum { BR_LLID_L2CAP_CONT = 1, BR_LLID_L2CAP_START = 2, BR_LLID_LMP = 3 };

#define BR_MAX_PAYLOAD 339 /* DH5 */
#define BR_FHS_BYTES 18    /* 144 bits before CRC */
/* Largest packet on air: 72 access + 54 header + DH5 (16 + 339*8 + 16). Rounded up. */
#define BR_PACKET_MAX_BITS 2880
#define BR_PACKET_MAX_BYTES (BR_PACKET_MAX_BITS / 8)

typedef enum {
    BR_OK = 0,
    BR_ERR_TOO_SHORT = -1,
    BR_ERR_HEC = -2,
    BR_ERR_FEC = -3,
    BR_ERR_CRC = -4,
    BR_ERR_TYPE = -5,   /* type not supported by this library */
    BR_ERR_LENGTH = -6, /* payload length out of range for the type */
    BR_ERR_SYNC = -7,   /* access code sync word does not match */
} br_status_t;

typedef struct {
    br_header_t hdr;
    /* Payload header (DMx/DHx only) */
    uint8_t llid;
    uint8_t pflow;
    uint16_t len; /* payload body bytes; FHS always BR_FHS_BYTES */
    uint8_t payload[BR_MAX_PAYLOAD];
} br_pkt_t;

typedef struct {
    uint32_t lap;   /* access code LAP (channel access code = master's LAP; DAC/IAC for ID packets) */
    uint8_t uap;    /* HEC/CRC initialisation (DCI 0x00 for inquiry-related packets) */
    uint8_t clk6;   /* CLK1..6 for whitening, see br_whiten_init */
    uint8_t no_whitening;
    uint8_t sync_tolerance; /* decode: allowed bit errors in the sync word */
    /* Optional E0 encryption (Vol 2 Part H §4): when set, the payload (payload header, body and CRC, not FHS) is
     * XORed with this generator's keystream after the CRC and before whitening (decode: after de-whitening, before
     * the CRC check). The caller initialises it per packet with br_e0_init(Kc', central BD_ADDR, CLK); it advances. */
    struct br_e0* e0;
} br_link_ctx_t;

/* Max payload body bytes for a type, 0 for NULL/POLL, BR_FHS_BYTES for FHS, -1 if unsupported. */
int br_type_max_len(uint8_t type);
/* Number of 625 us slots a packet type occupies (1, 3 or 5). */
int br_type_slots(uint8_t type);

/* Encodes access code (72 bits) + header + payload into `out` (zeroed by the function).
 * `out_cap` is the buffer size in bytes. Writes the bit count to *nbits. */
br_status_t br_packet_encode(const br_pkt_t* p, const br_link_ctx_t* ctx, uint8_t* out, size_t out_cap, size_t* nbits);
/* Decodes from `in` (bit 0 = first preamble bit) with `nbits` available. */
br_status_t br_packet_decode(const uint8_t* in, size_t nbits, const br_link_ctx_t* ctx, br_pkt_t* p);

/* FHS payload fields. Core Vol 2 Part B §6.5.1.4. */
typedef struct {
    uint64_t parity;   /* 34 bits */
    uint32_t lap;      /* 24 */
    uint8_t eir;       /* 1 */
    uint8_t sr;        /* 2 */
    uint8_t uap;       /* 8 */
    uint16_t nap;      /* 16 */
    uint32_t cod;      /* 24, class of device */
    uint8_t lt_addr;   /* 3 */
    uint32_t clk27_2;  /* 26 */
    uint8_t page_scan_mode; /* 3 */
} br_fhs_t;

void br_fhs_pack(const br_fhs_t* f, uint8_t out[BR_FHS_BYTES]);
void br_fhs_unpack(const uint8_t in[BR_FHS_BYTES], br_fhs_t* f);
/* Parity field for a device's own LAP: sync word bits 0..33. TODO(spec): confirm against Vol 2 Part G sample data. */
uint64_t br_fhs_parity_for_lap(uint32_t lap);

#ifdef __cplusplus
}
#endif
