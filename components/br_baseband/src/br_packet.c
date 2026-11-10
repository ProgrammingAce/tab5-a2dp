#include "br/br_packet.h"

#include <string.h>

#include "br/br_access_code.h"
#include "br/br_bits.h"
#include "br/br_crc.h"
#include "br/br_fec.h"
#include "br/br_whiten.h"
#include "br/br_e0.h"

int br_type_max_len(uint8_t type)
{
    switch (type) {
    case BR_TYPE_NULL:
    case BR_TYPE_POLL: return 0;
    case BR_TYPE_FHS: return BR_FHS_BYTES;
    case BR_TYPE_DM1: return 17;
    case BR_TYPE_DH1: return 27;
    case BR_TYPE_DM3: return 121;
    case BR_TYPE_DH3: return 183;
    case BR_TYPE_DM5: return 224;
    case BR_TYPE_DH5: return 339;
    default: return -1;
    }
}

int br_type_slots(uint8_t type)
{
    switch (type) {
    case BR_TYPE_DM3:
    case BR_TYPE_DH3: return 3;
    case BR_TYPE_DM5:
    case BR_TYPE_DH5: return 5;
    default: return 1;
    }
}

static int type_has_fec23(uint8_t t) { return t == BR_TYPE_FHS || t == BR_TYPE_DM1 || t == BR_TYPE_DM3 || t == BR_TYPE_DM5; }
static int payload_header_bits(uint8_t t) { return (t == BR_TYPE_DM1 || t == BR_TYPE_DH1) ? 8 : 16; }

br_status_t br_packet_encode(const br_pkt_t* p, const br_link_ctx_t* ctx, uint8_t* out, size_t out_cap, size_t* nbits)
{
    const int max = br_type_max_len(p->hdr.type);
    if (max < 0) return BR_ERR_TYPE;
    if (out_cap < BR_PACKET_MAX_BYTES) return BR_ERR_TOO_SHORT;
    memset(out, 0, out_cap);

    size_t pos = br_access_code_bits(ctx->lap, 1, out);
    br_whiten_t w;
    br_whiten_init(&w, ctx->clk6);
    br_whiten_t* wp = ctx->no_whitening ? NULL : &w;
    br_header_encode(&p->hdr, ctx->uap, wp, out, pos);
    pos += BR_HEADER_AIR_BITS;

    if (max == 0) {
        *nbits = pos;
        return BR_OK;
    }

    /* Build payload (header + body + CRC) in raw form, whiten, then FEC or copy. */
    uint8_t raw[BR_PACKET_MAX_BYTES];
    memset(raw, 0, sizeof raw);
    size_t n = 0;
    if (p->hdr.type == BR_TYPE_FHS) {
        memcpy(raw, p->payload, BR_FHS_BYTES);
        n = BR_FHS_BYTES * 8;
    } else {
        if (p->len > (unsigned)max) return BR_ERR_LENGTH;
        const int hb = payload_header_bits(p->hdr.type);
        const uint32_t ph = (p->llid & 3u) | ((p->pflow & 1u) << 2) | ((uint32_t)p->len << 3);
        br_bits_write(raw, 0, ph, (unsigned)hb);
        n = (size_t)hb;
        for (unsigned i = 0; i < p->len; ++i) br_bits_write(raw, n + 8 * i, p->payload[i], 8);
        n += (size_t)p->len * 8;
    }
    br_bits_write(raw, n, br_crc16(raw, 0, n, ctx->uap), 16);
    n += 16;
    if (ctx->e0 && p->hdr.type != BR_TYPE_FHS) br_e0_apply(ctx->e0, raw, 0, n);
    if (wp) br_whiten_apply(wp, raw, 0, n);

    if (type_has_fec23(p->hdr.type)) pos += br_fec23_encode(raw, 0, n, out, pos);
    else {
        br_bits_copy(out, pos, raw, 0, n);
        pos += n;
    }
    *nbits = pos;
    return BR_OK;
}

/* Gets `n` payload bits (after FEC decode if needed) starting at air position `pos` into raw. */
static br_status_t take_payload(const uint8_t* in, size_t nbits, size_t pos, int fec, size_t n, uint8_t* raw)
{
    if (fec) {
        if (pos + br_fec23_coded_len(n) > nbits) return BR_ERR_TOO_SHORT;
        if (br_fec23_decode(in, pos, n, raw, 0, NULL) != 0) return BR_ERR_FEC;
    } else {
        if (pos + n > nbits) return BR_ERR_TOO_SHORT;
        br_bits_copy(raw, 0, in, pos, n);
    }
    return BR_OK;
}

br_status_t br_packet_decode(const uint8_t* in, size_t nbits, const br_link_ctx_t* ctx, br_pkt_t* p)
{
    memset(p, 0, sizeof *p);
    if (nbits < 72 + BR_HEADER_AIR_BITS) return BR_ERR_TOO_SHORT;
    const uint64_t sw = br_bits_read(in, 4, 64);
    if (br_popcount64(sw ^ br_sync_word(ctx->lap)) > ctx->sync_tolerance) return BR_ERR_SYNC;

    br_whiten_t w;
    br_whiten_init(&w, ctx->clk6);
    br_whiten_t* wp = ctx->no_whitening ? NULL : &w;
    size_t pos = 72;
    if (br_header_decode(in, pos, ctx->uap, wp, &p->hdr) != 0) return BR_ERR_HEC;
    pos += BR_HEADER_AIR_BITS;

    const uint8_t t = p->hdr.type;
    const int max = br_type_max_len(t);
    if (max < 0) return BR_ERR_TYPE;
    if (max == 0) return BR_OK;
    const int fec = type_has_fec23(t);
    uint8_t raw[BR_PACKET_MAX_BYTES];
    memset(raw, 0, sizeof raw);

    size_t n;
    if (t == BR_TYPE_FHS) {
        n = BR_FHS_BYTES * 8;
        p->len = BR_FHS_BYTES;
    } else {
        /* Read the payload header first (with a copy of the whitening state) to learn the length. */
        const int hb = payload_header_bits(t);
        br_status_t st = take_payload(in, nbits, pos, fec, (size_t)hb, raw);
        if (st != BR_OK) return st;
        if (wp) {
            br_whiten_t wc = w;
            br_whiten_apply(&wc, raw, 0, (size_t)hb);
        }
        if (ctx->e0) {
            br_e0_t ec = *ctx->e0;
            br_e0_apply(&ec, raw, 0, (size_t)hb);
        }
        const uint32_t ph = (uint32_t)br_bits_read(raw, 0, (unsigned)hb);
        p->llid = ph & 3u;
        p->pflow = (ph >> 2) & 1u;
        p->len = (uint16_t)((ph >> 3) & (hb == 8 ? 0x1Fu : 0x3FFu));
        if (p->len > (unsigned)max) return BR_ERR_LENGTH;
        n = (size_t)hb + (size_t)p->len * 8;
    }
    memset(raw, 0, sizeof raw);
    br_status_t st = take_payload(in, nbits, pos, fec, n + 16, raw);
    if (st != BR_OK) return st;
    if (wp) br_whiten_apply(wp, raw, 0, n + 16);
    if (ctx->e0 && t != BR_TYPE_FHS) br_e0_apply(ctx->e0, raw, 0, n + 16);
    if ((uint16_t)br_bits_read(raw, n, 16) != br_crc16(raw, 0, n, ctx->uap)) return BR_ERR_CRC;
    if (t == BR_TYPE_FHS) memcpy(p->payload, raw, BR_FHS_BYTES);
    else {
        const size_t hb = (size_t)payload_header_bits(t);
        for (unsigned i = 0; i < p->len; ++i) p->payload[i] = (uint8_t)br_bits_read(raw, hb + 8 * i, 8);
    }
    return BR_OK;
}

void br_fhs_pack(const br_fhs_t* f, uint8_t out[BR_FHS_BYTES])
{
    memset(out, 0, BR_FHS_BYTES);
    size_t pos = 0;
#define PUT(v, n) (br_bits_write(out, pos, (uint64_t)(v), (n)), pos += (n))
    PUT(f->parity, 34);
    PUT(f->lap, 24);
    PUT(f->eir, 1);
    PUT(0, 1); /* reserved */
    PUT(f->sr, 2);
    PUT(2, 2); /* SP = 0b10, Core v5.4 Vol 2 Part B §6.5.1.4, Table 6.3. */
    PUT(f->uap, 8);
    PUT(f->nap, 16);
    PUT(f->cod, 24);
    PUT(f->lt_addr, 3);
    PUT(f->clk27_2, 26);
    PUT(f->page_scan_mode, 3);
#undef PUT
}

void br_fhs_unpack(const uint8_t in[BR_FHS_BYTES], br_fhs_t* f)
{
    size_t pos = 0;
#define GET(n) (pos += (n), br_bits_read(in, pos - (n), (n)))
    f->parity = GET(34);
    f->lap = (uint32_t)GET(24);
    f->eir = (uint8_t)GET(1);
    (void)GET(1);
    f->sr = (uint8_t)GET(2);
    (void)GET(2);
    f->uap = (uint8_t)GET(8);
    f->nap = (uint16_t)GET(16);
    f->cod = (uint32_t)GET(24);
    f->lt_addr = (uint8_t)GET(3);
    f->clk27_2 = (uint32_t)GET(26);
    f->page_scan_mode = (uint8_t)GET(3);
#undef GET
}

uint64_t br_fhs_parity_for_lap(uint32_t lap) { return br_sync_word(lap) & ((1ull << 34) - 1); }
