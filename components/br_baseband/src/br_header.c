#include "br/br_header.h"

#include "br/br_bits.h"
#include "br/br_crc.h"
#include "br/br_fec.h"

uint16_t br_header_pack10(const br_header_t* h)
{
    return (uint16_t)((h->lt_addr & 7u) | ((h->type & 0xFu) << 3) | ((h->flow & 1u) << 7) | ((h->arqn & 1u) << 8) |
                      ((h->seqn & 1u) << 9));
}

void br_header_unpack10(uint16_t v, br_header_t* h)
{
    h->lt_addr = v & 7u;
    h->type = (v >> 3) & 0xFu;
    h->flow = (v >> 7) & 1u;
    h->arqn = (v >> 8) & 1u;
    h->seqn = (v >> 9) & 1u;
}

void br_header_encode(const br_header_t* h, uint8_t uap, br_whiten_t* w, uint8_t* buf, size_t pos)
{
    uint8_t raw[3] = {0, 0, 0};
    const uint16_t v = br_header_pack10(h);
    br_bits_write(raw, 0, v, 10);
    br_bits_write(raw, 10, br_hec(v, uap), 8);
    if (w) br_whiten_apply(w, raw, 0, 18);
    br_fec13_encode(raw, 0, 18, buf, pos);
}

int br_header_decode(const uint8_t* buf, size_t pos, uint8_t uap, br_whiten_t* w, br_header_t* h)
{
    uint8_t raw[3] = {0, 0, 0};
    br_fec13_decode(buf, pos, 18, raw, 0);
    if (w) br_whiten_apply(w, raw, 0, 18);
    const uint16_t v = (uint16_t)br_bits_read(raw, 0, 10);
    const uint8_t hec = (uint8_t)br_bits_read(raw, 10, 8);
    br_header_unpack10(v, h);
    return hec == br_hec(v, uap) ? 0 : -1;
}
