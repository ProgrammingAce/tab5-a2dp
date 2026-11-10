#include "br/br_page_setup.h"

#include "br/br_access_code.h"
#include "br/br_bits.h"
#include "br/br_hop.h"

/* BLE CRC (x^24+x^10+x^9+x^6+x^4+x^3+x+1) run backwards: the preset that yields `target` (24 bits in
 * transmission order) after `bits` (port of tools/br_lab/g3_dtm_tx.py crc_init_for). */
static uint32_t crc_init_for(const uint8_t* bits, int n, const uint8_t target[24])
{
    uint8_t st[24];
    for (int i = 0; i < 24; ++i) st[i] = target[23 - i];
    for (int k = n - 1; k >= 0; --k) {
        const uint8_t fb = st[0];
        uint8_t prev[24];
        for (int j = 0; j < 23; ++j) {
            const int t = j + 1;
            const int tap = t == 1 || t == 3 || t == 4 || t == 6 || t == 9 || t == 10;
            prev[j] = (uint8_t)(st[j + 1] ^ (tap ? fb : 0));
        }
        prev[23] = (uint8_t)(bits[k] ^ fb);
        for (int j = 0; j < 24; ++j) st[j] = prev[j];
    }
    uint32_t v = 0;
    for (int i = 0; i < 24; ++i) v |= (uint32_t)st[i] << i;
    return v;
}

void br_page_dtm_id(uint32_t lap, uint32_t* aa, uint32_t* tail, uint32_t* crc_init)
{
    uint8_t b[16] = {0};
    br_access_code_bits(lap, 0, b); /* 68 bits: preamble + sync */
    *aa = (uint32_t)br_bits_read(b, 4, 32);
    *tail = (uint32_t)br_bits_read(b, 36, 32);
    uint8_t hdr[16], target[24];
    for (int i = 0; i < 16; ++i) hdr[i] = (uint8_t)((*tail >> i) & 1u); /* the tail's first 2 bytes, LSB first */
    for (int i = 0; i < 16; ++i) target[i] = (uint8_t)br_bit_get(b, (size_t)(52 + i));
    for (int i = 16; i < 24; ++i) target[i] = 0;
    *crc_init = crc_init_for(hdr, 16, target);
}

void br_page_table(uint32_t lap, uint8_t uap, uint8_t tx[32], uint8_t rx[32])
{
    const uint32_t a28 = br_hop_address(uap, lap);
    for (uint32_t x = 0; x < 32; ++x) {
        tx[x] = (uint8_t)br_hop_page_scan(a28, x << 12);
        rx[x] = (uint8_t)br_hop_slave_page_response(a28, x << 12, (x << 12) | 2u, 0);
    }
}

void br_inquiry_table(uint8_t tx[32], uint8_t rx[32])
{
    for (uint32_t x = 0; x < 32; ++x) {
        tx[x] = (uint8_t)br_hop_inquiry_scan(x << 12);
        rx[x] = (uint8_t)br_hop_inquiry_response(x << 12, 0);
    }
}
