/* Tests against the Bluetooth Core 5.4 Vol 2 Part G sample data (tests/br/vectors/spec_vectors.h). */
#include <string.h>

#include "br/br.h"
#include "test.h"
#include "vectors/spec_vectors.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static int hop_for(const spec_hop_t* e)
{
    switch (e->mode) {
    case SPEC_HOP_PAGESCAN: return br_hop_page_scan(e->addr, e->clk);
    case SPEC_HOP_PAGE: return br_hop_page(e->addr, e->clk, e->koffset);
    case SPEC_HOP_PERIPH_RESP: return br_hop_slave_page_response(e->addr, e->frozen, e->clk, e->n);
    case SPEC_HOP_CENTRAL_RESP: return br_hop_master_page_response(e->addr, e->frozen, e->koffset, e->clk, e->n);
    case SPEC_HOP_CONN: return br_hop_connection(e->addr, e->clk);
    }
    return -1;
}

static void spec_hops(void)
{
    int per_mode[5] = {0, 0, 0, 0, 0}, bad_mode[5] = {0, 0, 0, 0, 0};
    for (unsigned i = 0; i < COUNT(kSpecHop); ++i) {
        const int ok = hop_for(&kSpecHop[i]) == kSpecHop[i].chan;
        ++per_mode[kSpecHop[i].mode];
        if (!ok) ++bad_mode[kSpecHop[i].mode];
        CHECK(ok);
    }
    for (int m = 0; m < 5; ++m) CHECK(per_mode[m] > 0 && bad_mode[m] == 0); /* every state is covered */
}

static void spec_access_codes(void)
{
    for (unsigned i = 0; i < COUNT(kSpecAccessCode); ++i) {
        const spec_ac_t* a = &kSpecAccessCode[i];
        CHECK(br_sync_word(a->lap) == a->sync);
        uint8_t buf[9];
        memset(buf, 0, sizeof buf);
        br_access_code_bits(a->lap, 1, buf);
        CHECK(br_bits_read(buf, 0, 4) == a->preamble);
        CHECK(br_bits_read(buf, 68, 4) == a->trailer);
    }
}

static void spec_hec(void)
{
    for (unsigned i = 0; i < COUNT(kSpecHec); ++i) {
        const spec_hec_t* h = &kSpecHec[i];
        CHECK(br_hec(h->data, h->uap) == h->hec);
        /* Full 54-bit header without whitening: decode the 1/3 FEC and compare with the 18 header bits. */
        br_header_t hd;
        br_header_unpack10(h->data, &hd);
        uint8_t air[8], raw[3];
        memset(air, 0, sizeof air);
        memset(raw, 0, sizeof raw);
        br_header_encode(&hd, h->uap, NULL, air, 0);
        CHECK(br_fec13_decode(air, 0, 18, raw, 0) == 0);
        CHECK(br_bits_read(raw, 0, 18) == h->header18);
    }
}

static void spec_crc(void)
{
    uint8_t bits[16];
    memset(bits, 0, sizeof bits);
    for (unsigned i = 0; i < sizeof kSpecCrcData; ++i) br_bits_write(bits, 8 * i, kSpecCrcData[i], 8);
    CHECK(br_crc16(bits, 0, 8 * sizeof kSpecCrcData, kSpecCrcUap) == kSpecCrc);
}

static void spec_packets(void)
{
    static uint8_t air[BR_PACKET_MAX_BYTES];
    for (unsigned i = 0; i < COUNT(kSpecPacket); ++i) {
        const spec_pkt_t* s = &kSpecPacket[i];
        br_pkt_t p;
        memset(&p, 0, sizeof p);
        p.hdr.type = s->type;
        p.hdr.lt_addr = s->lt_addr;
        p.hdr.flow = s->flow;
        p.hdr.arqn = s->arqn;
        p.hdr.seqn = s->seqn;
        p.llid = s->llid;
        p.pflow = s->pflow;
        p.len = s->len;
        memcpy(p.payload, s->data, s->len);
        const br_link_ctx_t ctx = {.lap = 0x9E8B33u, .uap = s->uap, .no_whitening = 1};
        size_t nbits = 0;
        CHECK(br_packet_encode(&p, &ctx, air, sizeof air, &nbits) == BR_OK);
        int hdr_ok = 1, pay_ok = 1;
        for (unsigned b = 0; b < s->hdr_nbits; ++b) hdr_ok &= br_bit_get(air, 72 + b) == br_bit_get(s->hdr_bits, b);
        for (unsigned b = 0; b < s->pay_nbits; ++b) pay_ok &= br_bit_get(air, 72 + 54 + b) == br_bit_get(s->pay_bits, b);
        CHECK(hdr_ok);
        CHECK(pay_ok);
        /* DM1's sample includes the 6 zero padding bits that complete the last FEC block. */
        CHECK(nbits == 72u + 54u + s->pay_nbits);
        br_pkt_t q;
        CHECK(br_packet_decode(air, nbits, &ctx, &q) == BR_OK);
        CHECK(q.len == s->len && memcmp(q.payload, s->data, s->len) == 0);
    }
}

static void spec_whiten(void)
{
    br_whiten_t w;
    br_whiten_init(&w, 0x3F);
    int ok = 1;
    for (unsigned i = 0; i < 127; ++i) ok &= br_whiten_next(&w) == br_bit_get(kSpecWhiten, i);
    CHECK(ok);
}

static void spec_fec(void)
{
    for (unsigned i = 0; i < COUNT(kSpecFecData); ++i) CHECK(br_fec23_block(kSpecFecData[i]) == kSpecFecCodeword[i]);
}

void run_spec_tests(void)
{
    spec_hops();
    spec_access_codes();
    spec_hec();
    spec_crc();
    spec_packets();
    spec_whiten();
    spec_fec();
}
