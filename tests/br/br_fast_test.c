/* br_fast (C6 slot-time fast path) against the spec-verified reference: br_e0 and br_packet_encode. */
#include <stdlib.h>
#include <string.h>

#include "br/br_bits.h"
#include "br/br_e0.h"
#include "br/br_fast.h"
#include "br/br_packet.h"
#include "test.h"
#include "vectors/spec_vectors.h"

static uint32_t s_rng = 0x2468ACE1u;
static uint32_t rnd(void)
{
    s_rng ^= s_rng << 13;
    s_rng ^= s_rng >> 17;
    s_rng ^= s_rng << 5;
    return s_rng;
}
static void rnd_bytes(uint8_t* b, size_t n)
{
    for (size_t i = 0; i < n; ++i) b[i] = (uint8_t)rnd();
}

static int keystream_matches(const uint8_t k[16], const uint8_t a[6], uint32_t clk, size_t nbits)
{
    uint8_t fast[64];
    br_e0_keystream(k, a, clk, fast, nbits);
    br_e0_t e;
    br_e0_init(&e, k, a, clk);
    for (size_t i = 0; i < nbits; ++i)
        if (br_e0_bit(&e) != br_bit_get(fast, i)) return 0;
    for (size_t i = nbits; i < (nbits + 7) / 8 * 8; ++i)
        if (br_bit_get(fast, i)) return 0; /* unused high bits cleared */
    return 1;
}

void run_fast_tests(void)
{
    /* E0: the four spec sets, then random keys/addresses/clocks/lengths */
    for (unsigned s = 0; s < sizeof kSpecE0 / sizeof kSpecE0[0]; ++s) {
        uint8_t ks[16];
        br_e0_keystream(kSpecE0[s].k, kSpecE0[s].addr, kSpecE0[s].clk, ks, 125);
        int ok = 1;
        for (unsigned b = 0; b < 125; ++b) ok &= br_bit_get(ks, b) == br_bit_get(kSpecE0[s].ks, b);
        CHECK(ok);
    }
    for (int t = 0; t < 400; ++t) {
        uint8_t k[16], a[6];
        rnd_bytes(k, 16);
        rnd_bytes(a, 6);
        CHECK(keystream_matches(k, a, rnd() & 0x0FFFFFFFu, 1 + rnd() % 400));
    }

    /* header whitening */
    for (unsigned c = 0; c < 64; ++c) {
        br_whiten_t w;
        br_whiten_init(&w, (uint8_t)c);
        uint32_t v = 0;
        for (unsigned i = 0; i < 18; ++i) v |= (uint32_t)br_whiten_next(&w) << i;
        CHECK(br_fast_header_whitening((uint8_t)c) == v);
    }

    /* whole packets: header table + plain payload + slot mask (+E0) + FEC table == br_packet_encode */
    static uint16_t tab[1024];
    br_fast_fec23_table(tab);
    for (int t = 0; t < 3000; ++t) {
        const uint8_t type = (rnd() & 1u) ? BR_TYPE_DM1 : BR_TYPE_DH1;
        const unsigned maxlen = type == BR_TYPE_DM1 ? 17u : 27u;
        br_pkt_t p;
        memset(&p, 0, sizeof p);
        p.hdr.type = type;
        p.hdr.lt_addr = 1 + rnd() % 7;
        p.hdr.flow = rnd() & 1u;
        p.hdr.arqn = rnd() & 1u;
        p.hdr.seqn = rnd() & 1u;
        p.llid = 1 + rnd() % 3;
        p.pflow = rnd() & 1u;
        p.len = (uint16_t)(rnd() % (maxlen + 1));
        rnd_bytes(p.payload, p.len);
        const uint32_t clk = (rnd() & 0x0FFFFFFCu) | ((rnd() & 1u) << 1); /* central (..00) or peripheral (..10) slot */
        const uint8_t uap = (uint8_t)rnd();
        const int enc = (int)(rnd() & 1u);
        uint8_t k[16], a[6];
        rnd_bytes(k, 16);
        rnd_bytes(a, 6);

        br_e0_t e;
        if (enc) br_e0_init(&e, k, a, clk);
        const br_link_ctx_t ctx = {.lap = 0x22CA1B, .uap = uap, .clk6 = (uint8_t)((clk >> 1) & 63u), .e0 = enc ? &e : NULL};
        static uint8_t ref[BR_PACKET_MAX_BYTES];
        size_t nref = 0;
        CHECK(br_packet_encode(&p, &ctx, ref, sizeof ref, &nref) == BR_OK);

        CHECK(br_fast_header(&p.hdr, uap, ctx.clk6) == br_bits_read(ref, 72, 54));

        uint8_t plain[BR_FAST_PAYLOAD_BYTES], mask[BR_FAST_PAYLOAD_BYTES], out[48];
        const size_t nplain = br_fast_plain(p.llid, p.pflow, p.payload, p.len, uap, plain);
        CHECK(nplain == 8u * (3u + p.len));
        br_fast_mask(clk, enc ? k : NULL, a, mask);
        memset(out, 0, sizeof out);
        const size_t pos = 5; /* arbitrary bit offset, as in the C6 body (58) */
        const size_t nair = br_fast_payload(type, plain, nplain, mask, tab, out, pos);
        CHECK(nair == nref - 126);
        int same = 1;
        for (size_t i = 0; i < nair; ++i) same &= br_bit_get(out, pos + i) == br_bit_get(ref, 126 + i);
        for (size_t i = 0; i < pos; ++i) same &= br_bit_get(out, i) == 0;
        CHECK(same);
    }
}
