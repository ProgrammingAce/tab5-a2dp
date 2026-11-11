/* Tests for packet header, packet types and hop selection. */
#include <string.h>

#include "br/br.h"
#include "test.h"
#include "vectors/oracle_vectors.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static const br_link_ctx_t kCtx = {.lap = 0x2F0519u, .uap = 0x6Bu, .clk6 = 0x2Du, .no_whitening = 0, .sync_tolerance = 0};

void run_header_tests(void)
{
    for (unsigned v = 0; v < 1024; v += 7) {
        br_header_t h, back;
        br_header_unpack10((uint16_t)v, &h);
        CHECK(br_header_pack10(&h) == v);
        uint8_t buf[8];
        memset(buf, 0, sizeof buf);
        br_whiten_t w1, w2;
        br_whiten_init(&w1, (uint8_t)(v & 0x3F));
        br_whiten_init(&w2, (uint8_t)(v & 0x3F));
        br_header_encode(&h, 0x47, &w1, buf, 3);
        CHECK(br_header_decode(buf, 3, 0x47, &w2, &back) == 0);
        CHECK(br_header_pack10(&back) == v);
        CHECK(w1.reg == w2.reg); /* both advanced 18 bits */
        /* Wrong UAP -> HEC mismatch. */
        br_whiten_init(&w2, (uint8_t)(v & 0x3F));
        CHECK(br_header_decode(buf, 3, 0x48, &w2, &back) == -1);
    }
}

static void fill(br_pkt_t* p, uint8_t type, uint16_t len, uint8_t seed)
{
    memset(p, 0, sizeof *p);
    p->hdr.lt_addr = 1;
    p->hdr.type = type;
    p->hdr.seqn = seed & 1;
    p->hdr.arqn = (seed >> 1) & 1;
    p->hdr.flow = 1;
    p->llid = BR_LLID_L2CAP_START;
    p->pflow = 1;
    p->len = len;
    for (unsigned i = 0; i < len; ++i) p->payload[i] = (uint8_t)(seed * 31u + i * 7u);
}

static int same(const br_pkt_t* a, const br_pkt_t* b)
{
    if (br_header_pack10(&a->hdr) != br_header_pack10(&b->hdr)) return 0;
    if (a->hdr.type == BR_TYPE_NULL || a->hdr.type == BR_TYPE_POLL) return 1;
    if (a->len != b->len || memcmp(a->payload, b->payload, a->len)) return 0;
    if (a->hdr.type == BR_TYPE_FHS) return 1;
    return a->llid == b->llid && a->pflow == b->pflow;
}

void run_packet_tests(void)
{
    static const uint8_t types[] = {BR_TYPE_NULL, BR_TYPE_POLL, BR_TYPE_FHS, BR_TYPE_DM1, BR_TYPE_DH1,
                                    BR_TYPE_DM3, BR_TYPE_DH3, BR_TYPE_DM5, BR_TYPE_DH5};
    static uint8_t air[BR_PACKET_MAX_BYTES];
    for (unsigned t = 0; t < COUNT(types); ++t) {
        const int max = br_type_max_len(types[t]);
        const uint16_t lens[3] = {0, 1, (uint16_t)(max > 0 ? max : 0)};
        for (unsigned k = 0; k < 3; ++k) {
            br_pkt_t p, q;
            fill(&p, types[t], types[t] == BR_TYPE_FHS ? BR_FHS_BYTES : (max > 0 ? lens[k] : 0), (uint8_t)(t * 3 + k));
            size_t nbits = 0;
            CHECK(br_packet_encode(&p, &kCtx, air, sizeof air, &nbits) == BR_OK);
            CHECK(nbits <= BR_PACKET_MAX_BITS);
            CHECK(br_packet_decode(air, nbits, &kCtx, &q) == BR_OK);
            CHECK(same(&p, &q));
            if (max > 0 && p.len >= 4) {
                /* Flip one bit near the end of the payload: DMx/FHS correct it, DHx fail the CRC.
                 * (Empty payloads are skipped: the flip can land in the length field instead.) */
                br_bit_put(air, nbits - 20, !br_bit_get(air, nbits - 20));
                const br_status_t st = br_packet_decode(air, nbits, &kCtx, &q);
                const int fec = types[t] == BR_TYPE_FHS || types[t] == BR_TYPE_DM1 || types[t] == BR_TYPE_DM3 ||
                                types[t] == BR_TYPE_DM5;
                CHECK(fec ? st == BR_OK : st == BR_ERR_CRC);
                CHECK(br_packet_decode(air, nbits - 30, &kCtx, &q) == BR_ERR_TOO_SHORT);
            }
        }
    }
    /* Air sizes for known types: POLL = 126 bits; DH1 max = 126 + 8 + 216 + 16. */
    {
        br_pkt_t p;
        size_t nbits;
        fill(&p, BR_TYPE_POLL, 0, 1);
        br_packet_encode(&p, &kCtx, air, sizeof air, &nbits);
        CHECK(nbits == 126);
        fill(&p, BR_TYPE_DH1, 27, 1);
        br_packet_encode(&p, &kCtx, air, sizeof air, &nbits);
        CHECK(nbits == 126 + 8 + 27 * 8 + 16);
        fill(&p, BR_TYPE_FHS, BR_FHS_BYTES, 1);
        br_packet_encode(&p, &kCtx, air, sizeof air, &nbits);
        CHECK(nbits == 126 + 240);
        fill(&p, BR_TYPE_DH1, 28, 1);
        CHECK(br_packet_encode(&p, &kCtx, air, sizeof air, &nbits) == BR_ERR_LENGTH);
    }
    /* Sync word tolerance. */
    {
        br_pkt_t p, q;
        size_t nbits;
        fill(&p, BR_TYPE_NULL, 0, 2);
        br_packet_encode(&p, &kCtx, air, sizeof air, &nbits);
        br_bit_put(air, 10, !br_bit_get(air, 10));
        CHECK(br_packet_decode(air, nbits, &kCtx, &q) == BR_ERR_SYNC);
        br_link_ctx_t tol = kCtx;
        tol.sync_tolerance = 2;
        CHECK(br_packet_decode(air, nbits, &tol, &q) == BR_OK);
    }
    /* FHS field round trip. */
    {
        br_fhs_t f = {.parity = br_fhs_parity_for_lap(0x123456), .lap = 0x123456, .eir = 1, .sr = 2, .uap = 0x9A,
                      .nap = 0xBEEF, .cod = 0x240404, .lt_addr = 5, .clk27_2 = 0x2ABCDEF, .page_scan_mode = 3};
        br_fhs_t g;
        uint8_t raw[BR_FHS_BYTES];
        br_fhs_pack(&f, raw);
        /* Core v5.4 Vol 2 Part B Table 6.3: SP is fixed 0b10, not reserved zeros.
         * Check the wire field: an encode/decode round trip alone cannot catch this. */
        CHECK(br_bits_read(raw, 62, 2) == 2);
        br_fhs_unpack(raw, &g);
        CHECK(g.parity == f.parity && g.lap == f.lap && g.eir == 1 && g.sr == 2 && g.uap == 0x9A && g.nap == 0xBEEF);
        CHECK(g.cod == 0x240404 && g.lt_addr == 5 && g.clk27_2 == 0x2ABCDEF && g.page_scan_mode == 3);
    }
}

/* E0 payload encryption round trip (ctx.e0): ciphertext differs, decrypts with the same generator state, and a
 * wrong clock fails the CRC. Keystream itself is checked against Part G sample data in br_e0_test.c. */
void run_packet_encryption_tests(void)
{
    static const uint8_t kc[16] = {0x21, 0x87, 0xF0, 0x4A, 0xBA, 0x90, 0x31, 0xD0,
                                   0x78, 0x0D, 0x4C, 0x53, 0xE0, 0x15, 0x3A, 0x63};
    static const uint8_t addr[6] = {0x1B, 0xCA, 0x22, 0x00, 0x00, 0x00};
    static const uint8_t types[] = {BR_TYPE_DM1, BR_TYPE_DH1, BR_TYPE_DM3, BR_TYPE_DH5};
    static uint8_t air_plain[BR_PACKET_MAX_BYTES], air_enc[BR_PACKET_MAX_BYTES];
    static br_pkt_t p, q;
    for (unsigned t = 0; t < sizeof types; ++t) {
        const int max = br_type_max_len(types[t]);
        for (int len = 0; len <= max; len += (max > 40 ? 37 : 5)) {
            const uint32_t clk = 0x0001234u + 4u * (uint32_t)len;
            fill(&p, types[t], (uint16_t)len, (uint8_t)(len + t));
            br_link_ctx_t ctx = {.lap = 0x22CA1B, .uap = 0x00, .clk6 = (uint8_t)((clk >> 1) & 63u)};
            size_t nb_plain = 0, nb_enc = 0;
            CHECK(br_packet_encode(&p, &ctx, air_plain, sizeof air_plain, &nb_plain) == BR_OK);
            br_e0_t e;
            br_e0_init(&e, kc, addr, clk);
            ctx.e0 = &e;
            CHECK(br_packet_encode(&p, &ctx, air_enc, sizeof air_enc, &nb_enc) == BR_OK);
            CHECK(nb_plain == nb_enc);
            CHECK(memcmp(air_plain, air_enc, 72 / 8) == 0);           /* access code untouched */
            if (len > 0) CHECK(memcmp(air_plain, air_enc, sizeof air_plain) != 0);
            br_e0_init(&e, kc, addr, clk);
            CHECK(br_packet_decode(air_enc, nb_enc, &ctx, &q) == BR_OK);
            CHECK(q.len == p.len && memcmp(q.payload, p.payload, p.len) == 0);
            br_e0_init(&e, kc, addr, clk + 4u);                          /* wrong slot clock -> CRC error */
            CHECK(br_packet_decode(air_enc, nb_enc, &ctx, &q) != BR_OK);
            ctx.e0 = NULL;
            CHECK(br_packet_decode(air_enc, nb_enc, &ctx, &q) != BR_OK);   /* unencrypted decode fails */
        }
    }
}

void run_hop_tests(void)
{
    /* T4.2: central/peripheral response kernels must agree after freezing the same
     * page X (Core v5.4 Vol 2 Part B §2.6.4.3–4). Cover both trains and X wrap. */
    for (unsigned i = 0; i < 32; ++i) {
        const uint32_t addr = br_hop_address(0xBC, 0x16CDE0);
        const int offset = i < 16 ? 24 : 8;
        const uint32_t frozen = ((i & 15u) >> 1) << 2 | (i & 1u) | 2u;
        const uint32_t x = br_hop_train_x(frozen, offset);
        CHECK(x == (i < 16 ? (24 + i) & 31u : i - 8));
        for (int n = 0; n < 33; ++n)
            for (uint32_t y1 = 0; y1 < 2; ++y1)
                CHECK(br_hop_master_page_response(addr, frozen, offset, y1 << 1, n) ==
                      br_hop_slave_page_response(addr, x << 12, y1 << 1, n));
    }
    for (unsigned i = 0; i < COUNT(kOracleHopAddr); ++i)
        CHECK(br_hop_connection(kOracleHopAddr[i], kOracleHopClk[i]) == kOracleHopChan[i]);

    /* Basic properties of the page/inquiry functions (spec sample data still pending). */
    int seen[79];
    memset(seen, 0, sizeof seen);
    for (uint32_t clk = 0; clk < (1u << 17); clk += 2) {
        const int ch = br_hop_inquiry(clk, 24);
        CHECK(ch >= 0 && ch < 79);
        if (ch >= 0 && ch < 79) seen[ch] = 1;
    }
    int distinct = 0;
    for (int i = 0; i < 79; ++i) distinct += seen[i];
    CHECK(distinct == 32); /* the inquiry hopping sequence uses 32 dedicated frequencies */

    /* Connection hopping visits all 79 channels. */
    memset(seen, 0, sizeof seen);
    for (uint32_t clk = 0; clk < 79u * 64u * 4u; clk += 2) seen[br_hop_connection(0x0A12345u, clk)] = 1;
    distinct = 0;
    for (int i = 0; i < 79; ++i) distinct += seen[i];
    CHECK(distinct == 79);
}
