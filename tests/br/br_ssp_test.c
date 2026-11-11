/* SSP f1, g, f2, f3 against Core 5.4 Vol 2 Part G §7.2, plus a SHA-256 known-answer check (FIPS 180-4 "abc"). */
#include <string.h>

#include "br/br_ssp.h"
#include "test.h"
#include "vectors/spec_vectors.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

void run_ssp_tests(void)
{
    static const uint8_t abc_digest[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                                           0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
                                           0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    uint8_t d[32];
    br_sha256((const uint8_t*)"abc", 3, d);
    CHECK(memcmp(d, abc_digest, 32) == 0);

    int per_fn[4] = {0, 0, 0, 0};
    for (unsigned i = 0; i < COUNT(kSpecSsp); ++i) {
        const spec_ssp_t* t = &kSpecSsp[i];
        uint8_t out[16];
        switch (t->fn) {
        case SPEC_F1:
            br_ssp_f1(t->u, t->v, t->key_len, t->x, t->z, out);
            CHECK(memcmp(out, t->out, 16) == 0);
            break;
        case SPEC_G: {
            /* The 6 displayed digits always match. The P-192 sample prints the full 32-bit value; the P-256 sample's
             * "output" is already reduced mod 10^6 (0x000240E0 = 147680; the full value is 0x5FDA62E0). */
            const uint32_t g = br_ssp_g(t->u, t->v, t->key_len, t->x, t->y);
            CHECK(g % 1000000u == t->g % 1000000u);
            if (t->key_len == 24) CHECK(g == t->g);
            break;
        }
        case SPEC_F2:
            br_ssp_f2(t->w, t->key_len, t->n1, t->n2, t->key_id, t->a1, t->a2, out);
            CHECK(memcmp(out, t->out, 16) == 0);
            break;
        case SPEC_F3:
            br_ssp_f3(t->w, t->key_len, t->n1, t->n2, t->r, t->iocap, t->a1, t->a2, out);
            CHECK(memcmp(out, t->out, 16) == 0);
            break;
        }
        ++per_fn[t->fn];
    }
    for (int f = 0; f < 4; ++f) CHECK(per_fn[f] > 0);
    /* The spec's worked example: g output 0x52146a1e -> 1377069598 -> displayed 069598. */
    CHECK(0x52146a1eu % 1000000u == 69598u);
}
