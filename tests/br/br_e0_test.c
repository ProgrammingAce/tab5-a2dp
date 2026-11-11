/* E0 stream cipher and key length reduction against Core 5.4 Vol 2 Part G §1.1. */
#include <string.h>

#include "br/br_bits.h"
#include "br/br_e0.h"
#include "test.h"
#include "vectors/spec_vectors.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

void run_e0_tests(void)
{
    for (unsigned i = 0; i < COUNT(kSpecE0KeyRed); ++i) {
        uint8_t ks[16];
        br_e0_key_reduce(kSpecE0KeyRed[i].k_enc, kSpecE0KeyRed[i].len, ks);
        CHECK(memcmp(ks, kSpecE0KeyRed[i].k_session, 16) == 0);
    }
    for (unsigned s = 0; s < COUNT(kSpecE0); ++s) {
        const spec_e0_t* v = &kSpecE0[s];
        br_e0_t e;
        br_e0_init(&e, v->k, v->addr, v->clk);
        for (int i = 0; i < 4; ++i) CHECK(e.r[i] == v->reload[i]);
        int ok = 1;
        for (unsigned b = 0; b < 125; ++b) ok &= br_e0_bit(&e) == br_bit_get(v->ks, b);
        CHECK(ok);
    }
    /* Encrypt then decrypt with a fresh generator gives the plaintext back. */
    uint8_t buf[40], orig[40];
    for (unsigned i = 0; i < sizeof buf; ++i) orig[i] = buf[i] = (uint8_t)(i * 37u + 5u);
    br_e0_t a, b;
    br_e0_init(&a, kSpecE0[3].k, kSpecE0[3].addr, 0x1234566u);
    br_e0_apply(&a, buf, 3, 300);
    CHECK(memcmp(buf, orig, sizeof buf) != 0);
    br_e0_init(&b, kSpecE0[3].k, kSpecE0[3].addr, 0x1234566u);
    br_e0_apply(&b, buf, 3, 300);
    CHECK(memcmp(buf, orig, sizeof buf) == 0);
}
