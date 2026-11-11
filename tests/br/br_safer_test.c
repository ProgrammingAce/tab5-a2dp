/* SAFER+ (Ar / A'r) and E1, E21, E22, E3 against Core 5.4 Vol 2 Part G §10. */
#include <string.h>

#include "br/br_safer.h"
#include "test.h"
#include "vectors/spec_vectors.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

void run_safer_tests(void)
{
    int final_ok = 0;
    for (unsigned t = 0; t < COUNT(kSpecSafer); ++t) {
        const spec_safer_t* s = &kSpecSafer[t];
        for (unsigned p = 0; p < s->npass; ++p) {
            const int prime = (s->kind == SPEC_E1 || s->kind == SPEC_E3) ? (int)p : 1;
            uint8_t keys[17][16], out[16], rounds[9][16];
            br_safer_keys(s->pass_key[p], keys);
            CHECK(memcmp(keys, s->subkeys[p], sizeof keys) == 0);
            br_safer_encrypt(s->pass_key[p], s->pass_in[p], prime, out, rounds);
            for (int r = 0; r < 8; ++r) CHECK(memcmp(rounds[r], s->rounds[p][r], 16) == 0);
            if (prime) CHECK(memcmp(rounds[8], s->added, 16) == 0);
        }
        uint8_t out[16];
        memset(out, 0, sizeof out);
        switch (s->kind) {
        case SPEC_E1: br_e1(s->key, s->rand, s->addr, out, out + 4); break;
        case SPEC_E21: br_e21(s->rand, s->addr, out); break;
        case SPEC_E22: br_e22(s->rand, s->pin, s->pin_len, s->addr, out); break;
        case SPEC_E3: br_e3(s->key, s->rand, s->cof, out); break;
        }
        const int ok = memcmp(out, s->out, 16) == 0;
        CHECK(ok);
        final_ok += ok;
    }
    CHECK(final_ok == 31);
}
