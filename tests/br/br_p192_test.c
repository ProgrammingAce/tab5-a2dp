/* br_p192 against Python cryptography vectors (public keys, ECDH shared x). */
#include <string.h>

#include "br/br_p192.h"
#include "test.h"
#include "vectors/p192_vectors.h"

void run_p192_tests(void)
{
    for (unsigned i = 0; i < sizeof kP192 / sizeof kP192[0]; ++i) {
        const p192_vec_t* v = &kP192[i];
        uint8_t x[24], y[24], s[24];
        CHECK(br_p192_private_ok(v->da));
        br_p192_public(v->da, x, y);
        CHECK(memcmp(x, v->ax, 24) == 0 && memcmp(y, v->ay, 24) == 0);
        CHECK(br_p192_on_curve(v->ax, v->ay) && br_p192_on_curve(v->bx, v->by));
        CHECK(br_p192_dhkey(v->da, v->bx, v->by, s) == 0 && memcmp(s, v->shared, 24) == 0);
        uint8_t bad[24];
        memcpy(bad, v->by, 24);
        bad[0] ^= 1;
        CHECK(!br_p192_on_curve(v->bx, bad) && br_p192_dhkey(v->da, v->bx, bad, s) == -1);
    }
    const uint8_t zero[24] = {0};
    CHECK(!br_p192_private_ok(zero));
}
