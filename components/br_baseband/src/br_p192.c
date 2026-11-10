#include "br/br_p192.h"

#include <string.h>

/* Field elements: 6 x 32-bit limbs, little-endian, fully reduced mod p = 2^192 - 2^64 - 1. */
typedef uint32_t fe[6];

static const fe P = {0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};
static const fe B = {0xC146B9B1u, 0xFEB8DEECu, 0x72243049u, 0x0FA7E9ABu, 0xE59C80E7u, 0x64210519u};
static const fe GX = {0x82FF1012u, 0xF4FF0AFDu, 0x43A18800u, 0x7CBF20EBu, 0xB03090F6u, 0x188DA80Eu};
static const fe GY = {0x1E794811u, 0x73F977A1u, 0x6B24CDD5u, 0x631011EDu, 0xFFC8DA78u, 0x07192B95u};
static const fe N = {0xB4D22831u, 0x146BC9B1u, 0x99DEF836u, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};

static void fe_from(fe r, const uint8_t b[24])
{
    for (int i = 0; i < 6; ++i)
        r[i] = (uint32_t)b[4 * i] | (uint32_t)b[4 * i + 1] << 8 | (uint32_t)b[4 * i + 2] << 16 | (uint32_t)b[4 * i + 3] << 24;
}
static void fe_to(uint8_t b[24], const fe a)
{
    for (int i = 0; i < 6; ++i)
        for (int k = 0; k < 4; ++k) b[4 * i + k] = (uint8_t)(a[i] >> (8 * k));
}
static int cmp6(const uint32_t* a, const uint32_t* b)
{
    for (int i = 5; i >= 0; --i)
        if (a[i] != b[i]) return a[i] > b[i] ? 1 : -1;
    return 0;
}
static int fe_zero(const fe a) { return !(a[0] | a[1] | a[2] | a[3] | a[4] | a[5]); }

/* r = a - b over 6 limbs; returns the borrow. */
static uint32_t sub6(uint32_t* r, const uint32_t* a, const uint32_t* b)
{
    uint64_t br = 0;
    for (int i = 0; i < 6; ++i) {
        const uint64_t d = (uint64_t)a[i] - b[i] - br;
        r[i] = (uint32_t)d;
        br = (d >> 63) & 1u;
    }
    return (uint32_t)br;
}
static uint32_t add6(uint32_t* r, const uint32_t* a, const uint32_t* b)
{
    uint64_t c = 0;
    for (int i = 0; i < 6; ++i) {
        c += (uint64_t)a[i] + b[i];
        r[i] = (uint32_t)c;
        c >>= 32;
    }
    return (uint32_t)c;
}

static void fe_add(fe r, const fe a, const fe b)
{
    const uint32_t c = add6(r, a, b);
    if (c || cmp6(r, P) >= 0) sub6(r, r, P);
}
static void fe_sub(fe r, const fe a, const fe b)
{
    if (sub6(r, a, b)) add6(r, r, P);
}

/* NIST fast reduction for P-192 on 64-bit words c0..c5 (Guide to ECC, Alg. 2.27):
 * r = (c2,c1,c0) + (0,c3,c3) + (c4,c4,0) + (c5,c5,c5) mod p. */
static void fe_reduce(fe r, const uint32_t c[12])
{
    /* 64-bit word k = limbs 2k, 2k+1 */
#define W(k) (uint64_t)c[2 * (k)] | (uint64_t)c[2 * (k) + 1] << 32
    const uint64_t c0 = W(0), c1 = W(1), c2 = W(2), c3 = W(3), c4 = W(4), c5 = W(5);
#undef W
    /* sum per 64-bit column with carries tracked in 32-bit halves */
    uint64_t s[3][4] = {{c0, c3, 0, c5}, {c1, c3, c4, c5}, {c2, 0, c4, c5}};
    uint32_t acc[7] = {0};
    uint64_t carry = 0;
    for (int col = 0; col < 3; ++col) {
        uint64_t lo = carry, hi = 0;
        for (int t = 0; t < 4; ++t) {
            lo += s[col][t] & 0xFFFFFFFFu;
            hi += s[col][t] >> 32;
        }
        hi += lo >> 32;
        acc[2 * col] = (uint32_t)lo;
        acc[2 * col + 1] = (uint32_t)hi;
        carry = hi >> 32;
    }
    /* acc (192 bits) + carry * 2^192, and 2^192 = 2^64 + 1 mod p */
    while (carry) {
        const uint32_t k[6] = {(uint32_t)carry, (uint32_t)(carry >> 32), (uint32_t)carry, (uint32_t)(carry >> 32), 0, 0};
        uint64_t cc = 0;
        for (int i = 0; i < 6; ++i) {
            cc += (uint64_t)acc[i] + k[i];
            acc[i] = (uint32_t)cc;
            cc >>= 32;
        }
        carry = cc;
    }
    memcpy(r, acc, sizeof(fe));
    while (cmp6(r, P) >= 0) sub6(r, r, P);
}

static void fe_mul(fe r, const fe a, const fe b)
{
    uint32_t c[12] = {0};
    for (int i = 0; i < 6; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 6; ++j) {
            const uint64_t t = (uint64_t)a[i] * b[j] + c[i + j] + carry;
            c[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        c[i + 6] = (uint32_t)carry;
    }
    fe_reduce(r, c);
}
static void fe_sqr(fe r, const fe a) { fe_mul(r, a, a); }

/* a^(p-2) mod p */
static void fe_inv(fe r, const fe a)
{
    fe e;
    memcpy(e, P, sizeof e);
    e[0] -= 2u; /* p - 2: low limb 0xFFFFFFFD, no borrow */
    fe x = {1, 0, 0, 0, 0, 0};
    for (int i = 191; i >= 0; --i) {
        fe_sqr(x, x);
        if ((e[i >> 5] >> (i & 31)) & 1u) fe_mul(x, x, a);
    }
    memcpy(r, x, sizeof(fe));
}

/* Jacobian points (X, Y, Z); infinity = Z == 0. a = -3. */
typedef struct { fe x, y, z; } jp;

static void jp_double(jp* r, const jp* p)
{
    if (fe_zero(p->z) || fe_zero(p->y)) { memset(r, 0, sizeof *r); return; }
    fe d, t1, t2, m, s, x3, y3, z3;
    /* m = 3 (X - Z^2)(X + Z^2) */
    fe_sqr(d, p->z);
    fe_sub(t1, p->x, d);
    fe_add(t2, p->x, d);
    fe_mul(m, t1, t2);
    fe_add(t1, m, m);
    fe_add(m, t1, m);
    /* s = 4 X Y^2 */
    fe_sqr(t1, p->y);
    fe_mul(s, p->x, t1);
    fe_add(s, s, s);
    fe_add(s, s, s);
    /* x3 = m^2 - 2 s */
    fe_sqr(x3, m);
    fe_sub(x3, x3, s);
    fe_sub(x3, x3, s);
    /* y3 = m (s - x3) - 8 Y^4 */
    fe_sqr(t2, t1);
    fe_add(t2, t2, t2);
    fe_add(t2, t2, t2);
    fe_add(t2, t2, t2);
    fe_sub(t1, s, x3);
    fe_mul(y3, m, t1);
    fe_sub(y3, y3, t2);
    /* z3 = 2 Y Z */
    fe_mul(z3, p->y, p->z);
    fe_add(z3, z3, z3);
    memcpy(r->x, x3, sizeof(fe));
    memcpy(r->y, y3, sizeof(fe));
    memcpy(r->z, z3, sizeof(fe));
}

/* r = p + q with q affine (qz = 1) */
static void jp_add_affine(jp* r, const jp* p, const fe qx, const fe qy)
{
    if (fe_zero(p->z)) {
        memcpy(r->x, qx, sizeof(fe));
        memcpy(r->y, qy, sizeof(fe));
        memset(r->z, 0, sizeof(fe));
        r->z[0] = 1;
        return;
    }
    fe z2, u2, s2, h, rr, h2, h3, t, x3, y3, z3;
    fe_sqr(z2, p->z);
    fe_mul(u2, qx, z2);
    fe_mul(s2, qy, z2);
    fe_mul(s2, s2, p->z);
    fe_sub(h, u2, p->x);
    fe_sub(rr, s2, p->y);
    if (fe_zero(h)) {
        if (fe_zero(rr)) { jp_double(r, p); return; }
        memset(r, 0, sizeof *r);
        return;
    }
    fe_sqr(h2, h);
    fe_mul(h3, h2, h);
    fe_mul(t, p->x, h2); /* U1 H^2 */
    fe_sqr(x3, rr);
    fe_sub(x3, x3, h3);
    fe_sub(x3, x3, t);
    fe_sub(x3, x3, t);
    fe_sub(y3, t, x3);
    fe_mul(y3, y3, rr);
    fe_mul(t, p->y, h3);
    fe_sub(y3, y3, t);
    fe_mul(z3, p->z, h);
    memcpy(r->x, x3, sizeof(fe));
    memcpy(r->y, y3, sizeof(fe));
    memcpy(r->z, z3, sizeof(fe));
}

static void scalar_mul(fe ox, fe oy, const uint8_t d[24], const fe px, const fe py)
{
    fe k;
    fe_from(k, d);
    jp acc;
    memset(&acc, 0, sizeof acc);
    for (int i = 191; i >= 0; --i) {
        jp_double(&acc, &acc);
        if ((k[i >> 5] >> (i & 31)) & 1u) jp_add_affine(&acc, &acc, px, py);
    }
    fe zi, zi2;
    fe_inv(zi, acc.z);
    fe_sqr(zi2, zi);
    fe_mul(ox, acc.x, zi2);
    fe_mul(zi2, zi2, zi);
    fe_mul(oy, acc.y, zi2);
}

static int on_curve(const fe x, const fe y)
{
    if (cmp6(x, P) >= 0 || cmp6(y, P) >= 0) return 0;
    fe l, r, t;
    fe_sqr(l, y);
    fe_sqr(r, x);
    fe_mul(r, r, x);
    fe_add(t, x, x);
    fe_add(t, t, x);
    fe_sub(r, r, t);
    fe_add(r, r, B);
    return cmp6(l, r) == 0;
}

int br_p192_on_curve(const uint8_t x[24], const uint8_t y[24])
{
    fe a, b;
    fe_from(a, x);
    fe_from(b, y);
    return on_curve(a, b);
}

int br_p192_private_ok(const uint8_t d[24])
{
    fe k;
    fe_from(k, d);
    return !fe_zero(k) && cmp6(k, N) < 0;
}

int br_p192_public(const uint8_t d[24], uint8_t x[24], uint8_t y[24])
{
    fe ox, oy;
    scalar_mul(ox, oy, d, GX, GY);
    fe_to(x, ox);
    fe_to(y, oy);
    return 0;
}

int br_p192_dhkey(const uint8_t d[24], const uint8_t px[24], const uint8_t py[24], uint8_t out_x[24])
{
    fe a, b, ox, oy;
    fe_from(a, px);
    fe_from(b, py);
    if (!on_curve(a, b)) return -1;
    scalar_mul(ox, oy, d, a, b);
    fe_to(out_x, ox);
    return 0;
}
