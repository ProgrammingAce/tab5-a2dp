#include "br/br_hop.h"

#include "br/br_access_code.h"

/* Butterfly stages of the PERM5 network, control bit P_i swaps Z bits index1[i] and index2[i]; stages run from
 * P13 down to P0. Core Vol 2 Part B §2.6.2, Figure "Butterfly implementation". Table cross-checked with libbtbb. */
static const uint8_t kIndex1[14] = {0, 2, 1, 3, 0, 1, 0, 3, 1, 0, 2, 1, 0, 1};
static const uint8_t kIndex2[14] = {1, 3, 2, 4, 4, 3, 2, 4, 4, 3, 4, 3, 3, 2};

uint8_t br_hop_perm5(uint8_t z, uint8_t p_high5, uint16_t p_low9)
{
    const uint32_t p = ((uint32_t)(p_high5 & 0x1Fu) << 9) | (p_low9 & 0x1FFu);
    unsigned zb = z & 0x1Fu;
    for (int i = 13; i >= 0; --i) {
        if (!((p >> i) & 1u)) continue;
        const unsigned b1 = (zb >> kIndex1[i]) & 1u, b2 = (zb >> kIndex2[i]) & 1u;
        if (b1 != b2) zb ^= (1u << kIndex1[i]) | (1u << kIndex2[i]);
    }
    return (uint8_t)zb;
}

int br_hop_kernel(const br_hop_in_t* in)
{
    const uint8_t z = (uint8_t)((((in->x + in->a) & 0x1Fu) ^ in->b) & 0x1Fu);
    const uint8_t p_high = (uint8_t)((in->y1 ? 0x1Fu : 0u) ^ in->c);
    const unsigned perm = br_hop_perm5(z, p_high, in->d);
    const unsigned idx = (perm + in->e + in->f + 32u * (in->y1 & 1u)) % 79u;
    /* Register bank: even channels 0..78 first, then odd 1..77. */
    return (int)((idx * 2u) % 79u);
}

/* Address-only parts of A..E (§2.6.4 table). */
static void address_inputs(uint32_t a28, br_hop_in_t* in)
{
    in->a = (a28 >> 23) & 0x1Fu;
    in->b = (a28 >> 19) & 0x0Fu;
    in->c = (uint8_t)(((a28 >> 4) & 0x10u) | ((a28 >> 3) & 0x08u) | ((a28 >> 2) & 0x04u) | ((a28 >> 1) & 0x02u) |
                      (a28 & 0x01u)); /* A8,6,4,2,0 */
    in->d = (a28 >> 10) & 0x1FFu;
    in->e = (uint8_t)(((a28 >> 7) & 0x40u) | ((a28 >> 6) & 0x20u) | ((a28 >> 5) & 0x10u) | ((a28 >> 4) & 0x08u) |
                      ((a28 >> 3) & 0x04u) | ((a28 >> 2) & 0x02u) | ((a28 >> 1) & 0x01u)); /* A13,11,...,1 */
    in->f = 0;
}

int br_hop_connection(uint32_t addr28, uint32_t clk)
{
    br_hop_in_t in;
    address_inputs(addr28, &in);
    in.x = (clk >> 2) & 0x1Fu;
    in.y1 = (clk >> 1) & 1u;
    in.a ^= (clk >> 21) & 0x1Fu;
    in.c ^= (clk >> 16) & 0x1Fu;
    in.d ^= (clk >> 7) & 0x1FFu;
    in.f = (uint8_t)(((uint64_t)16u * ((clk >> 7) & 0x1FFFFFu)) % 79u);
    return br_hop_kernel(&in);
}

/* X for page / inquiry: [CLK16-12 + koffset + (CLK4-2,0 - CLK16-12) mod 16] mod 32. */
static uint8_t train_x(uint32_t clk, int koffset)
{
    const int c16_12 = (int)((clk >> 12) & 0x1Fu);
    const int c4_2_0 = (int)((((clk >> 2) & 0x7u) << 1) | (clk & 1u));
    const int m = ((c4_2_0 - c16_12) % 16 + 16) % 16;
    return (uint8_t)((c16_12 + koffset + m) & 0x1F);
}

int br_hop_train_x(uint32_t clk, int koffset) { return train_x(clk, koffset); }

static const uint32_t kGiacAddr = BR_GIAC_LAP; /* UAP (DCI) = 0x00 */

int br_hop_page(uint32_t addr28, uint32_t clk, int koffset)
{
    br_hop_in_t in;
    address_inputs(addr28, &in);
    in.x = train_x(clk, koffset);
    in.y1 = (clk >> 1) & 1u;
    return br_hop_kernel(&in);
}

int br_hop_inquiry(uint32_t clk, int koffset) { return br_hop_page(kGiacAddr, clk, koffset); }

int br_hop_page_scan(uint32_t addr28, uint32_t clkn)
{
    br_hop_in_t in;
    address_inputs(addr28, &in);
    in.x = (clkn >> 12) & 0x1Fu;
    in.y1 = 0;
    return br_hop_kernel(&in);
}

int br_hop_inquiry_scan(uint32_t clkn) { return br_hop_page_scan(kGiacAddr, clkn); }

int br_hop_master_page_response(uint32_t addr28, uint32_t clke_frozen, int koffset_frozen, uint32_t clke, int n)
{
    br_hop_in_t in;
    address_inputs(addr28, &in);
    in.x = (uint8_t)((train_x(clke_frozen, koffset_frozen) + n) & 0x1F);
    in.y1 = (clke >> 1) & 1u;
    return br_hop_kernel(&in);
}

int br_hop_slave_page_response(uint32_t addr28, uint32_t clkn_frozen, uint32_t clkn, int n)
{
    br_hop_in_t in;
    address_inputs(addr28, &in);
    in.x = (uint8_t)((((clkn_frozen >> 12) & 0x1Fu) + (unsigned)n) & 0x1Fu);
    in.y1 = (clkn >> 1) & 1u;
    return br_hop_kernel(&in);
}

int br_hop_inquiry_response(uint32_t clkn, int n)
{
    br_hop_in_t in;
    address_inputs(kGiacAddr, &in);
    in.x = (uint8_t)((((clkn >> 12) & 0x1Fu) + (unsigned)n) & 0x1Fu);
    in.y1 = 1;
    return br_hop_kernel(&in);
}
