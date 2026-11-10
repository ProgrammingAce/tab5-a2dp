#include "br/br_whiten.h"

#include "br/br_bits.h"

void br_whiten_init(br_whiten_t* w, uint8_t clk6) { w->reg = (uint8_t)((clk6 & 0x3Fu) | 0x40u); }

int br_whiten_next(br_whiten_t* w)
{
    const unsigned out = (w->reg >> 6) & 1u;
    unsigned r = ((unsigned)w->reg << 1) & 0x7Fu;
    if (out) r ^= 0x11u; /* feedback into position 0 and tap position 4 */
    w->reg = (uint8_t)r;
    return (int)out;
}

void br_whiten_apply(br_whiten_t* w, uint8_t* buf, size_t pos, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        if (br_whiten_next(w)) br_bit_put(buf, pos + i, !br_bit_get(buf, pos + i));
}
