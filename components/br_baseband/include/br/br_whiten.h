#pragma once
/* Data whitening. Core Vol 2 Part B §7.2. LFSR g(D) = D^7+D^4+1 initialised with CLK6..1 and a 1 in position 6.
 * The header and payload use one continuous whitening sequence (header first). */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t reg;
} br_whiten_t;

/* clk6: clock bits CLK1..CLK6 in bits 0..5 (i.e. (CLK >> 1) & 0x3F). */
void br_whiten_init(br_whiten_t* w, uint8_t clk6);
int br_whiten_next(br_whiten_t* w);
/* XORs the next `n` whitening bits into buf starting at bit `pos`. */
void br_whiten_apply(br_whiten_t* w, uint8_t* buf, size_t pos, size_t n);

#ifdef __cplusplus
}
#endif
