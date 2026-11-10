#pragma once
/* Hop selection. Core Vol 2 Part B §2.6 (kernel §2.6.2, control words per state §2.6.4).
 * Channel index k in 0..78 means 2402 + k MHz. */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Kernel inputs, names as in §2.6.2. Y2 = 32 * Y1 for every state this library implements. */
typedef struct {
    uint8_t x;  /* 5 bits */
    uint8_t y1; /* 1 bit */
    uint8_t a;  /* 5 bits */
    uint8_t b;  /* 4 bits */
    uint8_t c;  /* 5 bits */
    uint16_t d; /* 9 bits */
    uint8_t e;  /* 7 bits */
    uint8_t f;  /* already reduced mod 79 */
} br_hop_in_t;

uint8_t br_hop_perm5(uint8_t z, uint8_t p_high5, uint16_t p_low9);
int br_hop_kernel(const br_hop_in_t* in);

/* 28-bit address input: UAP3..0 then LAP23..0. */
static inline uint32_t br_hop_address(uint8_t uap, uint32_t lap) { return ((uint32_t)(uap & 0xFu) << 24) | (lap & 0xFFFFFFu); }

/* Connection state (basic hopping, no AFH). clk = master clock CLK27..0. Verified against libbtbb. */
int br_hop_connection(uint32_t addr28, uint32_t clk);

/* Page / inquiry substates. koffset = 24 (train A) or 8 (train B). clk is CLKE (page) or CLKN (inquiry).
 * Page, page scan and both page-response states are verified against Core Vol 2 Part G §2 (all three sets).
 * Inquiry and inquiry scan are the same kernels with the GIAC address (no separate sample data). */
int br_hop_page(uint32_t addr28, uint32_t clk, int koffset);
/* The page/inquiry X input: [CLK16-12 + koffset + (CLK4-2,0 - CLK16-12) mod 16] mod 32 (§2.6.4.1). The FHS sent in
 * page response is whitened with this X plus the response counter N (§7.2), extended with two MSBs of 1. */
int br_hop_train_x(uint32_t clk, int koffset);
int br_hop_inquiry(uint32_t clk, int koffset); /* GIAC address, DCI UAP 0x00 */
int br_hop_page_scan(uint32_t addr28, uint32_t clkn);
int br_hop_inquiry_scan(uint32_t clkn);
/* Central (master) page response: X = Xp(CLKE*, koffset*) + n; Y1 = CLKE1 of the running clock.
 * clke_frozen = CLKE* when the peripheral's ID was received, clke = current CLKE, n = response counter. */
int br_hop_master_page_response(uint32_t addr28, uint32_t clke_frozen, int koffset_frozen, uint32_t clke, int n);
/* Peripheral (slave) page response: X = CLKN*16-12 + n; Y1 = CLKN1 of the running clock. */
int br_hop_slave_page_response(uint32_t addr28, uint32_t clkn_frozen, uint32_t clkn, int n);
/* Inquiry response (scanning device answering): X = CLKN16-12 + n, Y1 = 1. TODO(spec): no sample data. */
int br_hop_inquiry_response(uint32_t clkn, int n);

#ifdef __cplusplus
}
#endif
