#pragma once
/* Values the C6 radio lab needs to page a device (formerly computed on the Mac by tools/br_lab/g4_inquiry.py):
 * the BLE-DTM framing of the target's ID packet and the page train table. */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ID packet of `lap` as DTM raw mode 2 parameters: aa = sync word bits 0..31, tail = sync bits 32..63, crc_init =
 * the BLE CRC preset that makes the CRC24 after the 2 header bytes equal sync bits 48..63 + 8 zero bits. */
void br_page_dtm_id(uint32_t lap, uint32_t* aa, uint32_t* tail, uint32_t* crc_init);
/* For X = 0..31: page scan frequency f(X) and the peripheral's first response frequency (Y1 = 1), MHz - 2402. */
void br_page_table(uint32_t lap, uint8_t uap, uint8_t tx[32], uint8_t rx[32]);
/* Inquiry (GIAC): for X = 0..31 the inquiry scan frequency and the inquiry response frequency (n = 0), MHz - 2402. */
void br_inquiry_table(uint8_t tx[32], uint8_t rx[32]);
#define BR_GIAC_LAP 0x9E8B33u

#ifdef __cplusplus
}
#endif
