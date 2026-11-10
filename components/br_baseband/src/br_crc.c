#include "br/br_crc.h"

#include "br/br_bits.h"

/* Register position i is bit i. Each input bit: feedback = in XOR highest position; shift up; feedback enters
 * position 0 and is XORed into the tap positions. The register is sent highest position first.
 * Conventions cross-checked against libbtbb (see A2DP_PROGRESS.md); spec sample data pending. */

uint8_t br_hec(uint16_t header10, uint8_t uap)
{
    uint32_t reg = uap;
    for (int i = 0; i < 10; ++i) {
        const uint32_t fb = ((header10 >> i) ^ (reg >> 7)) & 1u;
        reg = (reg << 1) & 0xFFu;
        if (fb) reg ^= 0xA7u; /* positions 0,1,2,5,7 */
    }
    return (uint8_t)br_reverse_bits(reg, 8);
}

uint16_t br_crc16(const uint8_t* buf, size_t pos, size_t nbits, uint8_t uap)
{
    uint32_t reg = uap;
    for (size_t i = 0; i < nbits; ++i) {
        const uint32_t fb = ((uint32_t)br_bit_get(buf, pos + i) ^ (reg >> 15)) & 1u;
        reg = (reg << 1) & 0xFFFFu;
        if (fb) reg ^= 0x1021u; /* positions 0,5,12 */
    }
    return (uint16_t)br_reverse_bits(reg, 16);
}
