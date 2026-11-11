/* Tests for bits, access codes, HEC/CRC, whitening and FEC. */
#include <string.h>

#include "br/br.h"
#include "test.h"
#include "vectors/oracle_vectors.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

void run_bits_tests(void)
{
    const unsigned lens[] = {1, 7, 8, 9, 63, 64};
    for (unsigned k = 0; k < COUNT(lens); ++k) {
        for (unsigned pos = 0; pos < 11; ++pos) {
            uint8_t buf[16];
            memset(buf, 0xA5, sizeof buf);
            const uint64_t v = 0xF0E1D2C3B4A59687ull & (lens[k] == 64 ? ~0ull : ((1ull << lens[k]) - 1));
            br_bits_write(buf, pos, v, lens[k]);
            CHECK(br_bits_read(buf, pos, lens[k]) == v);
        }
    }
    uint8_t b[2] = {0, 0};
    br_bit_put(b, 0, 1);
    br_bit_put(b, 9, 1);
    CHECK(b[0] == 0x01 && b[1] == 0x02);
    CHECK(br_popcount64(0xFFull) == 8 && br_popcount64(0) == 0);
    CHECK(br_reverse_bits(0x1, 8) == 0x80 && br_reverse_bits(0x3, 5) == 0x18);
}

void run_access_code_tests(void)
{
    for (unsigned i = 0; i < COUNT(kOracleSyncLap); ++i) {
        const uint64_t sw = br_sync_word(kOracleSyncLap[i]);
        CHECK(sw == kOracleSyncWord[i]);
        CHECK(((sw >> 34) & 0xFFFFFFu) == kOracleSyncLap[i]); /* LAP visible at bits 34..57 */
    }
    /* Preamble and trailer alternate into/out of the sync word. */
    for (unsigned i = 0; i < 8; ++i) {
        uint8_t buf[9];
        memset(buf, 0, sizeof buf);
        CHECK(br_access_code_bits(kOracleSyncLap[i], 1, buf) == 72);
        CHECK(br_bit_get(buf, 3) != br_bit_get(buf, 4));
        CHECK(br_bit_get(buf, 0) != br_bit_get(buf, 1) && br_bit_get(buf, 1) != br_bit_get(buf, 2));
        CHECK(br_bit_get(buf, 67) != br_bit_get(buf, 68));
        CHECK(br_bit_get(buf, 68) != br_bit_get(buf, 69) && br_bit_get(buf, 70) != br_bit_get(buf, 71));
        CHECK(br_bits_read(buf, 4, 64) == br_sync_word(kOracleSyncLap[i]));
        CHECK(br_access_code_bits(kOracleSyncLap[i], 0, buf) == 68);
    }
}

void run_crc_tests(void)
{
    for (unsigned i = 0; i < COUNT(kOracleHec); ++i) CHECK(br_hec(kOracleHecData[i], kOracleHecUap[i]) == kOracleHec[i]);
    for (unsigned i = 0; i < COUNT(kOracleCrc); ++i)
        CHECK(br_crc16(kOracleCrc[i].bits, 0, kOracleCrc[i].nbits, kOracleCrc[i].uap) == kOracleCrc[i].crc);
    /* Offset start position gives the same CRC. */
    uint8_t shifted[60];
    memset(shifted, 0, sizeof shifted);
    br_bits_copy(shifted, 13, kOracleCrc[0].bits, 0, kOracleCrc[0].nbits);
    CHECK(br_crc16(shifted, 13, kOracleCrc[0].nbits, kOracleCrc[0].uap) == kOracleCrc[0].crc);
}

void run_whiten_tests(void)
{
    for (unsigned c = 0; c < 64; ++c) {
        br_whiten_t w;
        br_whiten_init(&w, (uint8_t)c);
        int ok = 1;
        for (unsigned i = 0; i < 127; ++i) ok &= br_whiten_next(&w) == br_bit_get(kOracleWhiten[c], i);
        CHECK(ok);
        /* Period 127: the next bit equals bit 0 again. */
        CHECK(br_whiten_next(&w) == br_bit_get(kOracleWhiten[c], 0));
    }
}

void run_fec_tests(void)
{
    for (unsigned d = 0; d < 1024; ++d) CHECK(br_fec23_block((uint16_t)d) == kOracleFec23[d]);

    /* Every single-bit error in a block is corrected. */
    for (unsigned d = 0; d < 1024; d += 37) {
        const uint16_t cw = br_fec23_block((uint16_t)d);
        for (unsigned e = 0; e < 15; ++e) {
            uint8_t in[2] = {0, 0}, out[2] = {0, 0};
            br_bits_write(in, 0, cw ^ (1u << e), 15);
            size_t fixed = 0;
            CHECK(br_fec23_decode(in, 0, 10, out, 0, &fixed) == 0);
            CHECK(br_bits_read(out, 0, 10) == d && fixed == 1);
        }
    }
    /* Multi-block round trip with padding (n = 23 bits -> 3 blocks). */
    uint8_t src[4] = {0x5A, 0xC3, 0x7E, 0}, coded[8], back[4];
    memset(coded, 0, sizeof coded);
    memset(back, 0, sizeof back);
    CHECK(br_fec23_encode(src, 0, 23, coded, 0) == 45);
    CHECK(br_fec23_coded_len(23) == 45);
    CHECK(br_fec23_decode(coded, 0, 23, back, 0, NULL) == 0);
    CHECK(br_bits_read(back, 0, 23) == br_bits_read(src, 0, 23));

    /* 1/3 FEC: one wrong bit per triple is outvoted. */
    uint8_t one[1] = {0xB2}, rep[3], dec[1] = {0};
    memset(rep, 0, sizeof rep);
    br_fec13_encode(one, 0, 8, rep, 0);
    br_bit_put(rep, 4, !br_bit_get(rep, 4));
    CHECK(br_fec13_decode(rep, 0, 8, dec, 0) == 1);
    CHECK(dec[0] == 0xB2);
}
