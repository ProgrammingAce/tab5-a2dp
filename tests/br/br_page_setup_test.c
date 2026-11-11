/* br_page_setup against the values the Mac lab tools sent to the C6 for the Bose (LAP 16CDE0, UAP BC). */
#include <string.h>

#include "br/br_page_setup.h"
#include "test.h"

void run_page_setup_tests(void)
{
    uint32_t aa, tail, crc;
    br_page_dtm_id(0x16CDE0, &aa, &tail, &crc);
    CHECK(aa == 0x4B5B5F1Cu && tail == 0xB05B3783u && crc == 0x62EF36u);
    static const uint8_t tx[32] = {65, 69, 49, 53, 67, 71, 51, 55, 25, 29, 9, 13, 27, 31, 11, 15, 57, 61, 41, 45, 59, 63,
                                   43, 47, 33, 37, 17, 21, 35, 39, 19, 23};
    static const uint8_t rx[32] = {44, 48, 12, 16, 52, 56, 20, 24, 26, 30, 73, 77, 34, 38, 2, 6, 28, 32, 75, 0, 36, 40,
                                   4, 8, 42, 46, 10, 14, 50, 54, 18, 22};
    uint8_t t[32], r[32];
    br_page_table(0x16CDE0, 0xBC, t, r);
    CHECK(memcmp(t, tx, 32) == 0 && memcmp(r, rx, 32) == 0);
    /* inquiry table = brcli inqtable */
    static const uint8_t itx[32] = {43, 59, 27, 77, 45, 61, 29, 0, 47, 63, 31, 2, 49, 65, 33, 4, 51, 67, 35, 6, 53, 69,
                                    37, 8, 55, 71, 39, 10, 57, 73, 41, 75};
    static const uint8_t irx[32] = {16, 44, 12, 56, 24, 52, 20, 50, 18, 46, 14, 58, 26, 54, 22, 64, 32, 60, 28, 72, 40,
                                    68, 36, 66, 34, 62, 30, 74, 42, 70, 38, 48};
    br_inquiry_table(t, r);
    CHECK(memcmp(t, itx, 32) == 0 && memcmp(r, irx, 32) == 0);
}
