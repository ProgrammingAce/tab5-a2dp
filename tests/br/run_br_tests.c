#include "test.h"

int br_test_failures = 0;
int br_test_checks = 0;

int main(void)
{
    run_bits_tests();
    run_access_code_tests();
    run_crc_tests();
    run_whiten_tests();
    run_fec_tests();
    run_header_tests();
    run_packet_tests();
    run_packet_encryption_tests();
    run_hop_tests();
    run_spec_tests();
    run_safer_tests();
    run_e0_tests();
    run_ssp_tests();
    run_fast_tests();
    run_p192_tests();
    run_a2dp_tests();
    run_page_setup_tests();
    if (br_test_failures) {
        fprintf(stderr, "%d of %d check(s) failed\n", br_test_failures, br_test_checks);
        return 1;
    }
    printf("br_baseband tests passed (%d checks)\n", br_test_checks);
    return 0;
}
