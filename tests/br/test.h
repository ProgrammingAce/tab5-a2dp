#pragma once
#include <stdio.h>

extern int br_test_failures;
extern int br_test_checks;

#define CHECK(cond)                                                                                     \
    do {                                                                                                \
        ++br_test_checks;                                                                               \
        if (!(cond)) {                                                                                  \
            ++br_test_failures;                                                                         \
            if (br_test_failures <= 30) fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                                               \
    } while (0)

void run_bits_tests(void);
void run_access_code_tests(void);
void run_crc_tests(void);
void run_whiten_tests(void);
void run_fec_tests(void);
void run_header_tests(void);
void run_packet_tests(void);
void run_packet_encryption_tests(void);
void run_hop_tests(void);
void run_spec_tests(void);
void run_safer_tests(void);
void run_e0_tests(void);
void run_ssp_tests(void);
void run_fast_tests(void);
void run_p192_tests(void);
void run_a2dp_tests(void);
void run_page_setup_tests(void);
