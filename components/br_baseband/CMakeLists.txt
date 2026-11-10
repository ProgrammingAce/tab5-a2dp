# Bluetooth BR baseband library: pure C99, no ESP-IDF dependencies (also built for host tests by
# tools/test_br_baseband.sh). Used by the C6 Classic controller (c6_fw/) and the HackRF tools.
idf_component_register(
    SRCS "src/br_bits.c" "src/br_access_code.c" "src/br_crc.c" "src/br_whiten.c" "src/br_fec.c"
         "src/br_header.c" "src/br_packet.c" "src/br_hop.c" "src/br_safer.c" "src/br_e0.c" "src/br_ssp.c"
         "src/br_fast.c" "src/br_p192.c" "src/br_a2dp_src.c" "src/br_page_setup.c"
    INCLUDE_DIRS "include")
