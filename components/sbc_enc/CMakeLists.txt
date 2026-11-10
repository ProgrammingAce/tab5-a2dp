# SBC encoder vendored unchanged from ESP-IDF 5.5.5 (Bluedroid, Apache-2.0): the P4 has no Bluedroid, the native A2DP
# source (main/bt/a2dp_native.cpp) needs only the encoder. Shim headers under include/{common,stack,osi}.
idf_component_register(SRCS "src/sbc_analysis.c" "src/sbc_dct.c" "src/sbc_dct_coeffs.c" "src/sbc_enc_bit_alloc_mono.c"
                            "src/sbc_enc_bit_alloc_ste.c" "src/sbc_enc_coeffs.c" "src/sbc_encoder.c" "src/sbc_packing.c"
                       INCLUDE_DIRS "include")
target_compile_options(${COMPONENT_LIB} PRIVATE -O2 -Wno-unused-variable -Wno-unused-but-set-variable)
