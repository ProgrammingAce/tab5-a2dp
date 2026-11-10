SBC encoder from ESP-IDF 5.5.5 `components/bt/host/bluedroid/external/sbc/encoder` (Bluedroid, Apache License 2.0;
the license headers are in each file), copied unchanged. `include/common`, `include/stack` and `include/osi` are small
shims with the configuration Bluedroid uses on ESP32. Used by the native A2DP source on the P4.

One change: `sbc_types.h` declares `SINT32` as `int32_t` instead of `long` (the same on the P4; on 64-bit hosts
`long` broke the fixed-point filterbank: a 440 Hz tone came back as ~5.4 kHz noise, measured with ffmpeg).
Note: `SBC_Encoder_Init` derives the bitpool from `u16BitRate`; set `s16BitPool` after it.
