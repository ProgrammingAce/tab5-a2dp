#pragma once
// Radio lab for the native A2DP work (A2DP_NATIVE_BUILD_PLAN.md, T0.4): drives the C6 firmware's lab commands
// (vendor HCI 0xFFE0 "BRL1", c6_fw/c6_firmware/main/radio_lab.h) from text lines on the USB serial console, and
// prints every reply as one "LAB ..." line. The operator script is tools/br_lab/lab.py.
//
// The lab borrows the controller through bt_owner (Owner::Lab, raw HCI channel). While the C6 is in BR mode its
// Wi-Fi and BLE are off, so the Tab5 has no network until "lab exit" (or the C6's own 120 s idle exit).
//
// Commands (numbers decimal unless shown as hex):
//   lab ping | lab enter | lab exit | lab release | lab stop | lab rxfreq | lab reboot
//   lab tone <fn|-> <mhz> [ms] [power]                 fn "-" = plain BLE channel (even MHz)
//   lab hop <fn> <f1> <f2> <period_us> <count>
//   lab rx <fn|-> <mhz> <access_address hex> <ms>
//   lab bletx <fn|-> <mhz> <syncword hex> <len> <type> <power> <count>
//   lab peek <addr hex> [count] | lab poke <addr hex> <value hex> | lab call <fn> <a0> <a1> <a2> <a3>

#include <cstddef>
#include <cstdint>

namespace radio_lab {

// Handles one console line that starts with "lab". Runs in the caller's task (may block while taking the controller).
void command(const char* line);

// Native A2DP host (a2dp_native.cpp): runs one "lab ..." line and waits for the reply to the command it sent (the
// vendor reply of its sub, or the DTM HCI command complete). Copies up to *out_len reply bytes. Returns the C6
// status (0 OK, e.g. 0x05 busy), -1 on timeout, -2 if the line sent nothing. Replies are not printed (set_verbose).
int exec(const char* line, uint8_t* out = nullptr, size_t* out_len = nullptr, int timeout_ms = 1000);
// n SBC frames of frame_len bytes into the C6 stream ring (page mode 24, C6 1.4.246+); no reply.
bool push_sbc(const uint8_t* frames, uint8_t n, uint8_t frame_len);
void set_verbose(bool on);

}  // namespace radio_lab
