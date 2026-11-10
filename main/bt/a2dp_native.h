#pragma once
// Native Classic A2DP source on the Tab5's own ESP32-C6 (no LE Audio, no dongle): the C6 radio lab (C6 firmware
// 1.4.246+) does paging, the baseband link, ARQ and E0; this module runs the host side on the P4 - LMP pairing,
// authentication and encryption, L2CAP and AVDTP (components/br_baseband/br_a2dp_src.c) - and encodes audio to SBC
// (components/sbc_enc) for the C6 to send. State, runbook and measurements: A2DP_HANDOFF.md.
//
// Console: a2dp find (list discoverable devices) | a2dp pair (find + pair the first audio device) | a2dp auto <0|1>
//          a2dp connect [pair] [beep] | a2dp stop | a2dp status | a2dp peer <BD_ADDR hex, MSB first>
//          a2dp key <link key hex, MSB first | clear> | a2dp tone <Hz | off> | a2dp verbose <0|1>
// The peer address and the link key (stored after pairing) live in NVS namespace "a2dpn".

#include <cstddef>
#include <cstdint>

namespace a2dp_native {

void command(const char* line);

struct Status {
    bool running = false;     // a session is active (setting up, paging, connected, streaming or stopping)
    bool streaming = false;
    bool have_peer = false, have_key = false;
    bool auto_reconnect = false;
    int tone_hz = 0;
    char text[96] = "";       // what the session is doing / why it ended
    char peer[20] = "";       // AA:BB:CC:DD:EE:FF
};
Status status();
struct Device { char address[20] = ""; bool audio = false; };
// Thread-safe snapshot of the most recent inquiry, updated as devices arrive.
size_t devices(Device* out, size_t capacity);
// UI: start a session with the stored key (pair = run Just Works pairing; the headphones must be in pairing mode).
void connect(bool pair);
// Ends the session (LMP detach) and stops auto-reconnect attempts until the next connect.
void disconnect();
// Auto-reconnect (NVS): one attempt after boot, up to three after an unexpected link loss. Bounded on purpose: while
// a session runs the C6 is in Classic mode and the Tab5 has no Wi-Fi.
void set_auto(bool on);
// Loads settings and starts the auto-reconnect supervisor (after nvs_flash_init).
void init();
// Streaming: PCM written now plays on the headphones.
bool ready();
// Sample rate of the stream (44100 or 48000), 0 when not streaming.
int rate();
// Interleaved stereo int16 at rate(). Blocks while more than ~120 ms are queued (paces the producer like the I2S DMA);
// returns the frames taken (0 when the stream is gone).
size_t write_pcm(const int16_t* stereo, size_t frames, int timeout_ms);

}  // namespace a2dp_native
