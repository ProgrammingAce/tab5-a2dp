#pragma once
// Native Classic A2DP source on the Tab5's own ESP32-C6 (no LE Audio, no dongle): the C6 radio lab (C6 firmware
// 1.4.246+) does paging, the baseband link, ARQ and E0; this module runs the host side on the P4 - LMP pairing,
// authentication and encryption, L2CAP and AVDTP (components/br_baseband/br_a2dp_src.c) - and encodes audio to SBC
// (components/sbc_enc) for the C6 to send. State, runbook and measurements: A2DP_HANDOFF.md.
//
// Console: a2dp find (search: list discoverable devices) | a2dp list | a2dp pair <n found | addr>
//          a2dp brmod <hex | 0> / brtrim <0..15> (BR modulation index registers, on by default)
//          a2dp pair (find + pair the first audio device) | a2dp connect [<n saved>] [pair] [beep] | a2dp forget <n>
//          a2dp stop | a2dp status | a2dp auto <0|1> | a2dp peer <BD_ADDR hex, MSB first>
//          a2dp key <link key hex, MSB first | clear> (default device) | a2dp tone <Hz | off> | a2dp verbose <0|1>
// Up to kMaxSaved paired devices (address, link key, name) live in NVS namespace "a2dpn", key "devs", most recently
// used first (older firmware's single "peer"/"key" is migrated).

#include <cstddef>
#include <cstdint>

namespace a2dp_native {

void command(const char* line);

constexpr int kMaxSaved = 8;   // remembered headphones
constexpr int kMaxFound = 16;  // devices listed by one search

struct Device {
    char addr[18] = "";   // AA:BB:CC:DD:EE:FF
    char name[49] = "";   // the device's own name, read on the first encrypted connection (empty until then)
    uint32_t cod = 0;     // class of device (from the inquiry)
    bool paired = false;  // a link key is stored
    bool saved = false;   // in the saved list
    bool supported = true;  // found list: the C6 can page this address (see kMaxFhsLen in a2dp_native.cpp)
};

struct Status {
    bool running = false;     // a session is active (searching, setting up, paging, connected, streaming or stopping)
    bool streaming = false;
    bool searching = false;   // the inquiry runs: found[] grows; pair_found() picks one
    bool have_peer = false, have_key = false;  // the default device (saved[0]) and its key
    bool auto_reconnect = false;
    int tone_hz = 0;          // console test tone (a2dp tone <Hz|off>), 0 = off
    char text[96] = "";       // what the session is doing / why it ended
    char peer[20] = "";       // the default device
    char active[20] = "";     // the device of the running session ("" while idle or searching)
    int saved_count = 0;
    Device saved[kMaxSaved];  // most recently used first; [0] is the default and the auto-reconnect target
    int found_count = 0;
    Device found[kMaxFound];  // the last search, audio devices first
};
Status status();
// "HEADPHONES", "SPEAKER", ... from the class of device.
const char* device_kind(uint32_t cod);
// Connects the default device (pair = search and pair the first headphones in pairing mode instead).
void connect(bool pair);
// Lists discoverable devices for up to 40 s (the headphones must be in pairing mode); status().found grows.
bool search();
// Pairs one found device (during a search: after the current search window). Saved once pairing succeeds; the
// other saved devices keep their keys.
bool pair_found(const char* addr);
bool connect_saved(const char* addr);
// Removes a saved device (and ends its session).
void forget_saved(const char* addr);
// Ends the session or search (LMP detach) and stops auto-reconnect attempts until the next connect.
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
