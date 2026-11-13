#pragma once

#include <cstdint>

namespace a2dp_native {

// SBC sample-rate learning, one byte per saved device (Saved::rate, NVS).
//
// A2DP requires every SBC sink to accept both 44.1 and 48 kHz, and a sink's capabilities do not say which rate
// it handles well. Some do not handle one of them: the Sennheiser HDB 630 stops accepting media after seconds to
// minutes of 44.1 kHz and runs clean at 48 kHz (TROUBLESHOOTING.md §3.11). So the rate is learned per device:
// start from a guess (48 kHz for known devices, else 44.1 kHz); after kRateStallLimit media stalls at one rate,
// switch to the other one; if that one stalls as often too, the rate is not the cause: settle on the guess and stop
// learning. kRateCleanUs of streaming without a stall forgives earlier stalls (a headset taken off, a fade).
//
// Byte layout: bits 0-1 choice, bits 2-3 stalls counted at the current choice. A zero byte (older firmware's
// padding) is "untested".
enum : uint8_t { kRateGuess = 0, kRate44 = 1, kRate48 = 2, kRateSettled = 3 };
constexpr int kRateStallLimit = 2;
constexpr int64_t kRateCleanUs = 10 * 60 * 1000000LL;

constexpr uint8_t rate_choice(uint8_t b) { return b & 3u; }
constexpr int rate_stalls(uint8_t b) { return (b >> 2) & 3; }

// The rate to ask for: true = 48 kHz.
constexpr bool rate_want48(uint8_t b, bool guess48) {
    return rate_choice(b) == kRate48 || ((rate_choice(b) == kRateGuess || rate_choice(b) == kRateSettled) && guess48);
}

// A media stall on a stream that asked for asked48 and runs at got48. Returns the new byte; *switched is set when
// the next connection should use the other rate. A stall on a stream whose rate is not the one asked for (the sink
// does not offer it) teaches nothing.
inline uint8_t rate_on_stall(uint8_t b, bool asked48, bool got48, bool* switched) {
    *switched = false;
    const uint8_t c = rate_choice(b);
    if (c == kRateSettled || asked48 != got48) return b;
    const int n = rate_stalls(b) + 1;
    if (n < kRateStallLimit) return static_cast<uint8_t>(c | n << 2);
    *switched = true;
    if (c == kRateGuess) return got48 ? kRate44 : kRate48;  // first verdict: try the other rate
    return kRateSettled;                                    // the other rate stalls as well: back to the guess
}

// A stream at the current choice ran kRateCleanUs without a stall: earlier stalls are forgiven.
constexpr uint8_t rate_on_clean(uint8_t b) { return rate_choice(b); }

}  // namespace a2dp_native
