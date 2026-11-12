#include "bt/a2dp_progress.h"
#include <cassert>
#include <cstdio>

int main() {
    a2dp_native::AudioProgress p;
    // A queued packet must fail to advance for a complete two seconds.
    assert(!p.stalled(0, 10, true));
    assert(!p.stalled(1999999, 10, true));
    assert(p.stalled(2000000, 10, true));
    // Any ACK progress, including wraparound, starts a fresh window.
    assert(!p.stalled(9000000, 11, true));
    assert(!p.stalled(10000000, 11, true));
    assert(!p.stalled(17000000, 0xffffffffu, true));
    assert(!p.stalled(18000000, 0, true));
    // A high-loss link that keeps delivering packets must never trip.
    for (unsigned i = 1; i <= 100; ++i)
        assert(!p.stalled(18000000 + int64_t(i) * 1500000, i, true));
    // Empty audio queues and suspended streams are not media failures.
    assert(!p.stalled(200000000, 100, false));
    assert(!p.stalled(900000000, 100, false));
    assert(!p.stalled(1000000000, 100, true));
    assert(!p.stalled(1001999999, 100, true));
    p.reset(); // invalid telemetry, a new connection, or suspend
    assert(!p.stalled(2000000000, 100, true));
    assert(!p.stalled(2001999999, 100, true));
    assert(p.stalled(2002000000, 100, true));
    // A fresh time origin does not inherit the previous deadline.
    assert(!p.stalled(0, 100, true));
    std::puts("A2DP media progress: PASS");
}
