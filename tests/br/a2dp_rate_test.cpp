#include "bt/a2dp_rate.h"
#include <cassert>
#include <cstdio>

using namespace a2dp_native;

int main() {
    bool sw = false;
    // Older firmware's zero padding is "untested": the guess decides.
    assert(!rate_want48(0, false));
    assert(rate_want48(0, true));

    // A 44.1 kHz device that stalls twice learns 48 kHz.
    uint8_t b = rate_on_stall(0, false, false, &sw);
    assert(!sw && rate_choice(b) == kRateGuess && rate_stalls(b) == 1 && !rate_want48(b, false));
    b = rate_on_stall(b, false, false, &sw);
    assert(sw && b == kRate48 && rate_stalls(b) == 0 && rate_want48(b, false));

    // One stall at the new rate is counted, a clean stretch forgives it.
    b = rate_on_stall(b, true, true, &sw);
    assert(!sw && rate_choice(b) == kRate48 && rate_stalls(b) == 1);
    b = rate_on_clean(b);
    assert(b == kRate48);

    // 48 kHz stalls as often: the rate is not the cause; back to the guess for good.
    b = rate_on_stall(b, true, true, &sw);
    b = rate_on_stall(b, true, true, &sw);
    assert(sw && b == kRateSettled && !rate_want48(b, false) && rate_want48(b, true));
    b = rate_on_stall(b, false, false, &sw);
    assert(!sw && b == kRateSettled);

    // Guessed 48 kHz (the H630 list) that stalls twice tries 44.1 kHz.
    b = rate_on_stall(0, true, true, &sw);
    b = rate_on_stall(b, true, true, &sw);
    assert(sw && b == kRate44 && !rate_want48(b, true));

    // The sink did not give the rate we asked for: nothing is learned.
    b = rate_on_stall(kRate48, true, false, &sw);
    assert(!sw && b == kRate48);
    b = rate_on_stall(0, false, true, &sw);
    assert(!sw && b == 0);

    // Stalls before a clean stretch do not add up with later ones.
    b = rate_on_stall(0, false, false, &sw);
    b = rate_on_clean(b);
    b = rate_on_stall(b, false, false, &sw);
    assert(!sw && rate_stalls(b) == 1);
    std::puts("A2DP rate learning: PASS");
}
