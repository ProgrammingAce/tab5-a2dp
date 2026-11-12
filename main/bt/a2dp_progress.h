#pragma once

#include <cstdint>

namespace a2dp_native {

// Observe successful delivery, not signal quality. Empty queues, missing
// telemetry and transitions out of Streaming must reset the observation.
class AudioProgress {
public:
    void reset() { watching_ = false; }

    bool stalled(int64_t now_us, uint32_t acked, bool pending) {
        if (!pending) { reset(); return false; }
        if (!watching_ || acked != acked_ || now_us < since_us_) {
            watching_ = true;
            acked_ = acked;
            since_us_ = now_us;
            return false;
        }
        return now_us - since_us_ >= 2000000;
    }

private:
    bool watching_ = false;
    uint32_t acked_ = 0;
    int64_t since_us_ = 0;
};

}  // namespace a2dp_native
