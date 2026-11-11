#include "bt/a2dp_native.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdarg>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>

#include "br/br_a2dp_src.h"
#include "br/br_access_code.h"
#include "br/br_bits.h"
#include "br/br_e0.h"
#include "br/br_packet.h"
#include "br/br_page_setup.h"
#include "bt/radio_lab.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"
#include "sbc_encoder.h"

namespace a2dp_native {
namespace {

constexpr const char* TAG = "a2dp_native";
constexpr const char* kNs = "a2dpn";
// Our own identity on the link (the lab's): LAP 22CA1B (its sync length byte 40 fits the C6's DTM framing), UAP 00,
// NAP 0000, class of device 5A020C.
constexpr uint32_t kOwnLap = 0x22CA1B;
constexpr uint8_t kOwnUap = 0x00;
constexpr uint8_t kOwnAddr[6] = {0x1B, 0xCA, 0x22, 0x00, 0x00, 0x00};
constexpr int kFramesPerPacket = 15;  // the SBC payload header allows 15: least L2CAP/RTP overhead
constexpr uint8_t kMaxBitpool = 20;     // our SEP; the link budget is one DH1 per central slot
constexpr uint8_t kStreamBitpool = 14;  // 41-byte frames: 15 per packet = 24 DH1 per 43.5 ms, ~69 % of TX slots

enum class State : uint8_t { Idle, Setup, Paging, Connected, Streaming, Stopping };
// Connect: a saved device with its key. Pair: one address, fresh pairing. Search: list discoverable devices until
// the user picks one (then pair it). SearchPair: pair the first audio device found (console `a2dp pair`).
enum class Kind : uint8_t { Connect, Pair, Search, SearchPair };

struct Found {
    uint8_t addr[6];  // LSB first
    uint32_t cod;
    int hits;
};

struct Session {
    Kind kind = Kind::Connect;
    bool pair = false, beep = false;
    Found found[kMaxFound];
    std::atomic<int> nfound{0};
    std::atomic<int> pick{-1};          // Search: the found device the user tapped
    std::atomic<bool> searching{false};
    bool peer_valid = false;            // peer holds the address of the last session
    uint32_t peer_cod = 0;
    std::atomic<State> state{State::Idle};
    std::atomic<bool> stop{false};
    br_a2dp_t eng;
    uint8_t peer[6] = {};  // LSB first
    uint8_t key[16] = {};
    bool have_key = false;
    uint16_t tag = 100;
    int enc_mode = 0;
    uint8_t kc[16] = {};
    uint32_t log_seen = 0, entries0 = 0;
    bool connected = false;
    uint8_t detach_reason = 0;  // the sink's LMP_detach reason (0 = none)
    br_a2dp_stream_t stream = {};
    char status[96] = "idle";
};

Session* s = nullptr;
TaskHandle_t task = nullptr, enc_task = nullptr;
// auto-reconnect: attempts left and when the next one may start (us); user_stop cancels them
std::atomic<int> reconnect_left{0};
std::atomic<int64_t> reconnect_at{0};
// Link-quality retry: some peers (the Galaxy projector speaker) time-share their radio with their own BLE links, and
// each connection lands at a random phase to them: ~2 % or 25-40 % missed replies for the life of the link.
// A qmax below 100 opts into startup reconnects; otherwise only measure and adapt the bitpool.
constexpr int kQualityRetries = 3;
// Keep established links by default. The adaptive encoder handles transient
// loss; the old 12% startup cutoff repeatedly disconnected the H630 even at
// 13% missed replies (see A2DP_PROGRESS.md, 2026-11-11 connection-quality retries).
// Console: a2dp qmax <pct>; 100 disables quality retries, 0 forces them for tests.
std::atomic<int> quality_max_pct{100};
std::atomic<int> quality_left{0};
std::atomic<int64_t> quality_at{0};
std::atomic<bool> quality_start{false};
// A sink that still holds our previous link (its supervision timeout, up to 20 s, has not run out, e.g. our LMP detach
// got lost on a poor link) refuses the next one with 0x0B "connection already exists": wait and try again.
std::atomic<int> stale_left{0};
// Adaptive bitpool: with one-slot packets, bitpool 14 needs ~69 % of all central slots. When the peer misses replies
// (a receiver sharing its radio with its own BLE links: 25-40 % for minutes) the stream would fall behind and break up,
// so the encoder steps down (14 -> 12 -> 10 -> 8, ~55 % of slots at 10) and back up after 5 clean seconds.
constexpr int kMinBitpool = 8;
std::atomic<int> stream_bitpool{14};
std::atomic<bool> auto_on{false}, user_stop{false};
// NVS state cached for status() (the UI polls it)
bool verbose = false;
int tone_hz = 0;
std::atomic<bool> dump_sbc{false};

// PCM ring (interleaved stereo int16) between write_pcm() and the encoder task
constexpr size_t kRingFrames = 8192;  // ~186 ms at 44.1 kHz
int16_t* ring = nullptr;
std::atomic<uint32_t> ring_w{0}, ring_r{0};
std::atomic<uint32_t> pcm_in{0}, pcm_peak{0}, frames_out{0};
SemaphoreHandle_t ring_space = nullptr;

void set_status(const char* fmt, ...) {
    if (!s) return;
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(s->status, sizeof s->status, fmt, ap);
    va_end(ap);
    std::printf("A2DP %s\n", s->status);
}

// ---- NVS --------------------------------------------------------------------------------------------------------
bool nvs_get(const char* k, uint8_t* out, size_t n) {
    nvs_handle_t h;
    if (nvs_open(kNs, NVS_READONLY, &h) != ESP_OK) return false;
    size_t len = n;
    const bool ok = nvs_get_blob(h, k, out, &len) == ESP_OK && len == n;
    nvs_close(h);
    return ok;
}
void nvs_put(const char* k, const uint8_t* v, size_t n) {
    nvs_handle_t h;
    if (nvs_open(kNs, NVS_READWRITE, &h) != ESP_OK) return;
    if (v) nvs_set_blob(h, k, v, n);
    else nvs_erase_key(h, k);
    nvs_commit(h);
    nvs_close(h);
}

// ---- saved headphones (NVS "devs": most recently used first; [0] is the default / auto-reconnect target) --------
struct Saved {
    uint8_t addr[6];  // LSB first
    uint8_t key[16];
    uint8_t has_key, rsvd;
    uint32_t cod;
    char name[BR_A2DP_NAME_MAX + 1];
};
Saved saved_list[kMaxSaved];
int saved_n = 0;
SemaphoreHandle_t saved_mu = nullptr;
struct SavedLock {
    SavedLock() { xSemaphoreTake(saved_mu, portMAX_DELAY); }
    ~SavedLock() { xSemaphoreGive(saved_mu); }
};

// under the lock
void saved_store() {
    nvs_put("devs", reinterpret_cast<const uint8_t*>(saved_list), saved_n * sizeof(Saved));
    if (!saved_n) nvs_put("devs", nullptr, 0);
}
void saved_load() {
    SavedLock l;
    saved_n = 0;
    nvs_handle_t h;
    size_t len = sizeof saved_list;
    bool have = false;
    if (nvs_open(kNs, NVS_READONLY, &h) == ESP_OK) {
        have = nvs_get_blob(h, "devs", saved_list, &len) == ESP_OK && len % sizeof(Saved) == 0;
        nvs_close(h);
    }
    if (have) {
        saved_n = static_cast<int>(len / sizeof(Saved));
        for (int i = 0; i < saved_n; ++i) saved_list[i].name[BR_A2DP_NAME_MAX] = '\0';
        return;
    }
    // older firmware kept one device: "peer" + "key"
    Saved d = {};
    if (!nvs_get("peer", d.addr, 6)) return;
    d.has_key = nvs_get("key", d.key, 16);
    saved_list[0] = d;
    saved_n = 1;
    saved_store();
    nvs_put("peer", nullptr, 0);
    nvs_put("key", nullptr, 0);
}
int saved_find(const uint8_t* a) {
    for (int i = 0; i < saved_n; ++i)
        if (!std::memcmp(saved_list[i].addr, a, 6)) return i;
    return -1;
}
void saved_to_front(int i) {
    if (i <= 0) return;
    const Saved d = saved_list[i];
    std::memmove(saved_list + 1, saved_list, i * sizeof(Saved));
    saved_list[0] = d;
}
// Adds or updates a device (key: nullptr keeps the stored one) and makes it the default.
void saved_upsert(const uint8_t* addr, const uint8_t* key, uint32_t cod, const char* name) {
    SavedLock l;
    int i = saved_find(addr);
    if (i < 0) {
        if (saved_n < kMaxSaved) ++saved_n;  // full: the least recently used one drops off the end
        i = saved_n - 1;
        saved_list[i] = {};
        std::memcpy(saved_list[i].addr, addr, 6);
    }
    if (key) { std::memcpy(saved_list[i].key, key, 16); saved_list[i].has_key = 1; }
    if (cod) saved_list[i].cod = cod;
    if (name && *name) std::snprintf(saved_list[i].name, sizeof saved_list[i].name, "%s", name);
    saved_to_front(i);
    saved_store();
}

void fmt_addr(char* out, size_t n, const uint8_t* a) {
    std::snprintf(out, n, "%02X:%02X:%02X:%02X:%02X:%02X", a[5], a[4], a[3], a[2], a[1], a[0]);
}
bool parse_addr(const char* t, uint8_t* le) {  // "AA:BB:CC:DD:EE:FF" or 12 hex digits, MSB first
    uint8_t be[6];
    int k = 0;
    for (const char* c = t; *c && k < 12; ++c) {
        if (*c == ':') continue;
        const char ch = static_cast<char>(std::toupper(static_cast<unsigned char>(*c)));
        int v = ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
        if (v < 0) return false;
        if (k % 2 == 0) be[k / 2] = static_cast<uint8_t>(v << 4);
        else be[k / 2] |= static_cast<uint8_t>(v);
        ++k;
    }
    if (k != 12) return false;
    for (int i = 0; i < 6; ++i) le[i] = be[5 - i];
    return true;
}

// The C6 sends the FHS as a BLE DTM frame. Without the shift (C6 < 1.4.253) the frame's length byte is bits 8..15 of
// the peer's access-code tail: 40..55 is the normal case, 56..80 works with r2skip/r2late (C6 1.4.248+), other
// addresses cannot be paged. C6 1.4.253 `lab page shift 1` sends the BR packet after our own BLE header: any address.
constexpr unsigned kMaxFhsLen = 80;
bool c6_shift = true;     // the C6 accepted `lab page shift 1` (refreshed at every setup)
bool use_shift = true;    // console: a2dp shift <0|1> (0 = the old length-byte path, for comparison)
bool pageable(unsigned fhs_len) { return (c6_shift && use_shift) || (fhs_len >= 40 && fhs_len <= kMaxFhsLen); }
unsigned fhs_len_for(const uint8_t* addr) {
    uint32_t aa, tail, crc;
    br_page_dtm_id(addr[0] | addr[1] << 8 | static_cast<uint32_t>(addr[2]) << 16, &aa, &tail, &crc);
    return (tail >> 8) & 0xFFu;
}

// ---- lab helpers ------------------------------------------------------------------------------------------------
int lab(const char* line, uint8_t* out = nullptr, size_t* n = nullptr, int timeout_ms = 1500) {
    for (int attempt = 0; attempt < 4; ++attempt) {
        const int rc = radio_lab::exec(line, out, n, timeout_ms);
        if (rc == 0) return 0;
        if (rc == 0xE1 || rc == -1 || rc == -2) {  // busy / no reply / not sent: retry
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        ESP_LOGW(TAG, "'%s' -> %d", line, rc);
        return rc;
    }
    ESP_LOGW(TAG, "'%s' failed", line);
    return -1;
}
void hex(char* dst, const uint8_t* v, size_t n) {
    for (size_t i = 0; i < n; ++i) std::sprintf(dst + 2 * i, "%02X", v[i]);
    dst[2 * n] = '\0';
}

struct Connq {
    uint8_t state = 0;
    uint32_t n = 0, entries = 0, count = 0, head = 0, tail = 0, sbc_level = 0, tx = 0, noreply = 0, sbc_drops = 0;
    bool ok = false;
};
Connq connq() {
    Connq q;
    uint8_t b[240];
    size_t n = sizeof b;
    if (lab("lab page connq", b, &n) != 0 || n < 93) return q;
    auto u32 = [&](size_t o) { return static_cast<uint32_t>(b[o] | b[o + 1] << 8 | b[o + 2] << 16 | static_cast<uint32_t>(b[o + 3]) << 24); };
    q.state = b[1];
    q.n = u32(2);
    q.entries = u32(10);
    q.count = u32(89);
    q.tx = u32(14);
    if (n >= 101) { q.head = u32(93); q.tail = u32(97); }
    if (n >= 145) q.noreply = u32(141);
    if (n >= 205) { q.sbc_level = u32(193); q.sbc_drops = u32(197); }
    q.ok = true;
    return q;
}

// One fragment into the C6 ACL FIFO (retried with the same tag: the C6 drops duplicates).
bool fifo_push(uint8_t type, uint8_t llid, const uint8_t* d, size_t n) {
    char line[48 + 2 * 27 + 1];
    s->tag = static_cast<uint16_t>(s->tag % 65000 + 1);
    char h[2 * 27 + 1];
    hex(h, d, n);
    std::snprintf(line, sizeof line, "lab page fifo %u %u %u %s", s->tag, type, llid, h);
    for (int i = 0; i < 200; ++i) {
        uint8_t r[8];
        size_t rn = sizeof r;
        if (lab(line, r, &rn) == 0 && rn >= 1 && r[0]) return true;
        vTaskDelay(pdMS_TO_TICKS(5));  // FIFO full
    }
    return false;
}

// ---- engine I/O -------------------------------------------------------------------------------------------------
bool l2_dm1 = false;
int l2_frag = 0;  // console: a2dp frag <1..27> (DH1 media fragment bytes; 0 = 27)
void io_send(void*, uint8_t llid, const uint8_t* d, size_t n) {
    if (llid == 3) {
        fifo_push(3, 3, d, n);  // LMP in DM1
        return;
    }
    // DH1 (27 bytes, no FEC) or DM1 (17 bytes, 2/3 FEC) per l2_dm1 (console: a2dp dm1 <0|1>)
    const size_t frag = l2_dm1 ? 17 : 27;
    for (size_t off = 0; off < n; off += frag) fifo_push(l2_dm1 ? 3 : 4, off ? 1 : 2, d + off, n - off < frag ? n - off : frag);
}
void io_set_enc(void*, int mode, const uint8_t kc[16], const uint8_t addr[6]) {
    char k[33], a[13], line[80];
    hex(k, kc, 16);
    hex(a, addr, 6);
    std::snprintf(line, sizeof line, "lab page enc %d %s %s", mode, k, a);
    lab(line);
    s->enc_mode = mode;
    std::memcpy(s->kc, kc, 16);
}
void io_random(void*, uint8_t* out, size_t n) { esp_fill_random(out, n); }
uint32_t io_now(void*) { return static_cast<uint32_t>(esp_timer_get_time() / 1000); }
void io_event(void*, int ev, const void* arg) {
    switch (ev) {
    case BR_A2DP_EV_LOG:
        if (verbose) std::printf("A2DP %s\n", static_cast<const char*>(arg));
        break;
    case BR_A2DP_EV_PAIRED:
        std::memcpy(s->key, arg, 16);
        s->have_key = true;
        saved_upsert(s->peer, s->key, s->peer_cod, nullptr);
        set_status("paired; saved");
        break;
    case BR_A2DP_EV_NAME: {
        const char* name = static_cast<const char*>(arg);
        SavedLock l;
        const int i = saved_find(s->peer);
        if (i >= 0 && std::strcmp(saved_list[i].name, name)) {
            std::snprintf(saved_list[i].name, sizeof saved_list[i].name, "%s", name);
            saved_store();
        }
        break;
    }
    case BR_A2DP_EV_ENCRYPTED: set_status("encrypted"); break;
    case BR_A2DP_EV_STREAMING: {
        s->stream = *static_cast<const br_a2dp_stream_t*>(arg);
        lab(l2_dm1 ? "lab page dm1 1" : "lab page dm1 0");
        { char fl[32]; std::snprintf(fl, sizeof fl, "lab page frag %d", l2_frag); lab(fl); }
        char line[64];
        if (s->beep) std::snprintf(line, sizeof line, "lab page stream 1 %04X %d 0", s->stream.media_cid, kFramesPerPacket);
        else std::snprintf(line, sizeof line, "lab page stream 2 %04X %d 0", s->stream.media_cid, kFramesPerPacket);
        lab(line);
        s->state = State::Streaming;
        reconnect_left = 0;
        {  // the device that plays becomes the default (auto-reconnect target)
            SavedLock l;
            const int i = saved_find(s->peer);
            if (i > 0) { saved_to_front(i); saved_store(); }
        }
        set_status("streaming SBC %lu Hz, bitpool <= %u%s", static_cast<unsigned long>(s->stream.freq),
                   s->stream.max_bitpool, s->beep ? " (C6 beep test)" : "");
        break;
    }
    case BR_A2DP_EV_FAILED:
        set_status("failed: %s", static_cast<const char*>(arg));
        s->stop = true;
        break;
    case BR_A2DP_EV_DETACHED:
        s->detach_reason = *static_cast<const uint8_t*>(arg);
        set_status("headphones disconnected (0x%02X)", *static_cast<const uint8_t*>(arg));
        s->stop = true;
        break;
    case BR_A2DP_EV_SUSPENDED:
        // no media while suspended (AVDTP): the C6 stops sending, the encoder ends; the engine sends START again
        // and BR_A2DP_EV_STREAMING re-arms both
        if (s->state == State::Streaming) {
            lab("lab page stream 0 0 1 0");
            s->state = State::Connected;
        }
        set_status("headphones paused the stream: restarting");
        break;
    default: break;
    }
}

// Received packet log entry -> verified payload (decrypting when needed) -> engine.
void feed_log_entry(const uint8_t* e, size_t n) {
    if (n < 52) return;
    const uint32_t slot = e[0] | e[1] << 8 | e[2] << 16 | static_cast<uint32_t>(e[3]) << 24;
    static uint8_t head[16];
    static bool head_ready = false;
    if (!head_ready) { br_access_code_bits(kOwnLap, 0, head); head_ready = true; }
    uint8_t air[64] = {};
    for (unsigned b = 0; b < 36; ++b) br_bit_put(air, b, br_bit_get(head, b));
    for (unsigned b = 0; b < 8 * 48; ++b) br_bit_put(air, 36 + b, (e[4 + (b >> 3)] >> (b & 7)) & 1);
    const uint32_t clk = 4u * (slot + 1u) + 2u;
    static br_pkt_t pkt;
    br_status_t rc = BR_ERR_CRC;
    for (int attempt = s->enc_mode ? 0 : 1; attempt < 2 && rc != BR_OK; ++attempt) {
        br_e0_t e0;
        if (attempt == 0) br_e0_init(&e0, s->kc, kOwnAddr, clk);
        br_link_ctx_t ctx = {};
        ctx.lap = kOwnLap;
        ctx.uap = kOwnUap;
        ctx.clk6 = static_cast<uint8_t>((clk >> 1) & 63u);
        ctx.sync_tolerance = 4;
        ctx.e0 = attempt == 0 ? &e0 : nullptr;
        std::memset(&pkt, 0, sizeof pkt);
        rc = br_packet_decode(air, 36 + 8 * 48, &ctx, &pkt);
    }
    if (rc != BR_OK || (pkt.hdr.type != BR_TYPE_DM1 && pkt.hdr.type != BR_TYPE_DH1)) return;
    // Log only protocol metadata: authentication payloads contain secret material.
    // Rate limit repeated packets so a stalled peer cannot flood the console.
    if (verbose) {
        static int64_t rx_log_at = 0;
        const int64_t now = esp_timer_get_time();
        if (pkt.llid == 3 || !pkt.pflow || now >= rx_log_at) {
            rx_log_at = now + 1000000;
            std::printf("A2DP RX: slot %lu type %u seq %u ack %u llid %u pflow %u len %u LMP %d\n",
                        static_cast<unsigned long>(slot), pkt.hdr.type, pkt.hdr.seqn, pkt.hdr.arqn,
                        pkt.llid, pkt.pflow, static_cast<unsigned>(pkt.len),
                        pkt.llid == 3 && pkt.len ? pkt.payload[0] >> 1 : -1);
        }
    }
    br_a2dp_rx(&s->eng, pkt.llid, pkt.payload, pkt.len);
}

// ---- SBC encoder task -------------------------------------------------------------------------------------------
uint32_t ring_level() { return ring_w.load() - ring_r.load(); }

void encoder_task(void*) {
    static SBC_ENC_PARAMS enc;
    std::memset(&enc, 0, sizeof enc);
    const br_a2dp_stream_t& st = s->stream;
    enc.s16SamplingFreq = st.freq == 48000 ? SBC_sf48000 : st.freq == 32000 ? SBC_sf32000 : st.freq == 16000 ? SBC_sf16000 : SBC_sf44100;
    enc.s16ChannelMode = st.mode;
    enc.s16NumOfSubBands = st.subbands;
    enc.s16NumOfChannels = st.mode == 0 ? 1 : 2;
    enc.s16NumOfBlocks = st.blocks;
    enc.s16AllocationMethod = st.alloc;
    enc.sbc_mode = SBC_MODE_STD;
    SBC_Encoder_Init(&enc);
    enc.s16BitPool = std::min<int>(kStreamBitpool, st.max_bitpool);
    stream_bitpool = enc.s16BitPool;
    const int spf = st.blocks * st.subbands;  // samples per channel per frame (128)
    uint8_t frames[4][64];
    uint8_t flen = 0;
    const int64_t t0 = esp_timer_get_time();
    uint64_t made = 0;
    double phase = 0;
    while (s && s->state == State::Streaming && !s->stop) {
        // real-time pacing with ~40 ms lead into the C6 ring (128 frames there)
        const int64_t due = (esp_timer_get_time() - t0) * st.freq / spf / 1000000 + 14;
        if (static_cast<int64_t>(made) >= due) { vTaskDelay(pdMS_TO_TICKS(4)); continue; }
        // adaptive bitpool: change only between batches (one frame length per push)
        enc.s16BitPool = static_cast<SINT16>(std::max<int>(std::max<int>(st.min_bitpool, 2),
                                                           std::min<int>(stream_bitpool.load(), st.max_bitpool)));
        int nf = 0;
        while (nf < 4 && static_cast<int64_t>(made) < due) {
            int16_t* pcm = enc.as16PcmBuffer;
            for (int i = 0; i < spf; ++i) {
                int16_t l = 0, r = 0;
                if (tone_hz) {
                    const int16_t v = static_cast<int16_t>(9000 * std::sin(phase));
                    phase += 2 * M_PI * tone_hz / st.freq;
                    if (phase > 2 * M_PI) phase -= 2 * M_PI;
                    l = r = v;
                } else if (ring_level()) {
                    const uint32_t k = ring_r.load() % kRingFrames;
                    l = ring[2 * k];
                    r = ring[2 * k + 1];
                    ring_r.fetch_add(1);
                }
                if (enc.s16NumOfChannels == 2) { pcm[2 * i] = l; pcm[2 * i + 1] = r; }
                else pcm[i] = static_cast<int16_t>((l + r) / 2);
            }
            if (ring_space) xSemaphoreGive(ring_space);
            enc.pu8Packet = frames[nf];
            SBC_Encoder(&enc);
            flen = static_cast<uint8_t>(enc.u16PacketLength);
            ++nf;
            ++made;
            ++frames_out;
        }
        if (nf && flen && flen <= 64) {
            uint8_t blob[4 * 64];
            for (int i = 0; i < nf; ++i) std::memcpy(blob + i * flen, frames[i], flen);
            if (dump_sbc.exchange(false)) {
                char encoded[2 * sizeof blob + 1];
                hex(encoded, blob, static_cast<size_t>(nf) * flen);
                std::printf("A2DP SBC: frames %d bytes %u data %s\n", nf, flen, encoded);
            }
            radio_lab::push_sbc(blob, static_cast<uint8_t>(nf), flen);
        }
    }
    enc_task = nullptr;
    vTaskDelete(nullptr);
}

// ---- inquiry: find discoverable headphones (they are discoverable in pairing mode) --------------------------------
bool audio_class(uint32_t cod) { return ((cod >> 8) & 0x1Fu) == 0x04u; }  // major device class "audio/video"

void add_found(const br_fhs_t& f) {
    uint8_t a[6] = {static_cast<uint8_t>(f.lap), static_cast<uint8_t>(f.lap >> 8), static_cast<uint8_t>(f.lap >> 16), f.uap,
                    static_cast<uint8_t>(f.nap), static_cast<uint8_t>(f.nap >> 8)};
    const int nf = s->nfound;
    for (int i = 0; i < nf; ++i)
        if (!std::memcmp(s->found[i].addr, a, 6)) { ++s->found[i].hits; return; }
    if (nf >= kMaxFound) return;
    Found& n = s->found[nf];
    std::memcpy(n.addr, a, 6);
    n.cod = f.cod;
    n.hits = 1;
    s->nfound = nf + 1;  // published after the entry is complete (status() reads it from the UI task)
    std::printf("A2DP found %02X:%02X:%02X:%02X:%02X:%02X class %06lX%s\n", a[5], a[4], a[3], a[2], a[1], a[0],
                static_cast<unsigned long>(f.cod), audio_class(f.cod) ? " (audio)" : "");
}

void decode_capture(const uint8_t* d, size_t n) {
    static uint8_t head[16];
    static bool ready = false;
    if (!ready) { br_access_code_bits(BR_GIAC_LAP, 0, head); ready = true; }
    uint8_t air[96] = {};
    for (unsigned b = 0; b < 36; ++b) br_bit_put(air, b, br_bit_get(head, b));
    if (n > 64) n = 64;
    for (unsigned b = 0; b < 8 * n; ++b) br_bit_put(air, 36 + b, (d[b >> 3] >> (b & 7)) & 1);
    static br_pkt_t p;
    for (uint8_t c = 0; c < 64; ++c) {  // the responder whitens with its own clock: try every seed
        br_link_ctx_t ctx = {};
        ctx.lap = BR_GIAC_LAP;
        ctx.uap = 0x00;
        ctx.clk6 = c;
        ctx.sync_tolerance = 4;
        if (br_packet_decode(air, 36 + 8 * n, &ctx, &p) == BR_OK && p.hdr.type == BR_TYPE_FHS) {
            br_fhs_t f;
            br_fhs_unpack(p.payload, &f);
            add_found(f);
            return;
        }
    }
}

// Runs the inquiry train for up to `seconds`; stops after the first window that found an audio device (unless
// list_all). The C6 is left with DTM and hopping off (setup_radio configures paging from there).
bool run_inquiry(int seconds, bool list_all) {
    s->nfound = 0;
    s->pick = -1;
    uint8_t b[240];
    size_t n = sizeof b;
    if (lab("lab ping", b, &n) != 0 || n < 3) { set_status("C6 lab not answering"); return false; }
    if (b[2] != 0) { set_status("C6 image is on trial: confirm it first"); return false; }
    lab("lab exit");
    if (lab("lab quiet 1") != 0) { set_status("could not enter BR mode"); return false; }
    lab("lab dtmstats 0");
    lab("lab dtmstats 5");
    uint32_t aa, tail, crc;
    br_page_dtm_id(BR_GIAC_LAP, &aa, &tail, &crc);
    char line[160];
    std::snprintf(line, sizeof line, "lab dtmraw 2 %08lX %08lX 0 %06lX", static_cast<unsigned long>(aa),
                  static_cast<unsigned long>(tail), static_cast<unsigned long>(crc));
    if (lab(line) != 0) return false;
    uint8_t tx[32], rx[32];
    br_inquiry_table(tx, rx);
    for (int off = 0; off < 32; off += 16) {
        char th[33], rh[33];
        uint8_t t16[16], r16[16];
        for (int i = 0; i < 16; ++i) {
            const int x = off == 0 ? (24 + i) % 32 : (8 + i) % 32;
            t16[i] = tx[x];
            r16[i] = rx[x];
        }
        hex(th, t16, 16);
        hex(rh, r16, 16);
        std::snprintf(line, sizeof line, "lab dtmtrain load %d %s %s", off, th, rh);
        if (lab(line) != 0) return false;
    }
    lab("lab dtmtrain cfg 32 128");
    lab("lab page off");
    if (lab("lab dtmhop 2467 2456 625 rx 100 1050 1") != 0) return false;
    if (lab("lab dtm tx 19 37 0", nullptr, nullptr, 3000) != 0) return false;
    set_status("searching for headphones in pairing mode");
    const int64_t until = esp_timer_get_time() + static_cast<int64_t>(seconds) * 1000000;
    while (esp_timer_get_time() < until && !s->stop && s->pick < 0) {
        std::snprintf(line, sizeof line, "lab rawmatch 4000 %08lX 3 64 450", static_cast<unsigned long>(tail));
        const int rc = radio_lab::exec(line, nullptr, nullptr, 1500);
        if (rc != 1 && rc != 0) { vTaskDelay(pdMS_TO_TICKS(200)); continue; }  // 1 = started
        vTaskDelay(pdMS_TO_TICKS(4300));
        uint8_t r[64];
        size_t rn = 0;
        for (int t = 0; t < 20; ++t) {  // the window's result (busy until the worker finishes)
            rn = sizeof r;
            if (radio_lab::exec("lab rawmatch 0 0", r, &rn, 1000) == 0) break;
            rn = 0;
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        const uint32_t matches = rn >= 12 ? (r[8] | r[9] << 8 | r[10] << 16 | static_cast<uint32_t>(r[11]) << 24) : 0;
        if (matches) {
            uint8_t c[8];
            size_t cn = sizeof c;
            const int count = lab("lab rawdump", c, &cn) == 0 && cn ? c[0] : 0;
            for (int i = 0; i < count; ++i) {
                uint8_t d[80];
                size_t dn = sizeof d;
                char l2[32];
                std::snprintf(l2, sizeof l2, "lab rawdump %d", i);
                if (lab(l2, d, &dn) == 0 && dn >= 5) decode_capture(d + 5, std::min<size_t>(d[4], dn - 5));
            }
        }
        bool audio = false;
        for (int i = 0; i < s->nfound; ++i) audio |= audio_class(s->found[i].cod);
        if (audio && !list_all) break;
        if (s->pick < 0 && !s->stop)
            set_status("searching for headphones in pairing mode: %d found", s->nfound.load());
    }
    for (const char* l : {"lab dtm off", "lab dtmhop off", "lab dtmtrain cfg 0 1", "lab dtmraw 0 0 0"}) lab(l);
    return true;
}

// ---- session ----------------------------------------------------------------------------------------------------
int rx_early_us = 0;     // RX events open this much before the nominal +625 us (console: a2dp rxearly <us>)
int conn_ls44 = 700;     // connection RX window, raw ls44 (console: a2dp connls44 <v>). 700: an empty RX ends early
                         // enough to arm the next TX (1028 cost a second slot per missed reply); ~4 % more misses
int late_skip_us = 500;  // late-hook central slot skip threshold (console: a2dp lateskip <us>, 0 = off)

int tx_dbm = 0;  // console: a2dp txpwr <3..20> (0 = C6 default, +9 dBm)
// Modulation index. The C6 sends BLE GFSK (h ~0.5); BR receivers expect 0.28-0.35 and some (the Sennheiser HDB 630)
// lose ~1.5 % of payload bits at 0.5. Two BT baseband TX registers scale the deviation cleanly (HackRF run-length
// profile stays GFSK-shaped, carrier unchanged): 0x600A200C bits 8..11, a signed trim (-8..+7, bt_bb_v2_tx_set writes
// 1), and 0x600A20EC bits 24..31, part of the TX filter setup (0xEC). Trim -8 with 0x40 -> h 0.33 (BR nominal 0.32).
// 0x600A043C (DCO gain) is NOT usable: it detunes two-point modulation and scales the receiver too.
constexpr uint32_t kTrimReg = 0x600A200C, kFiltReg = 0x600A20EC;
uint32_t br_filt = 0x40;      // console: a2dp brmod <20EC byte 3 hex | 0 = BLE modulation>
uint32_t br_trim = 8;         // console: a2dp brtrim <0..15> (8 = -8)
bool mod_on = false;
uint32_t mod_trim_saved = 0, mod_filt_saved = 0;
uint32_t peek32(uint32_t addr, bool* ok) {
    char line[40];
    std::snprintf(line, sizeof line, "lab peek %08lX 1", static_cast<unsigned long>(addr));
    uint8_t b[8];
    size_t n = sizeof b;
    *ok = lab(line, b, &n) == 0 && n >= 4;
    return *ok ? (b[0] | b[1] << 8 | b[2] << 16 | static_cast<uint32_t>(b[3]) << 24) : 0;
}
void poke32(uint32_t addr, uint32_t v) {
    char line[48];
    std::snprintf(line, sizeof line, "lab poke %08lX %08lX", static_cast<unsigned long>(addr), static_cast<unsigned long>(v));
    lab(line);
}
void mod_apply() {
    if (!br_filt || mod_on) return;
    bool ok1 = false, ok2 = false;
    mod_trim_saved = peek32(kTrimReg, &ok1);
    mod_filt_saved = peek32(kFiltReg, &ok2);
    if (!ok1 || !ok2) { std::printf("A2DP modulation: registers not readable (C6 1.4.256+)\n"); return; }
    mod_on = true;
    poke32(kTrimReg, (mod_trim_saved & ~0xF00u) | ((br_trim & 0xFu) << 8));
    poke32(kFiltReg, (mod_filt_saved & 0x00FFFFFFu) | (br_filt << 24));
    std::printf("A2DP BR modulation: trim %lu, filter %02lX (was %08lX / %08lX)\n", static_cast<unsigned long>(br_trim),
                static_cast<unsigned long>(br_filt), static_cast<unsigned long>(mod_trim_saved),
                static_cast<unsigned long>(mod_filt_saved));
}
void mod_restore() {
    if (!mod_on) return;
    poke32(kTrimReg, mod_trim_saved);
    poke32(kFiltReg, mod_filt_saved);
    mod_on = false;
}
bool setup_radio() {
    const uint32_t plap = s->peer[0] | s->peer[1] << 8 | static_cast<uint32_t>(s->peer[2]) << 16;
    const uint8_t puap = s->peer[3];
    uint8_t b[240];
    size_t n = sizeof b;
    if (lab("lab ping", b, &n) != 0 || n < 3) { set_status("C6 lab not answering (firmware 1.4.246+?)"); return false; }
    if (b[2] != 0) { set_status("C6 image is on trial: confirm it first"); return false; }
    lab("lab exit");
    if (lab("lab quiet 1") != 0) { set_status("could not enter BR mode"); return false; }
    lab("lab dtmstats 0");
    lab("lab dtmstats 5");
    if (tx_dbm) {
        char pl[32];
        std::snprintf(pl, sizeof pl, "lab page txpwr %d", tx_dbm);
        if (lab(pl) != 0) std::printf("A2DP TX power %d dBm refused (C6 1.4.257+, 3/6/9/12/15/18/20)\n", tx_dbm);
    }
    uint32_t aa, tail, crc;
    br_page_dtm_id(plap, &aa, &tail, &crc);
    char line[160];
    std::snprintf(line, sizeof line, "lab dtmraw 2 %08lX %08lX 0 %06lX", static_cast<unsigned long>(aa),
                  static_cast<unsigned long>(tail), static_cast<unsigned long>(crc));
    if (lab(line) != 0) { set_status("dtmraw refused"); return false; }
    uint8_t tx[32], rx[32];
    br_page_table(plap, puap, tx, rx);
    for (int off = 0; off < 32; off += 16) {
        char th[33], rh[33];
        uint8_t t16[16], r16[16];
        for (int i = 0; i < 16; ++i) {
            const int x = off == 0 ? (24 + i) % 32 : (8 + i) % 32;  // train A: X 24..31,0..7; train B: 8..23
            t16[i] = tx[x];
            r16[i] = rx[x];
        }
        hex(th, t16, 16);
        hex(rh, r16, 16);
        std::snprintf(line, sizeof line, "lab dtmtrain load %d %s %s", off, th, rh);
        if (lab(line) != 0) return false;
    }
    lab("lab dtmtrain cfg 32 128");
    lab("lab page off");
    // The C6 sends the FHS as a BLE DTM frame whose length byte is bits 8..15 of the peer's access-code tail. Up to
    // 55 it fits one slot; 56..80 (e.g. a speaker with LAP E91187 -> 70) overlaps the peer's second response, so the
    // C6 enters the link without waiting for it (C6 1.4.247+, falls back to paging if the peer never answers).
    unsigned fhs_len = (tail >> 8) & 0xFFu;
    c6_shift = lab(use_shift ? "lab page shift 1" : "lab page shift 0") == 0;
    const bool shift = c6_shift && use_shift;
    if (shift) fhs_len = 46;  // the C6's own header: one-slot frame for every peer
    if (!pageable(fhs_len)) {
        set_status("these headphones need C6 firmware 1.4.253+ (FHS length %u)", fhs_len);
        return false;
    }
    if (fhs_len > 55 && lab("lab page r2skip 1") != 0) {
        set_status("these headphones need C6 firmware 1.4.247+ (long FHS)");
        return false;
    }
    if (fhs_len <= 55) lab("lab page r2skip 0");
    // The long FHS ends after the next event should be armed and the C6 scheduler slips a slot: start the RX after it
    // 200 us late (short window) and the first central TX 200 us early, keeping the first POLL at FHS + 1250 us.
    lab(fhs_len > 55 ? "lab page r2late 200" : "lab page r2late 0");
    std::printf("A2DP paging: FHS %s (length %u)\n", shift ? "shifted" : "in the sync tail", fhs_len);
    std::snprintf(line, sizeof line, "lab page %06lX %02X %06lX %02X 0000 5A020C 0", static_cast<unsigned long>(plap),
                  puap, static_cast<unsigned long>(kOwnLap), kOwnUap);
    if (lab(line) != 0) { set_status("page setup refused"); return false; }
    std::snprintf(line, sizeof line, "lab page conn %06lX %02X 65535 40 %d", static_cast<unsigned long>(kOwnLap), kOwnUap,
                  conn_ls44);
    if (lab(line) != 0) { set_status("connection setup refused"); return false; }
    if (lab("lab page fiforeset 1 1") != 0) { set_status("C6 has no ACL FIFO (needs 1.4.244+)"); return false; }
    // A hook that runs too late to arm the next central TX skips that slot instead of letting the scheduler slide
    // the TX into the peripheral's slot (C6 1.4.251; older firmware refuses the command and keeps the old behaviour).
    std::snprintf(line, sizeof line, "lab page lateskip %d", late_skip_us);
    lab(line);
    lab("lab page mask FF");
    lab("lab page det 2");
    if (fhs_len > 55) lab("lab page r2ls44 250");  // the delayed RX after a long FHS ends early enough for the POLL
    std::snprintf(line, sizeof line, "lab dtmhop 2467 2456 625 rx %d 700 1", rx_early_us);
    if (lab(line) != 0) return false;
    lab("lab dtmhop rxmax 4");
    if (lab("lab dtm tx 19 42 0", nullptr, nullptr, 3000) != 0) { set_status("DTM start failed"); return false; }
    mod_apply();  // BR modulation index for the whole session (page, FHS, connection)
    return true;
}

void cleanup_radio() {
    mod_restore();
    for (const char* l : {"lab page stream 0 0 1 0", "lab dtm off", "lab dtmhop off", "lab page off",
                          "lab dtmtrain cfg 0 1", "lab dtmraw 0 0 0", "lab dtmstats 2", "lab quiet 0"})
        lab(l);
    radio_lab::command("lab release");
}

void session_task(void*) {
    s->state = State::Setup;
    if (s->kind == Kind::Search || s->kind == Kind::SearchPair) {
        s->searching = true;
        const bool search = s->kind == Kind::Search;
        const bool ok = run_inquiry(search ? 40 : 30, search);
        s->searching = false;
        int pick = search ? s->pick.load() : -1;
        for (int i = 0; !search && i < s->nfound && pick < 0; ++i) if (audio_class(s->found[i].cod)) pick = i;
        if (!ok || pick < 0 || pick >= s->nfound || s->stop) {
            if (s->stop) set_status("search stopped");
            else if (ok && !s->nfound) set_status("no discoverable headphones found (pairing mode?)");
            else if (ok && search) set_status("found %d device(s): tap yours to pair", s->nfound.load());
            else if (ok) set_status("found %d device(s), none of them audio", s->nfound.load());
            cleanup_radio();
            s->state = State::Idle;
            task = nullptr;
            vTaskDelete(nullptr);
        }
        // the saved devices stay as they are until pairing succeeds (BR_A2DP_EV_PAIRED)
        std::memcpy(s->peer, s->found[pick].addr, 6);
        s->peer_cod = s->found[pick].cod;
        s->peer_valid = true;
        s->have_key = false;
        s->pair = true;
        set_status("pairing with %02X:%02X:%02X:%02X:%02X:%02X", s->peer[5], s->peer[4], s->peer[3], s->peer[2], s->peer[1],
                   s->peer[0]);
    }
    set_status("setting up the C6 radio");
    br_a2dp_cfg_t cfg = {};
    std::memcpy(cfg.own_addr, kOwnAddr, 6);
    std::memcpy(cfg.peer_addr, s->peer, 6);
    if (s->have_key) { std::memcpy(cfg.link_key, s->key, 16); cfg.have_key = 1; }
    cfg.pair = s->pair || !s->have_key;
    cfg.max_bitpool = kMaxBitpool;
    cfg.name = "Tab5";
    const br_a2dp_io_t io = {nullptr, io_send, io_set_enc, io_random, io_now, io_event};
    br_a2dp_init(&s->eng, &cfg, &io);
    bool ok = setup_radio();
    if (ok) {
        br_a2dp_connected(&s->eng);  // version/features/host connection requests wait in the FIFO for the link
        s->state = State::Paging;
        set_status("paging the headphones");
    }
    const int64_t t_start = esp_timer_get_time();
    int64_t q_from = 0;     // link-quality window: start time, then counters at its start
    uint32_t q_tx0 = 0, q_nr0 = 0;
    bool q_done = false, q_retry = false;
    int64_t bp_at = 0;     // adaptive bitpool: 1 s windows
    uint32_t bp_tx = 0, bp_nr = 0, bp_drops = 0;
    int bp_clean = 0;
    while (ok && !s->stop) {
        const Connq q = connq();
        if (!q.ok) { vTaskDelay(pdMS_TO_TICKS(20)); continue; }
        if (!s->connected) {
            if (q.state == 4) {
                s->connected = true;
                s->entries0 = q.entries;
                s->state = State::Connected;
                set_status("connected (page %.1f s)", (esp_timer_get_time() - t_start) / 1e6);

            } else if (esp_timer_get_time() - t_start > 60 * 1000000LL) {
                set_status("headphones did not answer the page (60 s): on? in range? another device connected?");
                break;
            } else {
                vTaskDelay(pdMS_TO_TICKS(50));
                continue;
            }
        }
        if (q.state != 4 || q.entries != s->entries0) {
            set_status("link lost");
            s->connected = false;
            break;
        }
        while (s->log_seen < q.count) {
            if (q.count - s->log_seen > 48) s->log_seen = q.count - 48;
            char line[40];
            std::snprintf(line, sizeof line, "lab page connlogx %lu", static_cast<unsigned long>(s->log_seen));
            uint8_t e[64];
            size_t en = sizeof e;
            ++s->log_seen;
            if (lab(line, e, &en) == 0) feed_log_entry(e, en);
        }
        if (s->state == State::Streaming && !q_done) {
            const int64_t now = esp_timer_get_time();
            if (!q_from) q_from = now + 1000000;  // let the stream settle for 1 s
            else if (!q_tx0 && now >= q_from) { q_tx0 = q.tx; q_nr0 = q.noreply; }
            else if (q_tx0 && now >= q_from + 2000000 && q.tx > q_tx0 + 500) {
                q_done = true;
                const uint32_t pct = 100 * (q.noreply - q_nr0) / (q.tx - q_tx0);
                const int max_pct = quality_max_pct.load();
                if (max_pct < 100 && static_cast<int>(pct) > max_pct && quality_left > 0 && !s->beep) {
                    set_status("link quality poor (%lu %% missed): reconnecting", static_cast<unsigned long>(pct));
                    q_retry = true;
                    break;
                }
                std::printf("A2DP link quality: %lu %% missed replies\n", static_cast<unsigned long>(pct));
            }
        }
        if (s->state == State::Streaming && !s->beep) {
            const int64_t now = esp_timer_get_time();
            if (!bp_at) { bp_at = now + 1000000; bp_tx = q.tx; bp_nr = q.noreply; bp_drops = q.sbc_drops; }
            else if (now >= bp_at && q.tx > bp_tx) {
                const uint32_t pct = 100 * (q.noreply - bp_nr) / (q.tx - bp_tx);
                const bool dropped = q.sbc_drops != bp_drops;
                const int bp = stream_bitpool.load();
                if ((pct > 15 || dropped) && bp > kMinBitpool) {
                    stream_bitpool = std::max(kMinBitpool, bp - 2);
                    bp_clean = 0;
                    std::printf("A2DP bitpool %d (link %lu %% missed%s)\n", stream_bitpool.load(), static_cast<unsigned long>(pct),
                                dropped ? ", frames dropped" : "");
                } else if (pct < 8 && !dropped && bp < kStreamBitpool && ++bp_clean >= 5) {
                    stream_bitpool = std::min<int>(kStreamBitpool, bp + 2);
                    bp_clean = 0;
                    std::printf("A2DP bitpool %d (link %lu %% missed)\n", stream_bitpool.load(), static_cast<unsigned long>(pct));
                } else if (pct >= 8 || dropped) {
                    bp_clean = 0;
                }
                bp_at = now + 1000000; bp_tx = q.tx; bp_nr = q.noreply; bp_drops = q.sbc_drops;
            }
        }
        br_a2dp_poll(&s->eng);
        if (s->state == State::Streaming && !s->beep && !enc_task)
            xTaskCreatePinnedToCore(encoder_task, "a2dp_sbc", 6144, nullptr, 7, &enc_task, 1);
        vTaskDelay(pdMS_TO_TICKS(s->state == State::Streaming ? 50 : 15));
    }
    const bool was_connected = s->connected;
    s->state = State::Stopping;
    while (enc_task) vTaskDelay(pdMS_TO_TICKS(10));
    if (was_connected) {
        lab("lab page stream 0 0 1 0");
        br_a2dp_detach(&s->eng, 0x13);
        for (int i = 0; i < 30; ++i) {  // until the detach is acknowledged
            const Connq q = connq();
            if (!q.ok || q.state != 4 || q.head == q.tail) break;
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        lab("lab page connend");
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    cleanup_radio();
    const bool lost = !std::strncmp(s->status, "link lost", 9) || !std::strncmp(s->status, "headphones did not", 18);
    if (std::strncmp(s->status, "failed", 6) && std::strncmp(s->status, "headphones", 10) && !lost && !q_retry)
        set_status("stopped");
    if (q_retry && !user_stop) {
        --quality_left;
        quality_at = esp_timer_get_time() + 2 * 1000000LL;
    }
    if (s->detach_reason == 0x0B && !user_stop && stale_left > 0) {
        --stale_left;
        quality_at = esp_timer_get_time() + 12 * 1000000LL;  // reuses the quality retry path (same headphones)
        set_status("headphones still hold the last link: retrying in 12 s");
    }
    if (auto_on && !user_stop && lost && was_connected) {  // unexpected loss of a working link: try again
        if (reconnect_left <= 0) reconnect_left = 3;
        reconnect_at = esp_timer_get_time() + 5 * 1000000LL;
    }
    s->state = State::Idle;
    if (ring_space) xSemaphoreGive(ring_space);
    task = nullptr;
    vTaskDelete(nullptr);
}

bool parse_hex(const char* t, uint8_t* out, size_t n) {
    if (!t || std::strlen(t) != 2 * n) return false;
    for (size_t i = 0; i < n; ++i) {
        char b[3] = {t[2 * i], t[2 * i + 1], 0};
        char* end = nullptr;
        out[i] = static_cast<uint8_t>(std::strtoul(b, &end, 16));
        if (*end) return false;
    }
    return true;
}

void ensure_session() {
    if (!saved_mu) saved_mu = xSemaphoreCreateMutex();
    if (s) return;
    s = static_cast<Session*>(heap_caps_calloc(1, sizeof(Session), MALLOC_CAP_SPIRAM));
    new (s) Session();
}

// addr: the device for Connect (nullptr = the default, saved[0]) and Pair.
bool start(Kind kind, const uint8_t* addr, bool beep = false) {
    ensure_session();
    if (task) { std::printf("A2DP busy (%s)\n", s->status); return false; }
    s->kind = kind;
    s->pair = kind != Kind::Connect;
    s->have_key = false;
    if (kind == Kind::Connect) {
        SavedLock l;
        const int i = addr ? saved_find(addr) : saved_n ? 0 : -1;
        if (i < 0) { set_status(saved_n ? "those headphones are not saved: pair them" : "no headphones saved: search and pair first"); return false; }
        std::memcpy(s->peer, saved_list[i].addr, 6);
        std::memcpy(s->key, saved_list[i].key, 16);
        s->have_key = saved_list[i].has_key;
        s->peer_cod = saved_list[i].cod;
        s->peer_valid = true;
    } else if (kind == Kind::Pair) {
        if (!addr) return false;
        std::memcpy(s->peer, addr, 6);
        s->peer_cod = 0;
        for (int i = 0; i < s->nfound; ++i)
            if (!std::memcmp(s->found[i].addr, addr, 6)) s->peer_cod = s->found[i].cod;
        s->peer_valid = true;
    }
    s->beep = beep;
    s->stop = false;
    s->connected = false;
    s->detach_reason = 0;
    s->log_seen = 0;
    s->enc_mode = 0;
    if (!ring) {
        ring = static_cast<int16_t*>(heap_caps_malloc(kRingFrames * 2 * sizeof(int16_t), MALLOC_CAP_SPIRAM));
        ring_space = xSemaphoreCreateBinary();
    }
    ring_w = 0;
    ring_r = 0;
    user_stop = false;
    if (!quality_start.exchange(false)) { quality_left = kQualityRetries; quality_at = 0; stale_left = 2; }
    xTaskCreatePinnedToCore(session_task, "a2dp_native", 8192, nullptr, 6, &task, 1);
    return true;
}

void supervisor_task(void*) {
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        if (!task && !user_stop && quality_at && esp_timer_get_time() >= quality_at) {
            quality_at = 0;
            std::printf("A2DP reconnecting for link quality (%d tries left)\n", quality_left.load());
            quality_start = true;
            if (!start(Kind::Connect, s->peer_valid ? s->peer : nullptr)) quality_start = false;
            continue;
        }
        if (!auto_on || user_stop || task || reconnect_left <= 0 || esp_timer_get_time() < reconnect_at) continue;
        --reconnect_left;
        std::printf("A2DP auto-reconnect (%d left)\n", reconnect_left.load());
        // after a link loss: the same headphones; after boot: the default
        if (!start(Kind::Connect, s->peer_valid ? s->peer : nullptr)) reconnect_left = 0;
        reconnect_at = esp_timer_get_time() + 15 * 1000000LL;
    }
}

}  // namespace

const char* device_kind(uint32_t cod) {
    if (!cod) return "AUDIO DEVICE";  // saved before classes were kept
    const unsigned major = (cod >> 8) & 0x1Fu, minor = (cod >> 2) & 0x3Fu;
    if (major == 0x04) {
        switch (minor) {
        case 1: return "HEADSET";
        case 2: return "HANDS-FREE";
        case 5: return "SPEAKER";
        case 6: return "HEADPHONES";
        case 7: return "PORTABLE AUDIO";
        case 8: return "CAR AUDIO";
        case 10: return "HI-FI AUDIO";
        case 15: return "TV";
        default: return "AUDIO";
        }
    }
    switch (major) {
    case 0x01: return "COMPUTER";
    case 0x02: return "PHONE";
    case 0x05: return "INPUT DEVICE";
    case 0x07: return "WEARABLE";
    default: return "OTHER DEVICE";
    }
}

Status status() {
    Status st;
    if (!s || !saved_mu) return st;
    st.running = task != nullptr;
    st.streaming = s->state == State::Streaming;
    st.searching = st.running && s->searching;
    st.auto_reconnect = auto_on;
    st.tone_hz = tone_hz;
    std::snprintf(st.text, sizeof st.text, "%s", s->status);
    if (st.running && s->peer_valid && !s->searching) fmt_addr(st.active, sizeof st.active, s->peer);
    {
        SavedLock l;
        st.saved_count = saved_n;
        for (int i = 0; i < saved_n; ++i) {
            Device& d = st.saved[i];
            fmt_addr(d.addr, sizeof d.addr, saved_list[i].addr);
            std::snprintf(d.name, sizeof d.name, "%s", saved_list[i].name);
            d.cod = saved_list[i].cod;
            d.paired = saved_list[i].has_key;
            d.saved = true;
        }
        st.have_peer = saved_n > 0;
        st.have_key = saved_n > 0 && saved_list[0].has_key;
        if (saved_n) fmt_addr(st.peer, sizeof st.peer, saved_list[0].addr);
        // last search: audio devices first, then the rest, each in the order found
        const int nf = s->nfound;
        for (int pass = 0; pass < 2; ++pass) {
            for (int i = 0; i < nf; ++i) {
                const Found& f = s->found[i];
                if (audio_class(f.cod) != (pass == 0)) continue;
                Device& d = st.found[st.found_count++];
                fmt_addr(d.addr, sizeof d.addr, f.addr);
                d.cod = f.cod;
                d.supported = pageable(fhs_len_for(f.addr));
                const int k = saved_find(f.addr);
                d.saved = k >= 0;
                d.paired = k >= 0 && saved_list[k].has_key;
                if (k >= 0) std::snprintf(d.name, sizeof d.name, "%s", saved_list[k].name);
            }
        }
    }
    return st;
}

void connect(bool pair) {
    if (!pair) { start(Kind::Connect, nullptr); return; }
    start(Kind::SearchPair, nullptr);  // find the first headphones in pairing mode and pair them
}

bool search() { return start(Kind::Search, nullptr); }

bool pair_found(const char* addr) {
    uint8_t a[6];
    if (!parse_addr(addr, a)) return false;
    ensure_session();
    if (task) {
        if (!s->searching) return false;
        for (int i = 0; i < s->nfound; ++i)
            if (!std::memcmp(s->found[i].addr, a, 6)) {
                s->pick = i;
                set_status("finishing the search window, then pairing with %s", addr);
                return true;
            }
        return false;
    }
    return start(Kind::Pair, a);
}

bool connect_saved(const char* addr) {
    uint8_t a[6];
    return parse_addr(addr, a) && start(Kind::Connect, a);
}

void forget_saved(const char* addr) {
    uint8_t a[6];
    if (!parse_addr(addr, a)) return;
    ensure_session();
    if (task && s->peer_valid && !std::memcmp(s->peer, a, 6)) disconnect();
    SavedLock l;
    const int i = saved_find(a);
    if (i < 0) return;
    std::memmove(saved_list + i, saved_list + i + 1, (saved_n - i - 1) * sizeof(Saved));
    --saved_n;
    saved_store();
    std::printf("A2DP forgot %s\n", addr);
}

void disconnect() {
    user_stop = true;
    reconnect_left = 0;
    quality_at = 0;
    if (task && s) s->stop = true;
}

void set_auto(bool on) {
    auto_on = on;
    const uint8_t v = on;
    nvs_put("auto", &v, 1);
}

void init() {
    ensure_session();
    saved_load();
    uint8_t v = 0;
    auto_on = nvs_get("auto", &v, 1) && v;
    if (auto_on) {  // one attempt after boot, once the C6 link is up
        reconnect_left = 1;
        reconnect_at = esp_timer_get_time() + 20 * 1000000LL;
    }
    xTaskCreate(supervisor_task, "a2dp_sup", 3072, nullptr, 2, nullptr);
}

bool ready() { return s && s->state == State::Streaming && !s->beep && !tone_hz; }
int rate() { return ready() ? static_cast<int>(s->stream.freq) : 0; }

size_t write_pcm(const int16_t* stereo, size_t frames, int timeout_ms) {
    if (!ready() || !ring) return 0;
    size_t done = 0;
    const int64_t until = esp_timer_get_time() + static_cast<int64_t>(timeout_ms) * 1000;
    const uint32_t max_level = s->stream.freq * 120 / 1000;
    while (done < frames && ready()) {
        if (ring_level() >= max_level || ring_level() >= kRingFrames - 1) {
            if (esp_timer_get_time() > until) break;
            xSemaphoreTake(ring_space, pdMS_TO_TICKS(10));
            continue;
        }
        const uint32_t k = ring_w.load() % kRingFrames;
        ring[2 * k] = stereo[2 * done];
        ring[2 * k + 1] = stereo[2 * done + 1];
        ring_w.fetch_add(1);
        const uint32_t a = static_cast<uint32_t>(std::abs(stereo[2 * done]));
        if (a > pcm_peak.load()) pcm_peak = a;
        ++done;
    }
    pcm_in += static_cast<uint32_t>(done);
    return done;
}

void command(const char* line) {
    ensure_session();
    char buf[160];
    std::snprintf(buf, sizeof buf, "%s", line);
    char* tok[6] = {};
    int n = 0;
    char* save = nullptr;
    for (char* t = strtok_r(buf, " \t", &save); t && n < 6; t = strtok_r(nullptr, " \t", &save)) tok[n++] = t;
    if (n < 2) { std::printf("A2DP usage: a2dp find | list | pair [<n found> | <addr>] | connect [<n saved>] [pair] [beep] | forget <n saved> | stop | status | auto <0|1> | peer <hex> | key <hex|clear> | tone <Hz|off>\n"); return; }
    const char* c = tok[1];
    if (!std::strcmp(c, "sbc") && n == 2) {
        if (!enc_task) std::printf("A2DP SBC: encoder is not running\n");
        else dump_sbc = true;
        return;
    }
    if (!std::strcmp(c, "checktx") && n == 5) {
        // Check a receive-only RF capture against our session cipher without exporting the key.
        // The capture must begin at the BR preamble; slot range compensates for USB capture latency.
        const size_t bytes = std::strlen(tok[4]) / 2;
        uint8_t air[52];
        if (!s->enc_mode || bytes < 20 || bytes > sizeof air || !parse_hex(tok[4], air, bytes)) {
            std::printf("A2DP checktx: need encrypted session and 20..52 captured bytes\n");
            return;
        }
        const uint32_t first = static_cast<uint32_t>(std::strtoul(tok[2], nullptr, 10));
        const uint32_t count = static_cast<uint32_t>(std::strtoul(tok[3], nullptr, 10));
        if (!count || count > 4096 || first > UINT32_MAX - count) {
            std::printf("A2DP checktx: slot range must be 1..4096\n");
            return;
        }
        static br_pkt_t captured;
        unsigned matches = 0;
        for (uint32_t slot = first; slot < first + count; ++slot) {
            if (((slot - first) & 31u) == 0) vTaskDelay(1);
            const uint32_t clk = 4u * (slot + 1u);
            br_link_ctx_t ctx = {};
            ctx.lap = kOwnLap; ctx.uap = kOwnUap;
            ctx.clk6 = static_cast<uint8_t>((clk >> 1) & 63u);
            ctx.sync_tolerance = 4;
            std::memset(&captured, 0, sizeof captured);
            const br_status_t header_rc = br_packet_decode(air, bytes * 8, &ctx, &captured);
            if (header_rc == BR_ERR_HEC || header_rc == BR_ERR_SYNC || captured.hdr.lt_addr != 1 ||
                (captured.hdr.type != BR_TYPE_DM1 && captured.hdr.type != BR_TYPE_DH1)) continue;
            br_e0_t e0;
            br_e0_init(&e0, s->kc, kOwnAddr, clk);
            ctx.e0 = &e0;
            std::memset(&captured, 0, sizeof captured);
            if (br_packet_decode(air, bytes * 8, &ctx, &captured) != BR_OK ||
                (captured.hdr.type != BR_TYPE_DM1 && captured.hdr.type != BR_TYPE_DH1)) continue;
            ++matches;
            std::printf("A2DP checktx: CRC PASS slot %lu type %u seq %u llid %u len %u\n",
                        static_cast<unsigned long>(slot), captured.hdr.type, captured.hdr.seqn,
                        captured.llid, static_cast<unsigned>(captured.len));
        }
        std::printf("A2DP checktx: %u matches in %lu slots\n", matches, static_cast<unsigned long>(count));
        return;
    }
    if (!std::strcmp(c, "connect")) {
        bool pair = false, beep = false;
        int idx = 0;
        for (int i = 2; i < n; ++i) {
            if (!std::strcmp(tok[i], "pair")) pair = true;
            else if (!std::strcmp(tok[i], "beep")) beep = true;
            else idx = std::atoi(tok[i]);
        }
        uint8_t a[6];
        {
            SavedLock l;
            if (idx < 0 || idx >= saved_n) { std::printf("A2DP no saved device %d (a2dp list)\n", idx); return; }
            std::memcpy(a, saved_list[idx].addr, 6);
        }
        start(pair ? Kind::Pair : Kind::Connect, a, beep);
        return;
    }
    if (!std::strcmp(c, "find") || !std::strcmp(c, "search")) { search(); return; }
    if (!std::strcmp(c, "pair") && n == 2) { start(Kind::SearchPair, nullptr); return; }
    if ((!std::strcmp(c, "pair") || !std::strcmp(c, "forget")) && n >= 3) {
        static Status st;  // ~2 KB: off the console task's stack
        st = status();
        const bool pair = !std::strcmp(c, "pair");
        const int count = pair ? st.found_count : st.saved_count;
        const Device* list = pair ? st.found : st.saved;
        const bool index = std::strlen(tok[2]) <= 2;
        const char* addr = index ? (std::atoi(tok[2]) >= 0 && std::atoi(tok[2]) < count ? list[std::atoi(tok[2])].addr : nullptr) : tok[2];
        if (!addr) { std::printf("A2DP no %s device %s (a2dp list)\n", pair ? "found" : "saved", tok[2]); return; }
        if (pair) std::printf("A2DP pair %s: %s\n", addr, pair_found(addr) ? "started" : "refused (busy or bad address)");
        else forget_saved(addr);
        return;
    }
    if (!std::strcmp(c, "list")) {
        static Status st;
        st = status();
        std::printf("A2DP saved (%d, most recent first):\n", st.saved_count);
        for (int i = 0; i < st.saved_count; ++i)
            std::printf("  %d  %s  %-14s %s%s\n", i, st.saved[i].addr, device_kind(st.saved[i].cod), st.saved[i].name,
                        st.saved[i].paired ? "" : " (no key)");
        std::printf("A2DP found in the last search (%d):\n", st.found_count);
        for (int i = 0; i < st.found_count; ++i)
            std::printf("  %d  %s  %06lX %s%s%s\n", i, st.found[i].addr, static_cast<unsigned long>(st.found[i].cod),
                        device_kind(st.found[i].cod), st.found[i].saved ? " (saved)" : "",
                        st.found[i].supported ? "" : " (not supported yet: long FHS)");
        return;
    }
    if (!std::strcmp(c, "auto") && n == 3) { set_auto(std::atoi(tok[2]) != 0); std::printf("A2DP auto-reconnect %d\n", auto_on.load()); return; }
    if (!std::strcmp(c, "stop")) {
        if (task) std::printf("A2DP stopping\n");
        else std::printf("A2DP not running\n");
        disconnect();
        return;
    }
    if (!std::strcmp(c, "status")) {
        static Status st;
        st = status();
        std::printf("A2DP %s | default %s | key %s | %d saved | tone %d Hz | pcm in %lu (peak %lu) "
                    "| sbc frames %lu | bitpool %d\n", s->status, st.have_peer ? st.peer : "(none)",
                    st.have_key ? "stored" : "none", st.saved_count, tone_hz, static_cast<unsigned long>(pcm_in.load()),
                    static_cast<unsigned long>(pcm_peak.load()), static_cast<unsigned long>(frames_out.load()),
                    stream_bitpool.load());
        return;
    }
    if (!std::strcmp(c, "peer") && n == 3) {
        uint8_t be[6], le[6];
        if (!parse_hex(tok[2], be, 6)) { std::printf("A2DP peer: 12 hex digits, MSB first (e.g. AABBCCDDEEFF)\n"); return; }
        for (int i = 0; i < 6; ++i) le[i] = be[5 - i];
        saved_upsert(le, nullptr, 0, nullptr);
        std::printf("A2DP peer saved as the default; pair with: a2dp connect pair\n");
        return;
    }
    if (!std::strcmp(c, "key") && n == 3) {
        SavedLock l;
        if (!saved_n) { std::printf("A2DP no saved device: a2dp peer <hex> first\n"); return; }
        if (!std::strcmp(tok[2], "clear")) {
            saved_list[0].has_key = 0;
            std::memset(saved_list[0].key, 0, 16);
            saved_store();
            std::printf("A2DP key cleared (default device)\n");
            return;
        }
        uint8_t be[16];
        if (!parse_hex(tok[2], be, 16)) { std::printf("A2DP key: 32 hex digits, MSB first\n"); return; }
        for (int i = 0; i < 16; ++i) saved_list[0].key[i] = be[15 - i];
        saved_list[0].has_key = 1;
        saved_store();
        std::printf("A2DP key stored (default device)\n");
        return;
    }
    if (!std::strcmp(c, "qmax") && n == 3) {
        quality_max_pct = std::max(-1, std::min(100, std::atoi(tok[2])));
        if (quality_max_pct >= 100) std::printf("A2DP automatic link-quality reconnect disabled\n");
        else std::printf("A2DP link-quality reconnect above %d %% missed replies\n", quality_max_pct.load());
        return;
    }
    if (!std::strcmp(c, "lateskip") && n == 3) {
        late_skip_us = std::max(0, std::min(1000, std::atoi(tok[2])));
        std::printf("A2DP late-hook slot skip %d us (next connect)\n", late_skip_us);
        return;
    }
    if (!std::strcmp(c, "connls44") && n == 3) {
        conn_ls44 = std::max(400, std::min(1100, std::atoi(tok[2])));
        std::printf("A2DP connection RX window ls44 %d (next connect)\n", conn_ls44);
        return;
    }
    if (!std::strcmp(c, "brmod") && n == 3) {
        br_filt = static_cast<uint32_t>(std::strtoul(tok[2], nullptr, 16)) & 0xFFu;
        std::printf("A2DP BR modulation filter byte %02lX (next connect; 0 = BLE h 0.5)\n", static_cast<unsigned long>(br_filt));
        return;
    }
    if (!std::strcmp(c, "brtrim") && n == 3) {
        br_trim = static_cast<uint32_t>(std::atoi(tok[2])) & 0xFu;
        std::printf("A2DP BR modulation trim %lu (next connect)\n", static_cast<unsigned long>(br_trim));
        return;
    }
    if (!std::strcmp(c, "frag") && n == 3) {
        l2_frag = std::max(0, std::min(27, std::atoi(tok[2])));
        std::printf("A2DP media DH1 fragments %d bytes (next stream)\n", l2_frag ? l2_frag : 27);
        return;
    }
    if (!std::strcmp(c, "txpwr") && n == 3) {
        tx_dbm = std::atoi(tok[2]);
        std::printf("A2DP TX power %d dBm (next connect)\n", tx_dbm);
        return;
    }
    if (!std::strcmp(c, "dm1") && n == 3) {
        l2_dm1 = std::atoi(tok[2]) != 0;
        std::printf("A2DP L2CAP in %s (next packets)\n", l2_dm1 ? "DM1 (FEC 2/3, 17 bytes)" : "DH1 (27 bytes)");
        return;
    }
    if (!std::strcmp(c, "diag")) {  // link counters since the connection started (C6 FIFO + scheduler)
        uint8_t b[240];
        size_t bn = sizeof b;
        if (lab("lab page connq", b, &bn) != 0 || bn < 165) { std::printf("A2DP diag: no connq\n"); return; }
        auto u32 = [&](size_t o) { return static_cast<unsigned long>(b[o] | b[o + 1] << 8 | b[o + 2] << 16 | static_cast<uint32_t>(b[o + 3]) << 24); };
        std::printf("A2DP diag: tx %lu noreply %lu hecfail %lu | fifo tx %lu retx %lu acked %lu | rx nak %lu ack %lu dup %lu"
                    " verified %lu verify_fail %lu\n", u32(14), u32(93 + 48), u32(93 + 32), u32(93 + 8), u32(93 + 12),
                    u32(93 + 16), u32(93 + 24), u32(93 + 28), u32(93 + 44), u32(93 + 36), u32(93 + 40));
        if (bn >= 227)
            std::printf("A2DP diag: payload flow %s, STOP %lu GO %lu, withheld TX slots %lu\n",
                        b[226] ? "GO" : "STOP", u32(214), u32(218), u32(222));
        bn = sizeof b;
        if (lab("lab page chanq", b, &bn) == 0 && bn >= 234) {
            std::printf("A2DP diag: replies to our data %lu: ARQN=1 %lu, FLOW=stop %lu, types", u32(158), u32(162), u32(166));
            for (int i = 0; i < 16; ++i) if (u32(170 + 4 * i)) std::printf(" %d:%lu", i, u32(170 + 4 * i));
            std::printf("\n");
        }
        bn = sizeof b;
        if (lab("lab page diag", b, &bn) == 0 && bn >= 213) {
            std::printf("A2DP diag: late skips %lu | hook latency after TX (100 us bins):", u32(209));
            for (int i = 0; i < 16; ++i) std::printf(" %lu", u32(4 * i));
            std::printf(" | after RX:");
            for (int i = 0; i < 16; ++i) std::printf(" %lu", u32(64 + 4 * i));
            std::printf("\n");
        }
        return;
    }
    if (!std::strcmp(c, "chans")) {  // per-channel missed replies of the links so far (C6 1.4.254; "chans 0" resets)
        if (n == 3) { lab("lab page chanq 0"); std::printf("A2DP channel stats reset\n"); return; }
        uint8_t b[200];
        size_t bn = sizeof b;
        if (lab("lab page chanq", b, &bn) != 0 || bn < 158) { std::printf("A2DP chans: needs C6 1.4.254\n"); return; }
        for (int half = 0; half < 2; ++half) {
            std::printf("A2DP missed %% by %s channel (2402+ch MHz, -- = unused):\n", half ? "reply" : "our TX");
            for (int row = 0; row < 79; row += 20) {
                char line[160];
                int o = std::snprintf(line, sizeof line, "A2DP  %2d:", row);
                for (int ch = row; ch < row + 20 && ch < 79; ++ch) {
                    const uint8_t v = b[half * 79 + ch];
                    o += v == 255 ? std::snprintf(line + o, sizeof line - o, "  --") : std::snprintf(line + o, sizeof line - o, " %3u", v);
                }
                std::printf("%s\n", line);
            }
        }
        return;
    }
    if (!std::strcmp(c, "shift") && n == 3) {
        use_shift = std::atoi(tok[2]) != 0;
        std::printf("A2DP shifted FHS %s (next connect)\n", use_shift ? "on (C6 1.4.253+)" : "off");
        return;
    }
    if (!std::strcmp(c, "rxearly") && n == 3) {
        rx_early_us = std::max(0, std::min(150, std::atoi(tok[2])));
        std::printf("A2DP RX early %d us (next connect)\n", rx_early_us);
        return;
    }
    if (!std::strcmp(c, "tone") && n == 3) {
        tone_hz = !std::strcmp(tok[2], "off") ? 0 : std::atoi(tok[2]);
        std::printf("A2DP test tone %d Hz\n", tone_hz);
        return;
    }
    if (!std::strcmp(c, "verbose") && n == 3) {
        verbose = std::atoi(tok[2]) != 0;
        radio_lab::set_verbose(false);
        return;
    }
    std::printf("A2DP unknown command\n");
}

}  // namespace a2dp_native
