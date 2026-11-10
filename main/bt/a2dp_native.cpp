#include "bt/a2dp_native.h"

#include <algorithm>
#include <atomic>
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

struct Found {
    uint8_t addr[6];  // LSB first
    uint32_t cod;
    int hits;
};

struct Session {
    bool pair = false, beep = false, find = false, find_only = false;
    Found found[8];
    int nfound = 0;
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
    br_a2dp_stream_t stream = {};
    char status[96] = "idle";
};

Session* s = nullptr;
TaskHandle_t task = nullptr, enc_task = nullptr;
// auto-reconnect: attempts left and when the next one may start (us); user_stop cancels them
std::atomic<int> reconnect_left{0};
std::atomic<int64_t> reconnect_at{0};
// Link-quality retry: some peers (the Galaxy projector speaker) time-share their radio with their own BLE links, and
// each connection lands at a random phase to them: ~2 % or 25-40 % missed replies for the life of the link. After
// streaming starts we measure, and reconnect from a bad phase (each try is a fresh roll).
constexpr int kQualityRetries = 3;
std::atomic<int> quality_max_pct{12};  // console: a2dp qmax <pct> (test: 0 forces the retries)
std::atomic<int> quality_left{0};
std::atomic<int64_t> quality_at{0};
std::atomic<bool> quality_start{false};
// Adaptive bitpool: with one-slot packets, bitpool 14 needs ~69 % of all central slots. When the peer misses replies
// (a receiver sharing its radio with its own BLE links: 25-40 % for minutes) the stream would fall behind and break up,
// so the encoder steps down (14 -> 12 -> 10 -> 8, ~55 % of slots at 10) and back up after 5 clean seconds.
constexpr int kMinBitpool = 8;
std::atomic<int> stream_bitpool{14};
std::atomic<bool> auto_on{false}, user_stop{false};
// NVS state cached for status() (the UI polls it)
bool cache_valid = false, cache_peer = false, cache_key = false;
uint8_t cache_peer_addr[6] = {};
bool verbose = false;
int tone_hz = 0;
Device discovered[8];
size_t discovered_count = 0;
portMUX_TYPE discovery_mux = portMUX_INITIALIZER_UNLOCKED;

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
    cache_valid = false;
    nvs_handle_t h;
    if (nvs_open(kNs, NVS_READWRITE, &h) != ESP_OK) return;
    if (v) nvs_set_blob(h, k, v, n);
    else nvs_erase_key(h, k);
    nvs_commit(h);
    nvs_close(h);
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
void io_send(void*, uint8_t llid, const uint8_t* d, size_t n) {
    if (llid == 3) {
        fifo_push(3, 3, d, n);  // LMP in DM1
        return;
    }
    for (size_t off = 0; off < n; off += 27) fifo_push(4, off ? 1 : 2, d + off, n - off < 27 ? n - off : 27);
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
        nvs_put("key", s->key, 16);
        set_status("paired; link key stored");
        break;
    case BR_A2DP_EV_ENCRYPTED: set_status("encrypted"); break;
    case BR_A2DP_EV_STREAMING: {
        s->stream = *static_cast<const br_a2dp_stream_t*>(arg);
        char line[64];
        if (s->beep) std::snprintf(line, sizeof line, "lab page stream 1 %04X %d 0", s->stream.media_cid, kFramesPerPacket);
        else std::snprintf(line, sizeof line, "lab page stream 2 %04X %d 0", s->stream.media_cid, kFramesPerPacket);
        lab(line);
        s->state = State::Streaming;
        reconnect_left = 0;
        set_status("streaming SBC %lu Hz, bitpool <= %u%s", static_cast<unsigned long>(s->stream.freq),
                   s->stream.max_bitpool, s->beep ? " (C6 beep test)" : "");
        break;
    }
    case BR_A2DP_EV_FAILED:
        set_status("failed: %s", static_cast<const char*>(arg));
        s->stop = true;
        break;
    case BR_A2DP_EV_DETACHED:
        set_status("headphones disconnected (0x%02X)", *static_cast<const uint8_t*>(arg));
        s->stop = true;
        break;
    case BR_A2DP_EV_SUSPENDED:
        set_status("headphones suspended the stream");
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
    for (int i = 0; i < s->nfound; ++i)
        if (!std::memcmp(s->found[i].addr, a, 6)) { ++s->found[i].hits; return; }
    if (s->nfound >= 8) return;
    Found& n = s->found[s->nfound++];
    std::memcpy(n.addr, a, 6);
    n.cod = f.cod;
    n.hits = 1;
    portENTER_CRITICAL(&discovery_mux);
    Device& d = discovered[discovered_count++];
    std::snprintf(d.address, sizeof d.address, "%02X:%02X:%02X:%02X:%02X:%02X", a[5], a[4], a[3], a[2], a[1], a[0]);
    d.audio = audio_class(f.cod);
    portEXIT_CRITICAL(&discovery_mux);
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
    portENTER_CRITICAL(&discovery_mux);
    discovered_count = 0;
    portEXIT_CRITICAL(&discovery_mux);
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
    while (esp_timer_get_time() < until && !s->stop) {
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
    }
    for (const char* l : {"lab dtm off", "lab dtmhop off", "lab dtmtrain cfg 0 1", "lab dtmraw 0 0 0"}) lab(l);
    return true;
}

// ---- session ----------------------------------------------------------------------------------------------------
int rx_early_us = 0;     // RX events open this much before the nominal +625 us (console: a2dp rxearly <us>)
int conn_ls44 = 700;     // connection RX window, raw ls44 (console: a2dp connls44 <v>). 700: an empty RX ends early
                         // enough to arm the next TX (1028 cost a second slot per missed reply); ~4 % more misses
int late_skip_us = 500;  // late-hook central slot skip threshold (console: a2dp lateskip <us>, 0 = off)

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
    const unsigned fhs_len = (tail >> 8) & 0xFFu;
    if (fhs_len > 55 && lab("lab page r2skip 1") != 0) {
        set_status("these headphones need C6 firmware 1.4.247+ (long FHS)");
        return false;
    }
    if (fhs_len <= 55) lab("lab page r2skip 0");
    // The long FHS ends after the next event should be armed and the C6 scheduler slips a slot: start the RX after it
    // 200 us late (short window) and the first central TX 200 us early, keeping the first POLL at FHS + 1250 us.
    lab(fhs_len > 55 ? "lab page r2late 200" : "lab page r2late 0");
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
    return true;
}

void cleanup_radio() {
    for (const char* l : {"lab page stream 0 0 1 0", "lab dtm off", "lab dtmhop off", "lab page off",
                          "lab dtmtrain cfg 0 1", "lab dtmraw 0 0 0", "lab dtmstats 2", "lab quiet 0"})
        lab(l);
    radio_lab::command("lab release");
}

void session_task(void*) {
    s->state = State::Setup;
    if (s->find) {
        const bool ok = run_inquiry(s->find_only ? 20 : 30, s->find_only);
        int pick = -1;
        for (int i = 0; i < s->nfound && pick < 0; ++i) if (audio_class(s->found[i].cod)) pick = i;
        if (s->find_only || !ok || pick < 0) {
            if (ok) set_status(s->nfound ? "found %d device(s), %s" : "no discoverable headphones found (pairing mode?)",
                               s->nfound, pick < 0 ? "none of them audio" : "see the list above");
            cleanup_radio();
            s->state = State::Idle;
            task = nullptr;
            vTaskDelete(nullptr);
        }
        std::memcpy(s->peer, s->found[pick].addr, 6);
        nvs_put("peer", s->peer, 6);
        nvs_put("key", nullptr, 0);
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
                if (static_cast<int>(pct) > quality_max_pct && quality_left > 0 && !s->beep) {
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
    if (s) return;
    s = static_cast<Session*>(heap_caps_calloc(1, sizeof(Session), MALLOC_CAP_SPIRAM));
    new (s) Session();
}

bool start(bool pair, bool beep, bool find = false, bool find_only = false) {
    ensure_session();
    if (task) { std::printf("A2DP busy (%s)\n", s->status); return false; }
    s->find = find;
    s->find_only = find_only;
    if (!find && !nvs_get("peer", s->peer, 6)) { set_status("no headphones set: pair first"); return false; }
    s->have_key = nvs_get("key", s->key, 16);
    s->pair = pair;
    s->beep = beep;
    s->stop = false;
    s->connected = false;
    s->log_seen = 0;
    s->enc_mode = 0;
    if (!ring) {
        ring = static_cast<int16_t*>(heap_caps_malloc(kRingFrames * 2 * sizeof(int16_t), MALLOC_CAP_SPIRAM));
        ring_space = xSemaphoreCreateBinary();
    }
    ring_w = 0;
    ring_r = 0;
    user_stop = false;
    if (!quality_start.exchange(false)) { quality_left = kQualityRetries; quality_at = 0; }
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
            if (!start(false, false)) quality_start = false;
            continue;
        }
        if (!auto_on || user_stop || task || reconnect_left <= 0 || esp_timer_get_time() < reconnect_at) continue;
        --reconnect_left;
        std::printf("A2DP auto-reconnect (%d left)\n", reconnect_left.load());
        if (!start(false, false)) reconnect_left = 0;
        reconnect_at = esp_timer_get_time() + 15 * 1000000LL;
    }
}

}  // namespace

size_t devices(Device* out, size_t capacity) {
    if (!out) return 0;
    portENTER_CRITICAL(&discovery_mux);
    const size_t count = std::min(capacity, discovered_count);
    std::memcpy(out, discovered, count * sizeof(Device));
    portEXIT_CRITICAL(&discovery_mux);
    return count;
}

Status status() {
    Status st;
    if (!s) return st;
    st.running = task != nullptr;
    st.streaming = s->state == State::Streaming;
    if (!cache_valid) {
        uint8_t key[16];
        cache_peer = nvs_get("peer", cache_peer_addr, 6);
        cache_key = nvs_get("key", key, 16);
        cache_valid = true;
    }
    const uint8_t* peer = cache_peer_addr;
    st.have_peer = cache_peer;
    st.have_key = cache_key;
    st.auto_reconnect = auto_on;
    st.tone_hz = tone_hz;
    std::snprintf(st.text, sizeof st.text, "%s", s->status);
    if (st.have_peer)
        std::snprintf(st.peer, sizeof st.peer, "%02X:%02X:%02X:%02X:%02X:%02X", peer[5], peer[4], peer[3], peer[2], peer[1], peer[0]);
    return st;
}

void connect(bool pair) { start(pair, false, pair, false); }  // pairing = find the headphones in pairing mode first

void disconnect() {
    user_stop = true;
    reconnect_left = 0;
    if (task && s) s->stop = true;
}

void set_auto(bool on) {
    auto_on = on;
    const uint8_t v = on;
    nvs_put("auto", &v, 1);
}

void init() {
    ensure_session();
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
    for (char* t = std::strtok(buf, " \t"); t && n < 6; t = std::strtok(nullptr, " \t")) tok[n++] = t;
    if (n < 2) { std::printf("A2DP usage: a2dp find | pair | connect [pair] [beep] | stop | status | auto <0|1> | peer <hex> | key <hex|clear> | tone <Hz|off>\n"); return; }
    const char* c = tok[1];
    if (!std::strcmp(c, "connect")) {
        bool pair = false, beep = false;
        for (int i = 2; i < n; ++i) {
            if (!std::strcmp(tok[i], "pair")) pair = true;
            if (!std::strcmp(tok[i], "beep")) beep = true;
        }
        start(pair, beep);
        return;
    }
    if (!std::strcmp(c, "find")) { start(false, false, true, true); return; }
    if (!std::strcmp(c, "pair")) { start(true, false, true, false); return; }
    if (!std::strcmp(c, "auto") && n == 3) { set_auto(std::atoi(tok[2]) != 0); std::printf("A2DP auto-reconnect %d\n", auto_on.load()); return; }
    if (!std::strcmp(c, "stop")) {
        if (task) std::printf("A2DP stopping\n");
        else std::printf("A2DP not running\n");
        disconnect();
        return;
    }
    if (!std::strcmp(c, "status")) {
        uint8_t peer[6];
        const bool hp = nvs_get("peer", peer, 6);
        uint8_t k[16];
        const bool hk = nvs_get("key", k, 16);
        std::printf("A2DP %s | peer %s%02X:%02X:%02X:%02X:%02X:%02X | key %s | tone %d Hz | pcm in %lu (peak %lu) "
                    "| sbc frames %lu | bitpool %d\n", s->status, hp ? "" : "(none) ", peer[5], peer[4], peer[3], peer[2], peer[1],
                    peer[0], hk ? "stored" : "none", tone_hz, static_cast<unsigned long>(pcm_in.load()),
                    static_cast<unsigned long>(pcm_peak.load()), static_cast<unsigned long>(frames_out.load()),
                    stream_bitpool.load());
        return;
    }
    if (!std::strcmp(c, "peer") && n == 3) {
        uint8_t be[6], le[6];
        if (!parse_hex(tok[2], be, 6)) { std::printf("A2DP peer: 12 hex digits, MSB first (e.g. AABBCCDDEEFF)\n"); return; }
        for (int i = 0; i < 6; ++i) le[i] = be[5 - i];
        nvs_put("peer", le, 6);
        nvs_put("key", nullptr, 0);  // a new peer needs pairing
        std::printf("A2DP peer set; pair with: a2dp connect pair\n");
        return;
    }
    if (!std::strcmp(c, "key") && n == 3) {
        if (!std::strcmp(tok[2], "clear")) { nvs_put("key", nullptr, 0); std::printf("A2DP key cleared\n"); return; }
        uint8_t be[16], le[16];
        if (!parse_hex(tok[2], be, 16)) { std::printf("A2DP key: 32 hex digits, MSB first\n"); return; }
        for (int i = 0; i < 16; ++i) le[i] = be[15 - i];
        nvs_put("key", le, 16);
        std::printf("A2DP key stored\n");
        return;
    }
    if (!std::strcmp(c, "qmax") && n == 3) {
        quality_max_pct = std::max(-1, std::min(100, std::atoi(tok[2])));
        std::printf("A2DP link-quality reconnect above %d %% missed replies\n", quality_max_pct.load());
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
