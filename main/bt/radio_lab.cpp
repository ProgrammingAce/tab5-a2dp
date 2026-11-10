#include "bt/radio_lab.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "bt/bt_owner.h"
#include "esp_hosted_cyberdeck.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

namespace radio_lab {
namespace {

constexpr const char* TAG = "radio_lab";
constexpr uint16_t kOpcode = 0xFFE0;
constexpr uint8_t kMagic[4] = {'B', 'R', 'L', '1'};

enum Sub : uint8_t {
    Ping = 0x00, EnterBr = 0x01, ExitBr = 0x02, Tone = 0x03, Stop = 0x04, Hop = 0x05, RxCount = 0x06,
    Peek = 0x07, Poke = 0x08, Call = 0x09, RxFreq = 0x0A, BleTx = 0x0B, Force = 0x0C, ChanMap = 0x0D, ScanAA = 0x0E, Reboot = 0x0F, IrqStats = 0x10, ScanFlags = 0x11, DtmStats = 0x12, ScanRaw = 0x13, RawMatch = 0x14, Quiet = 0x15, DtmRaw = 0x16, DtmHop = 0x17, RawDump = 0x18, DtmTrain = 0x19, Page = 0x1A,
};

// Scan counting (gate G2 via the real BLE controller): legacy advertising reports, all and for the target address.
struct ScanCount {
    uint32_t all = 0, target = 0;
    int32_t rssi_sum = 0;
    uint8_t addr[6] = {0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xC1};  // C1:A2:A3:A4:A5:A6 (Vol 6 Part C sample), LSB first
    uint16_t family[256] = {};  // reports from C1:A2:A3:A4:A5:xx by xx (whitening-sweep packets from ble_tx.py)
    bool on = false;
    bool extended = false;
} scan;

esp_hosted_cyberdeck_hci_rx_cb_t saved_cb = nullptr;

// Synchronous use by the native A2DP host (exec/push_sbc): the sub the waiting caller expects (0x100 = DTM HCI
// command complete), its reply, and whether replies to it are printed.
SemaphoreHandle_t exec_mutex = nullptr, exec_done = nullptr;
volatile int exec_wait = -1;
volatile bool exec_armed = false, exec_quiet = true, exec_sent = false;
uint8_t exec_buf[255];
volatile size_t exec_len = 0;
volatile int exec_status = 0;

// true if this reply completed a pending exec() (copied); the caller then skips printing when quiet
bool exec_capture(int key, uint8_t status, const uint8_t* d, size_t n) {
    if (exec_wait != key) return false;
    exec_len = n > sizeof(exec_buf) ? sizeof(exec_buf) : n;
    if (n) std::memcpy(exec_buf, d, exec_len);
    exec_status = status;
    exec_wait = -1;
    xSemaphoreGive(exec_done);
    return exec_quiet;
}
bool have_controller = false;
bool dtm_active = false;

const char* sub_name(uint8_t s) {
    switch (s) {
        case Ping: return "ping";
        case EnterBr: return "enter";
        case ExitBr: return "exit";
        case Tone: return "tone";
        case Stop: return "stop";
        case Hop: return "hop";
        case RxCount: return "rx";
        case Peek: return "peek";
        case Poke: return "poke";
        case Call: return "call";
        case RxFreq: return "rxfreq";
        case BleTx: return "bletx";
        case Force: return "force";
        case ChanMap: return "chanmap";
        case ScanAA: return "scanaa";
        case Reboot: return "reboot";
        case IrqStats: return "irq";
        case ScanFlags: return "scanflags";
        case DtmStats: return "dtmstats";
        case ScanRaw: return "scanraw";
        case RawMatch: return "rawmatch";
        case Quiet: return "quiet";
        case DtmRaw: return "dtmraw";
        case DtmHop: return "dtmhop";
        case RawDump: return "rawdump";
        case DtmTrain: return "dtmtrain";
        case Page: return "page";
        default: return "?";
    }
}

uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t rd32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

// Decoded fields for the replies/events that carry measurements; everything also gets a hex dump.
void print_result(const char* kind, uint8_t sub, uint8_t status, const uint8_t* d, size_t n) {
    char hex[2 * 240 + 1];
    size_t h = 0;
    for (size_t i = 0; i < n && i < 240; ++i) h += std::snprintf(hex + h, sizeof(hex) - h, "%02x", d[i]);
    hex[h] = '\0';
    char extra[192] = "";
    if (std::strcmp(kind, "event") == 0 && sub == Hop && n >= 10)
        std::snprintf(extra, sizeof(extra), " calls=%u call_us_min=%u call_us_max=%u call_us_avg=%u late=%u", rd16(d),
                      rd16(d + 2), rd16(d + 4), rd16(d + 6), rd16(d + 8));
    else if (std::strcmp(kind, "event") == 0 && sub == RxCount && n >= 13)
        std::snprintf(extra, sizeof(extra), " total=%lu correct=%lu rssi=%d rx_freq=%ld",
                      static_cast<unsigned long>(rd32(d)), static_cast<unsigned long>(rd32(d + 4)),
                      static_cast<int8_t>(d[8]), static_cast<long>(static_cast<int32_t>(rd32(d + 9))));
    else if (sub == Ping && n >= 3)
        std::snprintf(extra, sizeof(extra), " lab_version=%u br_mode=%u in_trial=%u fw=%.*s", d[0], d[1], d[2],
                      static_cast<int>(n - 3), reinterpret_cast<const char*>(d + 3));
    else if ((sub == RxFreq || sub == Call) && n >= 4)
        std::snprintf(extra, sizeof(extra), " value=%ld", static_cast<long>(static_cast<int32_t>(rd32(d))));
    if (sub == ScanAA && n >= 31)
        std::snprintf(extra, sizeof(extra),
                      " enabled=%u aa=%08lx resets=%lu applied=%lu last=%08lx rx=%lu buffers=%lu rx_status=%08lx header=%04x",
                      d[0], static_cast<unsigned long>(rd32(d + 1)),
                      static_cast<unsigned long>(rd32(d + 5)), static_cast<unsigned long>(rd32(d + 9)),
                      static_cast<unsigned long>(rd32(d + 13)), static_cast<unsigned long>(rd32(d + 17)),
                      static_cast<unsigned long>(rd32(d + 21)), static_cast<unsigned long>(rd32(d + 25)), rd16(d + 29));
    std::printf("LAB %s %s status=0x%02x%s data=%s\n", kind, sub_name(sub), status, extra, hex);
}

// Raw HCI receive callback while the lab owns the controller (SDIO receive thread).
void on_hci_rx(const uint8_t* p, uint32_t len) {
    if (len >= 5 && p[0] == 0x04 && p[1] == 0x3E && p[3] == 0x02) {  // LE Advertising Report
        const uint8_t num = p[4];
        size_t off = 5;
        for (uint8_t i = 0; i < num && off + 9 <= len; ++i) {
            const uint8_t* r = p + off;  // event type, addr type, addr[6], data len, data..., rssi
            const uint8_t dlen = r[8];
            if (off + 9 + dlen + 1 > len) break;
            ++scan.all;
            if (std::memcmp(r + 3, scan.addr + 1, 5) == 0 && scan.family[r[2]] < 0xFFFF) ++scan.family[r[2]];
            if (std::memcmp(r + 2, scan.addr, 6) == 0) {
                ++scan.target;
                scan.rssi_sum += static_cast<int8_t>(r[9 + dlen]);
            }
            off += 9 + dlen + 1;
        }
        return;
    }
    if (len >= 5 && p[0] == 0x04 && p[1] == 0x3E && p[3] == 0x0D) {
        scan.all += p[4];  // Extended Advertising Report count; raw lab ignores peer details.
        return;
    }
    // IDF nimble/hci_common.h: LE RX Test OCF 0x1D, LE Test End OCF 0x1F.
    if (len >= 7 && p[0] == 0x04 && p[1] == 0x0E && (rd16(p + 4) == 0x201D || rd16(p + 4) == 0x201E)) {
        dtm_active = p[6] == 0;
        if (exec_capture(0x100, p[6], nullptr, 0)) return;
        std::printf("LAB reply dtm status=0x%02x on=%u\n", p[6], dtm_active);
        return;
    }
    if (len >= 7 && p[0] == 0x04 && p[1] == 0x0E && rd16(p + 4) == 0x201F) {
        if (p[6] == 0) dtm_active = false;
        if (exec_capture(0x100, p[6], nullptr, 0)) return;
        if (len >= 9)
            std::printf("LAB reply dtm status=0x%02x on=0 packets=%u\n", p[6], rd16(p + 7));
        else std::printf("LAB reply dtm status=0x%02x on=0\n", p[6]);
        return;
    }
    if (len >= 7 && p[0] == 0x04 && p[1] == 0x0E && rd16(p + 4) != kOpcode && (rd16(p + 4) >> 10) == 0x08) {
        std::printf("LAB hci le_command opcode=0x%04x status=0x%02x\n", rd16(p + 4), p[6]);
        return;
    }
    if (len >= 5 && p[0] == 0x04 && p[1] == 0x0F) {  // Command Status
        std::printf("LAB hci command_status opcode=0x%04x status=0x%02x\n", rd16(p + 4), p[2 + 1]);
        return;
    }
    if (len >= 4 && p[0] == 0x04 && p[1] == 0x3E) {  // other LE meta events (e.g. extended reports)
        std::printf("LAB hci le_meta sub=0x%02x len=%lu\n", p[3], static_cast<unsigned long>(len));
        return;
    }
    if (len >= 9 && p[0] == 0x04 && p[1] == 0x0E && rd16(p + 4) == kOpcode) {
        if (exec_capture(p[8], p[6], p + 9, len - 9)) return;
        print_result("reply", p[8], p[6], p + 9, len - 9);
    } else if (len >= 7 && p[0] == 0x04 && p[1] == 0x0E) {
        std::printf("LAB hci command_complete opcode=0x%04x status=0x%02x\n", rd16(p + 4), p[6]);
    } else if (len >= 9 && p[0] == 0x04 && p[1] == 0xFF && std::memcmp(p + 3, kMagic, 4) == 0) {
        print_result("event", p[7], p[8], p + 9, len - 9);
    } else {
        std::printf("LAB hci other type=0x%02x len=%lu\n", p[0], static_cast<unsigned long>(len));
    }
}

void send_raw(uint8_t sub, const uint8_t* args, size_t n) {
    uint8_t pkt[4 + 5 + 250];
    if (n > 250) return;
    pkt[0] = 0x01;
    pkt[1] = static_cast<uint8_t>(kOpcode);
    pkt[2] = static_cast<uint8_t>(kOpcode >> 8);
    pkt[3] = static_cast<uint8_t>(5 + n);
    std::memcpy(pkt + 4, kMagic, 4);
    pkt[8] = sub;
    if (n) std::memcpy(pkt + 9, args, n);
    esp_hosted_cyberdeck_hci_tx(pkt, static_cast<uint16_t>(9 + n));
}

void send(uint8_t sub, const uint8_t* args, size_t n) {
    uint8_t pkt[4 + 5 + 250];
    if (n > 250) return;
    if (exec_armed) { exec_wait = sub; exec_sent = true; }
    pkt[0] = 0x01;
    pkt[1] = static_cast<uint8_t>(kOpcode);
    pkt[2] = static_cast<uint8_t>(kOpcode >> 8);
    pkt[3] = static_cast<uint8_t>(5 + n);
    std::memcpy(pkt + 4, kMagic, 4);
    pkt[8] = sub;
    if (n) std::memcpy(pkt + 9, args, n);
    if (esp_hosted_cyberdeck_hci_tx(pkt, static_cast<uint16_t>(9 + n)) != 0)
        std::printf("LAB error send failed (transport down or controller not owned)\n");
}

void hci_cmd(uint16_t op, const uint8_t* params, uint8_t n) {
    uint8_t pkt[4 + 32];
    if (exec_armed && (op == 0x201D || op == 0x201E || op == 0x201F)) { exec_wait = 0x100; exec_sent = true; }
    pkt[0] = 0x01;
    pkt[1] = static_cast<uint8_t>(op);
    pkt[2] = static_cast<uint8_t>(op >> 8);
    pkt[3] = n;
    if (n) std::memcpy(pkt + 4, params, n);
    esp_hosted_cyberdeck_hci_tx(pkt, static_cast<uint16_t>(4 + n));
}

void release_hook() {
    // bt_owner calls this when another host takes the controller: leave BR mode and give the callback back.
    if (!have_controller) return;
    if (scan.on) {
        const uint8_t disable[6] = {0, 0, 0, 0, 0, 0};
        hci_cmd(scan.extended ? 0x2042 : 0x200C, disable, scan.extended ? 6 : 2);
        scan.on = false;
    }
    if (dtm_active) { hci_cmd(0x201F, nullptr, 0); dtm_active = false; }
    send(ExitBr, nullptr, 0);
    esp_hosted_cyberdeck_set_hci_rx_cb(saved_cb);
    saved_cb = nullptr;
    have_controller = false;
    std::printf("LAB info controller released\n");
}

bool take_controller() {
    if (have_controller) return true;
    if (!esp_hosted_cyberdeck_transport_up()) {
        std::printf("LAB error C6 transport is not up\n");
        return false;
    }
    static bool hooks_set = false;
    if (!hooks_set) {
        // Busy while the lab holds the controller: otherwise the earbuds service takes it back when "idle", which
        // makes the C6 leave BR mode between two lab commands.
        bt_owner::set_hooks(bt_owner::Owner::Lab, release_hook, [] { return have_controller; });
        hooks_set = true;
    }
    if (bt_owner::acquire(bt_owner::Owner::Lab, "radio lab") != ESP_OK) {
        std::printf("LAB error could not take the controller\n");
        return false;
    }
    saved_cb = esp_hosted_cyberdeck_get_hci_rx_cb();
    esp_hosted_cyberdeck_set_hci_rx_cb(on_hci_rx);
    have_controller = true;
    return true;
}

// ---- argument helpers ----
struct Args {
    char* tok[12];
    int n = 0;
};

uint8_t fn_arg(const char* s) { return (s[0] == '-' && s[1] == '\0') ? 0xFF : static_cast<uint8_t>(std::atoi(s)); }
void put16(uint8_t* p, uint32_t v) { p[0] = static_cast<uint8_t>(v); p[1] = static_cast<uint8_t>(v >> 8); }
void put32(uint8_t* p, uint32_t v) { put16(p, v); put16(p + 2, v >> 16); }
uint32_t num(const char* s) { return static_cast<uint32_t>(std::strtoul(s, nullptr, 0)); }
uint32_t hexnum(const char* s) { return static_cast<uint32_t>(std::strtoul(s, nullptr, 16)); }

}  // namespace

void command(const char* line) {
    char buf[200];
    std::snprintf(buf, sizeof(buf), "%s", line);
    Args a;
    for (char* t = std::strtok(buf, " \t"); t && a.n < 12; t = std::strtok(nullptr, " \t")) a.tok[a.n++] = t;
    if (a.n < 2 || std::strcmp(a.tok[0], "lab") != 0) {
        std::printf("LAB error usage: lab ping|enter|exit|release|tone|stop|hop|rx|bletx|peek|poke|call|rxfreq|reboot\n");
        return;
    }
    const char* c = a.tok[1];
    if (!std::strcmp(c, "release")) {
        if (have_controller) bt_owner::release(bt_owner::Owner::Lab);
        std::printf("LAB info released\n");
        return;
    }
    if (!take_controller()) return;
    uint8_t p[64];
    std::memset(p, 0, sizeof(p));
    auto need = [&](int k) {
        if (a.n >= k) return true;
        std::printf("LAB error %s needs %d argument(s)\n", c, k - 2);
        return false;
    };
    if (!std::strcmp(c, "dtmraw")) {
        if (!need(5)) return;
        const auto mode = num(a.tok[2]);
        if (mode > 2 || scan.on || dtm_active) { std::printf("LAB error dtmraw: mode0..2; stop scan/DTM first\n"); return; }
        p[0] = mode; put32(p+1,hexnum(a.tok[3])); put32(p+5,hexnum(a.tok[4]));
        if (a.n > 5) {
            const auto cap = num(a.tok[5]);
            if (cap > 255) { std::printf("LAB error dtmraw cap0..255\n"); return; }
            p[9] = cap; put32(p+10,a.n > 6 ? hexnum(a.tok[6]) : 0x555555u);
        }
        send(DtmRaw,p,a.n > 5 ? 14 : 9); return;
    }
    if (!std::strcmp(c, "dtmhop")) {  // ... [rx <early> <ls44> <end> [late]] | off | (query)
        if (a.n == 2) { send(DtmHop, nullptr, 0); return; }
        if (scan.on || dtm_active) { std::printf("LAB error dtmhop: stop scan/DTM first\n"); return; }
        if (a.n == 3 && !std::strcmp(a.tok[2], "off")) { p[0] = p[1] = 0xFF; send(DtmHop, p, 5); return; }
        if (a.n == 4 && !std::strcmp(a.tok[2], "rxmax")) {  // RX max length for RX events (0 native); after dtmhop
            p[0] = 0xFD; p[1] = static_cast<uint8_t>(num(a.tok[3]));
            send(DtmHop, p, 2); return;
        }
        if (a.n == 4 && !std::strcmp(a.tok[2], "txlead")) {  // TX setup lead us (0 native, 40..600); set after dtmhop
            p[0] = 0xFE; put16(p + 1, static_cast<uint16_t>(num(a.tok[3])));
            send(DtmHop, p, 3); return;
        }
        if (!need(5)) return;
        auto freq = [&](const char* t, uint8_t* out) {
            if (!std::strcmp(t, "-")) { *out = 0xFF; return true; }
            const auto mhz = num(t);
            if (mhz < 2402 || mhz > 2480) return false;
            *out = static_cast<uint8_t>(mhz - 2402);
            return true;
        };
        const auto itvl = num(a.tok[4]);
        if (!freq(a.tok[2], p) || !freq(a.tok[3], p + 1) || itvl > 65000 || (itvl && itvl % 625)) {
            std::printf("LAB error dtmhop: MHz 2402..2480 or -, interval 0 or a multiple of 625 us\n");
            return;
        }
        put16(p + 2, static_cast<uint16_t>(itvl));
        p[4] = 1;
        if (a.n >= 9 && !std::strcmp(a.tok[5], "rx")) {  // ... 625 rx <early us> <ls44 raw> <end us>: TX f1 / RX f2
            const auto early = num(a.tok[6]), ls44 = num(a.tok[7]), end = num(a.tok[8]);
            const auto late = a.n >= 10 ? num(a.tok[9]) : 0;
            if (itvl != 625 || early > 100 || end < 1 || end > 1000 || late > 250) {
                std::printf("LAB error dtmhop rx: interval 625, early 0..100 us, ls44 raw (0 keep), end 1..1000 us, late 0..250 us\n");
                return;
            }
            p[5] = 1; p[6] = static_cast<uint8_t>(early); put32(p + 7, ls44); put16(p + 11, static_cast<uint16_t>(end));
            if (a.n >= 10) put16(p + 13, static_cast<uint16_t>(late));
            send(DtmHop, p, a.n >= 10 ? 15 : 13);
            return;
        }
        send(DtmHop, p, 5);
        return;
    }
    if (!std::strcmp(c, "quiet")) {
        if (!need(3)) return;
        const auto enabled = num(a.tok[2]);
        if (enabled > 1 || scan.on || dtm_active) { std::printf("LAB error quiet: 0|1; stop scan/DTM first\n"); return; }
        p[0] = enabled; send(Quiet, p, 1); return;
    }
    if (!std::strcmp(c, "rawmatch")) {
        if (!need(4)) return;
        const auto policy = a.n > 4 ? num(a.tok[4]) : 0u;
        if (policy > 3) { std::printf("LAB error rawmatch policy0..3\n"); return; }
        put16(p, num(a.tok[2])); put32(p+2, hexnum(a.tok[3]));
        p[6] = policy;
        if (a.n > 6) {  // rawmatch <ms> <expected> <policy> <capture bytes 0..64> <capture delay us 0..1000>
            p[7] = static_cast<uint8_t>(num(a.tok[5])); put16(p + 8, static_cast<uint16_t>(num(a.tok[6])));
            send(RawMatch, p, 10); return;
        }
        send(RawMatch, p, a.n > 4 ? 7 : 6); return;
    }
    if (!std::strcmp(c, "dtmtrain")) {  // dtmtrain | dtmtrain cfg <0|16|32> <repeats> | dtmtrain load <off> <txhex> <rxhex>
        if (a.n == 2) { send(DtmTrain, nullptr, 0); return; }
        if (a.n == 5 && !std::strcmp(a.tok[2], "cfg")) {
            p[0] = 0; p[1] = static_cast<uint8_t>(num(a.tok[3])); put16(p + 2, static_cast<uint16_t>(num(a.tok[4])));
            send(DtmTrain, p, 4); return;
        }
        const size_t tl = a.n == 6 ? std::strlen(a.tok[4]) : 0;
        if (a.n == 6 && !std::strcmp(a.tok[2], "load") && tl && tl % 2 == 0 && tl <= 32 && std::strlen(a.tok[5]) == tl) {
            const size_t cnt = tl / 2;
            p[0] = 1; p[1] = static_cast<uint8_t>(num(a.tok[3])); p[2] = static_cast<uint8_t>(cnt);
            for (size_t i = 0; i < cnt; ++i) {
                char b[3] = {a.tok[4][2 * i], a.tok[4][2 * i + 1], 0}, r[3] = {a.tok[5][2 * i], a.tok[5][2 * i + 1], 0};
                p[3 + i] = static_cast<uint8_t>(hexnum(b)); p[3 + cnt + i] = static_cast<uint8_t>(hexnum(r));
            }
            send(DtmTrain, p, 3 + 2 * cnt); return;
        }
        std::printf("LAB error dtmtrain: | cfg <0|16|32> <repeats> | load <offset> <txhex> <rxhex> (<=16 bytes)\n");
        return;
    }
    if (!std::strcmp(c, "page")) {  // page off | page | page <tlap> <tuap> <olap> <ouap> <nap> <cod> <clk27_2> (hex)
        if (a.n == 4 && !std::strcmp(a.tok[2], "end")) {
            p[0] = 4; put16(p + 1, static_cast<uint16_t>(num(a.tok[3])));
            send(Page, p, 3); return;
        }
        if ((a.n == 4 || a.n == 5) && !std::strcmp(a.tok[2], "test")) {
            p[0] = 3; p[1] = static_cast<uint8_t>(num(a.tok[3]));
            if (a.n == 5) put16(p + 2, static_cast<uint16_t>(num(a.tok[4])));
            send(Page, p, a.n == 5 ? 4 : 2); return;
        }
        if (a.n == 4 && !std::strcmp(a.tok[2], "det")) {  // detection path: 0 ls+8 buffer, 1 rxed-buffer hook
            p[0] = 8; p[1] = static_cast<uint8_t>(num(a.tok[3]));
            send(Page, p, 2); return;
        }
        if (a.n == 3 && !std::strcmp(a.tok[2], "rxlog")) { p[0] = 9; send(Page, p, 1); return; }
        if ((a.n == 6 || a.n == 8) && !std::strcmp(a.tok[2], "conn")) {  // own LAP, UAP (hex), slots [rxmax ls44]
            const uint32_t ol = hexnum(a.tok[3]);
            p[0] = 12; p[1] = ol; p[2] = ol >> 8; p[3] = ol >> 16; p[4] = static_cast<uint8_t>(hexnum(a.tok[4]));
            put16(p + 5, static_cast<uint16_t>(num(a.tok[5])));
            if (a.n == 8) { p[7] = static_cast<uint8_t>(num(a.tok[6])); put16(p + 8, static_cast<uint16_t>(num(a.tok[7]))); }
            send(Page, p, a.n == 8 ? 10 : 7); return;
        }
        if (a.n == 4 && !std::strcmp(a.tok[2], "connlogx")) { p[0] = 14; put32(p + 1, num(a.tok[3])); send(Page, p, 5); return; }
        if (a.n == 4 && !std::strcmp(a.tok[2], "connlog")) { p[0] = 14; p[1] = static_cast<uint8_t>(num(a.tok[3])); send(Page, p, 2); return; }
        if (a.n == 3 && !std::strcmp(a.tok[2], "connq")) { p[0] = 13; send(Page, p, 1); return; }
        if (a.n == 6 && !std::strcmp(a.tok[2], "enc")) {  // enc <on> <Kc' 32 hex, C byte order> <central addr 12 hex, LSB first>
            p[0] = 17; p[1] = static_cast<uint8_t>(num(a.tok[3]));
            const char* k = a.tok[4]; const char* d = a.tok[5];
            if (std::strlen(k) != 32 || std::strlen(d) != 12) { std::printf("LAB error page enc: 32 + 12 hex digits\n"); return; }
            for (int i = 0; i < 16; ++i) { char b[3] = {k[2 * i], k[2 * i + 1], 0}; p[2 + i] = static_cast<uint8_t>(std::strtoul(b, nullptr, 16)); }
            for (int i = 0; i < 6; ++i) { char b[3] = {d[2 * i], d[2 * i + 1], 0}; p[18 + i] = static_cast<uint8_t>(std::strtoul(b, nullptr, 16)); }
            send(Page, p, 24); return;
        }
        if ((a.n == 7 || a.n == 8 || a.n == 9) && (!std::strcmp(a.tok[2], "lmp") || !std::strcmp(a.tok[2], "acl"))) {
            // lmp <idx> <start> <repeat> <seqn> [hex PDU] | acl <idx> <start> <repeat> <seqn> <llid> [hex]
            const bool acl = !std::strcmp(a.tok[2], "acl");
            p[0] = acl ? 18 : 16; p[1] = static_cast<uint8_t>(num(a.tok[3])); put16(p + 2, static_cast<uint16_t>(num(a.tok[4])));
            p[4] = static_cast<uint8_t>(num(a.tok[5])); p[5] = static_cast<uint8_t>(num(a.tok[6]));
            size_t n = 6;
            if (acl) { if (a.n < 8) return; p[6] = static_cast<uint8_t>(num(a.tok[7])); n = 7; }
            const int hex_tok = acl ? 8 : 7;
            if (a.n > hex_tok) {
                const char* h = a.tok[hex_tok];
                for (; h[0] && h[1] && n < (acl ? 7u : 6u) + 17; h += 2) {
                    char b[3] = {h[0], h[1], 0};
                    p[n++] = static_cast<uint8_t>(std::strtoul(b, nullptr, 16));
                }
            }
            send(Page, p, n); return;
        }
        // 1.4.244 ACL FIFO with ARQ: fifo <tag> <type 3 DM1|4 DH1> <llid> <hex> | fiforeset <on> <first seqn> |
        // stream <on> <media cid hex> <frames per packet> <packets, 0 = until off>
        if (a.n == 7 && !std::strcmp(a.tok[2], "fifo")) {
            p[0] = 19; put16(p + 1, static_cast<uint16_t>(num(a.tok[3])));
            p[3] = static_cast<uint8_t>(num(a.tok[4])); p[4] = static_cast<uint8_t>(num(a.tok[5]));
            size_t n = 5;
            for (const char* h = a.tok[6]; h[0] && h[1] && n < 5u + 27u; h += 2) {
                char b[3] = {h[0], h[1], 0};
                p[n++] = static_cast<uint8_t>(std::strtoul(b, nullptr, 16));
            }
            send(Page, p, n); return;
        }
        if (a.n == 4 && !std::strcmp(a.tok[2], "sup")) {  // 1.4.245 supervision timeout in slots (0 = off)
            p[0] = 22; put16(p + 1, static_cast<uint16_t>(num(a.tok[3]))); send(Page, p, 3); return;
        }
        if (a.n == 3 && !std::strcmp(a.tok[2], "connend")) { p[0] = 23; send(Page, p, 1); return; }  // 1.4.245
        if (a.n == 5 && !std::strcmp(a.tok[2], "fiforeset")) {
            p[0] = 20; p[1] = static_cast<uint8_t>(num(a.tok[3])); p[2] = static_cast<uint8_t>(num(a.tok[4]));
            send(Page, p, 3); return;
        }
        if (a.n == 7 && !std::strcmp(a.tok[2], "stream")) {
            p[0] = 21; p[1] = static_cast<uint8_t>(num(a.tok[3])); put16(p + 2, static_cast<uint16_t>(hexnum(a.tok[4])));
            p[4] = static_cast<uint8_t>(num(a.tok[5])); put32(p + 5, num(a.tok[6]));
            send(Page, p, 9); return;
        }
        if (a.n == 4 && !std::strcmp(a.tok[2], "connbuf")) { p[0] = 15; p[1] = static_cast<uint8_t>(num(a.tok[3])); send(Page, p, 2); return; }
        if (a.n == 4 && !std::strcmp(a.tok[2], "mask")) { p[0] = 11; put32(p + 1, hexnum(a.tok[3])); send(Page, p, 5); return; }
        if (a.n == 3 && !std::strcmp(a.tok[2], "trace")) { p[0] = 10; send(Page, p, 1); return; }
        if (a.n == 4 && !std::strcmp(a.tok[2], "kick")) {  // emulate a response every N pairs (0 = off)
            p[0] = 6; put16(p + 1, static_cast<uint16_t>(num(a.tok[3])));
            send(Page, p, 3); return;
        }
        if (a.n == 4 && !std::strcmp(a.tok[2], "r2ls44")) {  // RX window for the resp2 RX after an FHS (0 = same)
            p[0] = 7; put32(p + 1, num(a.tok[3]));
            send(Page, p, 5); return;
        }
        if (a.n == 4 && !std::strcmp(a.tok[2], "xfix")) {  // fixed reaction X (0..31), "off" = train X
            p[0] = 5; p[1] = !std::strcmp(a.tok[3], "off") ? 0xFF : static_cast<uint8_t>(num(a.tok[3]));
            send(Page, p, 2); return;
        }
        if (a.n == 2) { p[0] = 2; send(Page, p, 1); return; }
        if (a.n == 3 && !std::strcmp(a.tok[2], "off")) { p[0] = 0; send(Page, p, 1); return; }
        if (a.n == 9) {
            const uint32_t tl = hexnum(a.tok[2]), ol = hexnum(a.tok[4]), cod = hexnum(a.tok[7]);
            p[0] = 1;
            p[1] = tl; p[2] = tl >> 8; p[3] = tl >> 16; p[4] = static_cast<uint8_t>(hexnum(a.tok[3]));
            p[5] = ol; p[6] = ol >> 8; p[7] = ol >> 16; p[8] = static_cast<uint8_t>(hexnum(a.tok[5]));
            put16(p + 9, static_cast<uint16_t>(hexnum(a.tok[6])));
            p[11] = cod; p[12] = cod >> 8; p[13] = cod >> 16;
            put32(p + 14, hexnum(a.tok[8]));
            send(Page, p, 18); return;
        }
        std::printf("LAB error page: | off | test <X> [end_us] | end <us> | xfix <X|off> | kick <pairs> | r2ls44 <raw> | det <0..3> | rxlog | trace | mask <hex> | conn <lap> <uap> <slots> [rxmax ls44] | connq | connlog <i> | lmp <idx> <start> <repeat> <seqn> [hex] | acl <idx> <start> <repeat> <seqn> <llid> [hex] | enc <on> <kc> <addr> | <tlap> <tuap> <olap> <ouap> <nap> <cod> <clk27_2> (hex)\n");
        return;
    }
    if (!std::strcmp(c, "rawdump")) {  // rawdump [index]
        if (a.n > 2) { p[0] = static_cast<uint8_t>(num(a.tok[2])); send(RawDump, p, 1); return; }
        send(RawDump, nullptr, 0); return;
    }
    if (!std::strcmp(c, "scanraw")) { send(ScanRaw, nullptr, 0); return; }
    if (!std::strcmp(c, "dtmstats")) {
        if (!need(3)) return;
        const auto mode = num(a.tok[2]);
        if (mode > 6 || ((mode != 1 && mode != 3) && (scan.on || dtm_active))) {
            std::printf("LAB error dtmstats: mode 0..6; stop scan/DTM before changing capture\n");
            return;
        }
        p[0] = static_cast<uint8_t>(mode);
        send(DtmStats, p, 1);
        return;
    }
    if (!std::strcmp(c, "dtm")) {  // dtm on <RF channel 0..39> | off
        if (!need(3)) return;
        if (!std::strcmp(a.tok[2], "off")) {
            hci_cmd(0x201F, nullptr, 0);
            return;
        }
        if (!std::strcmp(a.tok[2], "tx")) {
            if (!need(6)) return;
            const auto channel = num(a.tok[3]);
            const auto length = num(a.tok[4]);
            const auto type = num(a.tok[5]);
            if (channel > 39 || length > 255 || type > 2 || scan.on || dtm_active) {
                std::printf("LAB error dtm tx: channel 0..39, length 0..255, type 0..2; stop scan/DTM first\n");
                return;
            }
            hci_cmd(0x0C03, nullptr, 0);
            vTaskDelay(pdMS_TO_TICKS(300));
            p[0] = static_cast<uint8_t>(channel);
            p[1] = static_cast<uint8_t>(length);
            p[2] = static_cast<uint8_t>(type);
            dtm_active = true;
            // IDF hci_common.h LE_TX_TEST OCF 0x001E, three-byte legacy parameters.
            hci_cmd(0x201E, p, 3);
            return;
        }
        if (std::strcmp(a.tok[2], "on") || !need(4)) return;
        const auto channel = num(a.tok[3]);
        if (channel > 39 || scan.on || dtm_active) {
            std::printf("LAB error dtm: channel 0..39; stop scan/DTM first\n");
            return;
        }
        hci_cmd(0x0C03, nullptr, 0);
        vTaskDelay(pdMS_TO_TICKS(300));
        p[0] = static_cast<uint8_t>(channel);
        dtm_active = true;  // cover the pending command until completion updates it
        hci_cmd(0x201D, p, 1);
        return;
    }
    if (!std::strcmp(c, "scan") || !std::strcmp(c, "scanext")) {
        // lab scan on [units]|off: passive scan, interval = window (default 10 ms), duplicates reported (BLE controller running,
        // NOT in BR mode). "off" prints the counts.
        if (a.n < 3) { std::printf("LAB error scan needs on|off\n"); return; }
        if (!std::strcmp(a.tok[2], "on")) {
            // HCI scan parameters use 0.625 ms units, range 0x0004..0x4000.
            const auto units = a.n > 3 ? num(a.tok[3]) : 0x10u;
            if (units < 4 || units > 0x4000) { std::printf("LAB error scan units 4..16384\n"); return; }
            if (dtm_active) { std::printf("LAB error stop DTM before scan\n"); return; }
            hci_cmd(0x0C03, nullptr, 0);  // HCI Reset: the LE Audio host may have used extended scanning
            vTaskDelay(pdMS_TO_TICKS(300));
            // Event masks explicitly: LE Meta (bit 61) in the event mask; every LE subevent incl. advertising reports.
            const uint8_t evmask[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F};
            hci_cmd(0x0C01, evmask, sizeof(evmask));
            vTaskDelay(pdMS_TO_TICKS(50));
            const uint8_t lemask[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            hci_cmd(0x2001, lemask, sizeof(lemask));
            vTaskDelay(pdMS_TO_TICKS(50));
            scan.extended = !std::strcmp(c, "scanext");
            // IDF hci_common.h 0x2041: own/filter/PHY1 then passive type/interval/window.
            uint8_t legacy[7] = {0, 0, 0, 0, 0, 0, 0};
            uint8_t extended[8] = {0, 0, 1, 0, 0, 0, 0, 0};
            put16(legacy+1, units); put16(legacy+3, units);
            put16(extended+4, units); put16(extended+6, units);
            hci_cmd(scan.extended ? 0x2041 : 0x200B,
                    scan.extended ? extended : legacy, scan.extended ? 8 : 7);
            vTaskDelay(pdMS_TO_TICKS(50));
            scan.all = scan.target = 0;
            scan.rssi_sum = 0;
            std::memset(scan.family, 0, sizeof(scan.family));
            const uint8_t en[6] = {1, 0, 0, 0, 0, 0};
            hci_cmd(scan.extended ? 0x2042 : 0x200C, en, scan.extended ? 6 : 2);
            scan.on = true;
            std::printf("LAB reply scan status=0x00 on=1\n");
        } else {
            const uint8_t en[6] = {0, 0, 0, 0, 0, 0};
            hci_cmd(scan.extended ? 0x2042 : 0x200C, en, scan.extended ? 6 : 2);
            scan.on = false;
            char fam[400] = "";
            size_t fl = 0;
            for (int i = 0; i < 256 && fl < sizeof(fam) - 12; ++i)
                if (scan.family[i]) fl += std::snprintf(fam + fl, sizeof(fam) - fl, "%s%02x:%u", fl ? "," : "", i, scan.family[i]);
            std::printf("LAB reply scan status=0x00 all=%lu target=%lu target_rssi_avg=%ld family=%s\n",
                        static_cast<unsigned long>(scan.all), static_cast<unsigned long>(scan.target),
                        static_cast<long>(scan.target ? scan.rssi_sum / static_cast<int32_t>(scan.target) : 0),
                        fl ? fam : "-");
        }
        return;
    }
    if (!std::strcmp(c, "scanflags")) {  // 0/1 configure DTM bit27, 2 query
        if (!need(3)) return;
        const auto mode = num(a.tok[2]);
        if (mode > 5 || (mode != 2 && scan.on)) {
            std::printf("LAB error scanflags: mode 0..5; stop scan before changing flags\n");
            return;
        }
        p[0] = static_cast<uint8_t>(mode);
        send(ScanFlags, p, 1);
        return;
    }
    if (!std::strcmp(c, "irq")) {  // bank 0/1 query, 2 reset (scan stopped)
        if (!need(3)) return;
        const auto bank = num(a.tok[2]);
        if (bank > 2 || (bank == 2 && scan.on)) {
            std::printf("LAB error irq: bank 0..2; stop scan before reset\n");
            return;
        }
        p[0] = static_cast<uint8_t>(bank);
        send(IrqStats, p, 1);
        return;
    }
    if (!std::strcmp(c, "scanaa")) {  // scan off first; then scanaa <0|1|2> <AA hex>
        if (!need(4)) return;
        const auto mode = num(a.tok[2]);
        if (mode > 2 || (mode != 2 && scan.on)) {
            std::printf("LAB error scanaa: mode must be 0..2; stop scan before changing AA\n");
            return;
        }
        p[0] = static_cast<uint8_t>(mode);
        put32(p + 1, hexnum(a.tok[3]));
        send(ScanAA, p, 5);
        return;
    }
    if (!std::strcmp(c, "chanmap")) {  // lab chanmap <chan> <value|-1>: remap one BLE channel's frequency value
        if (!need(4)) return;
        p[0] = static_cast<uint8_t>(num(a.tok[2]));
        put16(p + 1, static_cast<uint32_t>(std::strtol(a.tok[3], nullptr, 0)));
        send(ChanMap, p, 3);
        return;
    }
    if (!std::strcmp(c, "force")) {
        if (!need(4)) return;
        p[0] = static_cast<uint8_t>(num(a.tok[2]));
        put16(p + 1, num(a.tok[3]));
        send(Force, p, 3);
        return;
    }
    if (!std::strcmp(c, "ping")) send(Ping, nullptr, 0);
    else if (!std::strcmp(c, "enter")) send(EnterBr, nullptr, 0);
    else if (!std::strcmp(c, "exit")) send(ExitBr, nullptr, 0);
    else if (!std::strcmp(c, "stop")) send(Stop, nullptr, 0);
    else if (!std::strcmp(c, "rxfreq")) send(RxFreq, nullptr, 0);
    else if (!std::strcmp(c, "reboot")) send(Reboot, nullptr, 0);
    else if (!std::strcmp(c, "tone")) {
        if (!need(4)) return;
        p[0] = fn_arg(a.tok[2]);
        put16(p + 1, num(a.tok[3]));
        p[3] = static_cast<uint8_t>(a.n > 5 ? num(a.tok[5]) : 0);
        put32(p + 4, a.n > 4 ? num(a.tok[4]) : 0);
        send(Tone, p, 8);
    } else if (!std::strcmp(c, "hop")) {
        if (!need(7)) return;
        p[0] = fn_arg(a.tok[2]);
        put16(p + 1, num(a.tok[3]));
        put16(p + 3, num(a.tok[4]));
        put16(p + 5, num(a.tok[5]));
        put16(p + 7, num(a.tok[6]));
        send(Hop, p, 9);
    } else if (!std::strcmp(c, "rx")) {
        if (!need(6)) return;
        p[0] = fn_arg(a.tok[2]);
        put16(p + 1, num(a.tok[3]));
        put32(p + 3, hexnum(a.tok[4]));
        put32(p + 7, num(a.tok[5]));
        send(RxCount, p, 11);
    } else if (!std::strcmp(c, "bletx")) {
        if (!need(9)) return;
        p[0] = fn_arg(a.tok[2]);
        put16(p + 1, num(a.tok[3]));
        put32(p + 3, hexnum(a.tok[4]));
        p[7] = static_cast<uint8_t>(num(a.tok[5]));
        p[8] = static_cast<uint8_t>(num(a.tok[6]));
        p[9] = static_cast<uint8_t>(num(a.tok[7]));
        put16(p + 10, num(a.tok[8]));
        send(BleTx, p, 13);  // 12 bytes of arguments + 1 pad: C6 1.4.190 checks n < 13 (off by one, fixed in 1.4.191)
    } else if (!std::strcmp(c, "peek")) {
        if (!need(3)) return;
        put32(p, hexnum(a.tok[2]));
        p[4] = static_cast<uint8_t>(a.n > 3 ? num(a.tok[3]) : 1);
        send(Peek, p, 5);
    } else if (!std::strcmp(c, "poke")) {
        if (!need(4)) return;
        put32(p, hexnum(a.tok[2]));
        put32(p + 4, hexnum(a.tok[3]));
        send(Poke, p, 8);
    } else if (!std::strcmp(c, "call")) {
        if (!need(7)) return;
        p[0] = static_cast<uint8_t>(num(a.tok[2]));
        for (int i = 0; i < 4; ++i) put32(p + 1 + 4 * i, static_cast<uint32_t>(std::strtol(a.tok[3 + i], nullptr, 0)));
        send(Call, p, 17);
    } else {
        std::printf("LAB error unknown command %s\n", c);
    }
    ESP_LOGD(TAG, "sent %s", c);
}

int exec(const char* line, uint8_t* out, size_t* out_len, int timeout_ms) {
    if (!exec_mutex) {
        exec_mutex = xSemaphoreCreateMutex();
        exec_done = xSemaphoreCreateBinary();
    }
    xSemaphoreTake(exec_mutex, portMAX_DELAY);
    xSemaphoreTake(exec_done, 0);
    exec_wait = -1;
    exec_sent = false;
    exec_armed = true;
    command(line);
    exec_armed = false;
    int rc = -2;  // the line sent nothing (parse error, controller not available)
    if (exec_sent) {
        if (xSemaphoreTake(exec_done, pdMS_TO_TICKS(timeout_ms)) == pdTRUE) {
            rc = exec_status;
            if (out && out_len) {
                const size_t n = exec_len < *out_len ? exec_len : *out_len;
                std::memcpy(out, exec_buf, n);
                *out_len = n;
            }
        } else {
            exec_wait = -1;
            rc = -1;
        }
    }
    xSemaphoreGive(exec_mutex);
    return rc;
}

bool push_sbc(const uint8_t* frames, uint8_t n, uint8_t frame_len) {
    if (!have_controller || 3u + static_cast<size_t>(n) * frame_len > 250) return false;
    uint8_t a[250];
    a[0] = 24;
    a[1] = n;
    a[2] = frame_len;
    std::memcpy(a + 3, frames, static_cast<size_t>(n) * frame_len);
    send_raw(Page, a, 3u + static_cast<size_t>(n) * frame_len);  // no reply; never disturbs a pending exec()
    return true;
}

void set_verbose(bool on) { exec_quiet = !on; }

}  // namespace radio_lab
