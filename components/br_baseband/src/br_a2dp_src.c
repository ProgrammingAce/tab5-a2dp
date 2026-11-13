#include "br/br_a2dp_src.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "br/br_e0.h"
#include "br/br_p192.h"
#include "br/br_safer.h"
#include "br/br_ssp.h"

/* ---- LMP opcodes (Core Vol 2 Part C §5.2) ------------------------------------------------------------------------ */
enum {
    OP_NAME_REQ = 1, OP_NAME_RES = 2, OP_ACCEPTED = 3, OP_NOT_ACCEPTED = 4, OP_CLKOFFSET_REQ = 5, OP_CLKOFFSET_RES = 6,
    OP_DETACH = 7, OP_AU_RAND = 11, OP_SRES = 12, OP_ENC_MODE_REQ = 15, OP_ENC_KEY_SIZE_REQ = 16, OP_START_ENC_REQ = 17,
    OP_STOP_ENC_REQ = 18, OP_SWITCH_REQ = 19, OP_HOLD_REQ = 21, OP_SNIFF_REQ = 23, OP_INCR_POWER_REQ = 31,
    OP_DECR_POWER_REQ = 32, OP_QOS_REQ = 42, OP_MAX_SLOT_REQ = 46, OP_TIMING_ACC_REQ = 47, OP_TIMING_ACC_RES = 48,
    OP_SETUP_COMPLETE = 49, OP_HOST_CONN_REQ = 51, OP_PAGE_MODE_REQ = 53, OP_PAGE_SCAN_MODE_REQ = 54,
    OP_VERSION_REQ = 37, OP_VERSION_RES = 38, OP_FEATURES_REQ = 39, OP_FEATURES_RES = 40,
    OP_KEY_SIZE_MASK_REQ = 58, OP_KEY_SIZE_MASK_RES = 59,
    OP_ENCAP_HEADER = 61, OP_ENCAP_PAYLOAD = 62, OP_SP_CONFIRM = 63, OP_SP_NUMBER = 64, OP_DHKEY_CHECK = 65,
    OP_ESCAPE4 = 127,
};
enum {
    EXT_ACCEPTED = 1, EXT_NOT_ACCEPTED = 2, EXT_FEATURES_REQ = 3, EXT_FEATURES_RES = 4, EXT_IO_CAP_REQ = 25,
    EXT_IO_CAP_RES = 26, EXT_PING_REQ = 33, EXT_PING_RES = 34,
};
/* PDUs that need no answer (informational, or responses the state machines look at) */
static const uint8_t kSilent[] = {OP_NAME_RES, OP_ACCEPTED, OP_NOT_ACCEPTED, OP_CLKOFFSET_RES, OP_SETUP_COMPLETE,
                                  OP_VERSION_RES, OP_FEATURES_RES, OP_TIMING_ACC_RES, 35 /* auto_rate */,
                                  36 /* preferred_rate */, 33, 34 /* max/min power */, 41 /* qos */, 45 /* max_slot */,
                                  52 /* slot_offset */, 55 /* supervision_timeout */, 60 /* set_afh */};

/* Page 0: encryption, SSP (controller), encapsulated PDU, extended features. 1-slot BR ACL only. */
/* Core Vol 2 Part C 3.3 / Part B 6.6.2: bits20..22 encode STOP lag
 * in 256-byte units. CRC verification is task-based, so zero lag is false.
 * Advertise the conservative 1792-byte allowance (64 queued DH1 fragments
 * plus one in flight fit in it); do not claim instantaneous payload STOP. */
static const uint8_t kFeatures0[8] = {0x04, 0x00, 0x70, 0x00, 0x00, 0x00, 0x18, 0x80};
static const uint8_t kFeatures1[8] = {0x01, 0, 0, 0, 0, 0, 0, 0}; /* SSP host support */
/* Initial feature request uses the same flow-control lag as our responses. */
static const uint8_t kFeaturesReq[8] = {0x04, 0x00, 0x70, 0x00, 0x00, 0x00, 0x08, 0x00};
static const uint8_t kIocap[3] = {0x03, 0x00, 0x04}; /* NoInputNoOutput, no OOB, MITM not required + bonding */

enum { SSP_IDLE, SSP_IOCAP, SSP_KEY_HDR, SSP_KEY_PL, SSP_PEER_KEY, SSP_WAIT_CONFIRM, SSP_WAIT_NUMBER, SSP_WAIT_DHKEY,
       SSP_PAIRED, SSP_FAIL };
enum { AU_IDLE, AU_RAND, AU_ENC_MODE, AU_KEY_SIZE, AU_START_ENC, AU_ENCRYPTED, AU_FAIL };
enum { L2_OFF, L2_WAIT_SINK, L2_SIG_CONNECTING, L2_SIGNALING, L2_SIGNALING_ACP, L2_MEDIA_CONNECTING, L2_STARTING,
       L2_STREAMING };
enum { AV_IDLE, AV_DISCOVER, AV_CAPS, AV_CONFIGURE, AV_OPEN, AV_CONFIGURED, AV_NEED_MEDIA, AV_STARTING, AV_STREAMING,
       AV_FAIL, AV_SUSPENDING };

#define PSM_AVDTP 0x0019
#define SIG_SCID 0x0041
#define MEDIA_SCID 0x0042
#define SDP_SCID 0x0043
#define PSM_SDP 0x0001
#define PSM_AVCTP 0x0017
#define OUR_MTU 672
#define INT_SEID 1
#define AVCTP_CID 0x0044
#define AVCTP_PID_AVRCP 0x110E

static void a2_log(br_a2dp_t* a, const char* fmt, ...)
{
    if (!a->io.event) return;
    char buf[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    a->io.event(a->io.ctx, BR_A2DP_EV_LOG, buf);
}
static void fail(br_a2dp_t* a, const char* why)
{
    if (a->failed) return;
    a->failed = 1;
    if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_FAILED, why);
}
static uint32_t now(br_a2dp_t* a) { return a->io.now_ms ? a->io.now_ms(a->io.ctx) : 0; }

/* ---- LMP output ------------------------------------------------------------------------------------------------- */
static void lmp(br_a2dp_t* a, uint8_t op, uint8_t tid, const uint8_t* p, size_t n)
{
    uint8_t b[17];
    if (n > 16) n = 16;
    b[0] = (uint8_t)((op << 1) | (tid & 1u));
    if (n) memcpy(b + 1, p, n);
    a->io.send(a->io.ctx, 3, b, 1 + n);
}
static void lmp_ext(br_a2dp_t* a, uint8_t ext, uint8_t tid, const uint8_t* p, size_t n)
{
    uint8_t b[17];
    if (n > 15) n = 15;
    b[0] = (uint8_t)((OP_ESCAPE4 << 1) | (tid & 1u));
    b[1] = ext;
    if (n) memcpy(b + 2, p, n);
    a->io.send(a->io.ctx, 3, b, 2 + n);
}
static void lmp_accept(br_a2dp_t* a, uint8_t tid, uint8_t op) { lmp(a, OP_ACCEPTED, tid, &op, 1); }
static void lmp_reject(br_a2dp_t* a, uint8_t tid, uint8_t op, uint8_t err)
{
    const uint8_t p[2] = {op, err};
    lmp(a, OP_NOT_ACCEPTED, tid, p, 2);
}

/* ---- L2CAP output ----------------------------------------------------------------------------------------------- */
static void l2_send(br_a2dp_t* a, uint16_t cid, const uint8_t* p, size_t n)
{
    uint8_t f[4 + 256];
    if (n > 256) return;
    f[0] = (uint8_t)n; f[1] = (uint8_t)(n >> 8); f[2] = (uint8_t)cid; f[3] = (uint8_t)(cid >> 8);
    memcpy(f + 4, p, n);
    a->io.send(a->io.ctx, 2, f, 4 + n);
}
static void sig(br_a2dp_t* a, uint8_t code, uint8_t ident, const uint8_t* d, size_t n)
{
    uint8_t c[4 + 48];
    if (n > 48) return;
    c[0] = code; c[1] = ident; c[2] = (uint8_t)n; c[3] = (uint8_t)(n >> 8);
    memcpy(c + 4, d, n);
    l2_send(a, 0x0001, c, 4 + n);
}
static uint8_t next_ident(br_a2dp_t* a)
{
    a->ident = (uint8_t)(a->ident % 255u + 1u);
    return a->ident;
}
static void put16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static uint16_t get16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static void ch_connect(br_a2dp_t* a, br_a2dp_ch_t* c, uint16_t scid)
{
    memset(c, 0, sizeof *c);
    c->used = 1; c->scid = scid; c->peer_mtu = 672;
    uint8_t d[4];
    put16(d, PSM_AVDTP); put16(d + 2, scid);
    sig(a, 0x02, next_ident(a), d, 4);
}
static void ch_cfg_req(br_a2dp_t* a, uint16_t dcid)
{
    uint8_t d[8];
    put16(d, dcid); put16(d + 2, 0); d[4] = 0x01; d[5] = 2; put16(d + 6, OUR_MTU);
    sig(a, 0x04, next_ident(a), d, 8);
}
static br_a2dp_ch_t* ch_by_scid(br_a2dp_t* a, uint16_t scid)
{
    if (a->sig.used && a->sig.scid == scid) return &a->sig;
    if (a->media.used && a->media.scid == scid) return &a->media;
    if (a->sdp.used && a->sdp.scid == scid) return &a->sdp;
    if (a->avctp.used && a->avctp.scid == scid) return &a->avctp;
    return NULL;
}

/* ---- SDP server (Core Vol 3 Part B): one record, A2DP Source (A2DP 1.3 §5.3, mandatory for a SRC) --------------- */
/* Attributes in ascending ID order: {id, encoded value}. Big-endian data elements. */
static const uint8_t kSdpRecord[] = {
    0x09, 0x00, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01,                          /* ServiceRecordHandle 0x00010001 */
    0x09, 0x00, 0x01, 0x35, 0x03, 0x19, 0x11, 0x0A,                          /* ServiceClassIDList: AudioSource */
    0x09, 0x00, 0x04, 0x35, 0x10, 0x35, 0x06, 0x19, 0x01, 0x00, 0x09, 0x00, 0x19, /* ProtocolDescriptorList: L2CAP 0x19 */
    0x35, 0x06, 0x19, 0x00, 0x19, 0x09, 0x01, 0x03,                          /*   AVDTP 1.3 */
    0x09, 0x00, 0x05, 0x35, 0x03, 0x19, 0x10, 0x02,                          /* BrowseGroupList: PublicBrowseRoot */
    0x09, 0x00, 0x09, 0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x0D, 0x09, 0x01, 0x03, /* ProfileDescriptorList: A2DP 1.3 */
    0x09, 0x01, 0x00, 0x25, 0x04, 'T', 'a', 'b', '5',                        /* ServiceName */
    0x09, 0x03, 0x11, 0x09, 0x00, 0x01,                                      /* SupportedFeatures: player */
};
#define SDP_HANDLE 0x00010001u
static const uint16_t kSdpUuids[] = {0x110A, 0x0100, 0x0019, 0x1002, 0x110D};

static uint32_t be32(const uint8_t* p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static uint16_t be16(const uint8_t* p) { return (uint16_t)(p[0] << 8 | p[1]); }
/* Data element header at p: returns the header length and sets *type and *len (0 = malformed). */
static size_t sdp_de(const uint8_t* p, size_t n, uint8_t* type, size_t* len)
{
    if (!n) return 0;
    *type = p[0] >> 3;
    const uint8_t sz = p[0] & 7u;
    if (*type == 0) { *len = 0; return 1; }
    if (sz < 5) { *len = (size_t)1 << sz; return 1; }
    const size_t hb = sz == 5 ? 1 : sz == 6 ? 2 : 4;
    if (n < 1 + hb) return 0;
    *len = sz == 5 ? p[1] : sz == 6 ? be16(p + 1) : be32(p + 1);
    return 1 + hb;
}
/* Sequence at p: calls fn for each element (pointer to its header, total size). Returns bytes used, 0 = malformed. */
static size_t sdp_seq(const uint8_t* p, size_t n, const uint8_t** body, size_t* body_len)
{
    uint8_t type; size_t len;
    const size_t h = sdp_de(p, n, &type, &len);
    if (!h || type != 6 || h + len > n) return 0;
    *body = p + h; *body_len = len;
    return h + len;
}
/* Every UUID of the search pattern must be in the record (16/32-bit, or 128-bit on the Base UUID). */
static int sdp_match(const uint8_t* pat, size_t n)
{
    static const uint8_t base[12] = {0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB};
    for (size_t i = 0; i < n;) {
        uint8_t type; size_t len;
        const size_t h = sdp_de(pat + i, n - i, &type, &len);
        if (!h || type != 3 || i + h + len > n) return 0;
        const uint8_t* u = pat + i + h;
        uint32_t v;
        if (len == 2) v = be16(u);
        else if (len == 4) v = be32(u);
        else if (len == 16 && !memcmp(u + 4, base, 12)) v = be32(u);
        else return 0;
        int found = 0;
        for (size_t k = 0; k < sizeof kSdpUuids / sizeof kSdpUuids[0]; ++k) found |= v == kSdpUuids[k];
        if (!found) return 0;
        i += h + len;
    }
    return 1;
}
/* The record's attributes selected by an AttributeIDList, as one data element sequence. */
static size_t sdp_attrs(const uint8_t* ids, size_t n, uint8_t* out, size_t cap)
{
    uint8_t body[sizeof kSdpRecord];
    size_t bl = 0;
    for (size_t r = 0; r < sizeof kSdpRecord;) {
        const uint16_t id = be16(kSdpRecord + r + 1);
        uint8_t type; size_t len;
        const size_t h = sdp_de(kSdpRecord + r + 3, sizeof kSdpRecord - r - 3, &type, &len);
        const size_t sz = 3 + h + len;
        int want = 0;
        for (size_t i = 0; i < n;) {
            uint8_t it; size_t il;
            const size_t ih = sdp_de(ids + i, n - i, &it, &il);
            if (!ih || it != 1 || i + ih + il > n) break;
            if (il == 2) want |= be16(ids + i + ih) == id;
            else if (il == 4) want |= be16(ids + i + ih) <= id && id <= be16(ids + i + ih + 2);
            i += ih + il;
        }
        if (want) { memcpy(body + bl, kSdpRecord + r, sz); bl += sz; }
        r += sz;
    }
    if (bl + 2 > cap) return 0;
    out[0] = 0x35; out[1] = (uint8_t)bl;
    memcpy(out + 2, body, bl);
    return bl + 2;
}
static void sdp_send(br_a2dp_t* a, uint8_t pdu, uint16_t tid, const uint8_t* p, size_t n)
{
    uint8_t b[5 + 200];
    if (n > 200) return;
    b[0] = pdu; b[1] = (uint8_t)(tid >> 8); b[2] = (uint8_t)tid; b[3] = (uint8_t)(n >> 8); b[4] = (uint8_t)n;
    memcpy(b + 5, p, n);
    l2_send(a, a->sdp.dcid, b, 5 + n);
}
static void sdp_error(br_a2dp_t* a, uint16_t tid, uint16_t code)
{
    const uint8_t e[2] = {(uint8_t)(code >> 8), (uint8_t)code};
    sdp_send(a, 0x01, tid, e, 2);
}
/* Attribute byte stream `full` cut at the sink's maximum byte count; continuation state = 2-byte offset. */
static void sdp_attr_response(br_a2dp_t* a, uint8_t pdu, uint16_t tid, const uint8_t* full, size_t fl, uint16_t max,
                              const uint8_t* cont, size_t cn)
{
    size_t off = 0;
    if (cn >= 1 && cont[0] == 2 && cn >= 3) off = be16(cont + 1);
    else if (cn >= 1 && cont[0] != 0) { sdp_error(a, tid, 0x0005); return; }
    if (off > fl) { sdp_error(a, tid, 0x0005); return; }
    if (max < 7) max = 7;
    if (max > 160) max = 160;
    const size_t take = fl - off < max ? fl - off : max;
    uint8_t r[2 + 160 + 3];
    r[0] = (uint8_t)(take >> 8); r[1] = (uint8_t)take;
    memcpy(r + 2, full + off, take);
    size_t rn = 2 + take;
    if (off + take < fl) { r[rn++] = 2; r[rn++] = (uint8_t)((off + take) >> 8); r[rn++] = (uint8_t)(off + take); }
    else r[rn++] = 0;
    sdp_send(a, pdu, tid, r, rn);
}
static void sdp_on(br_a2dp_t* a, const uint8_t* m, size_t n)
{
    if (n < 5) return;
    const uint8_t pdu = m[0];
    const uint16_t tid = be16(m + 1), plen = be16(m + 3);
    const uint8_t* p = m + 5;
    if ((size_t)plen + 5 > n) { sdp_error(a, tid, 0x0004); return; }
    const uint8_t *pat = NULL, *ids = NULL;
    size_t pl = 0, il = 0, used = 0, u;
    switch (pdu) {
    case 0x02: { /* ServiceSearchRequest: pattern, max count, continuation */
        if (!(used = sdp_seq(p, plen, &pat, &pl)) || used + 3 > plen) { sdp_error(a, tid, 0x0003); return; }
        const int hit = sdp_match(pat, pl) && be16(p + used) > 0;
        uint8_t r[2 + 2 + 4 + 1] = {0, (uint8_t)hit, 0, (uint8_t)hit};
        size_t rn = 4;
        if (hit) { r[4] = SDP_HANDLE >> 24; r[5] = (uint8_t)(SDP_HANDLE >> 16); r[6] = (uint8_t)(SDP_HANDLE >> 8); r[7] = (uint8_t)SDP_HANDLE; rn = 8; }
        r[rn++] = 0;
        sdp_send(a, 0x03, tid, r, rn);
        a2_log(a, "SDP: service search -> %d record(s)", hit);
        return;
    }
    case 0x04: { /* ServiceAttributeRequest: handle, max bytes, attribute IDs, continuation */
        if (plen < 6) { sdp_error(a, tid, 0x0003); return; }
        if (be32(p) != SDP_HANDLE) { sdp_error(a, tid, 0x0002); return; }
        if (!(u = sdp_seq(p + 6, plen - 6u, &ids, &il))) { sdp_error(a, tid, 0x0003); return; }
        uint8_t full[2 + sizeof kSdpRecord];
        const size_t fl = sdp_attrs(ids, il, full, sizeof full);
        sdp_attr_response(a, 0x05, tid, full, fl, be16(p + 4), p + 6 + u, plen - 6u - u);
        a2_log(a, "SDP: attributes of our record (%u bytes)", (unsigned)fl);
        return;
    }
    case 0x06: { /* ServiceSearchAttributeRequest: pattern, max bytes, attribute IDs, continuation */
        if (!(used = sdp_seq(p, plen, &pat, &pl)) || used + 2 > plen) { sdp_error(a, tid, 0x0003); return; }
        const uint16_t max = be16(p + used);
        if (!(u = sdp_seq(p + used + 2, plen - used - 2u, &ids, &il))) { sdp_error(a, tid, 0x0003); return; }
        uint8_t full[4 + sizeof kSdpRecord];
        size_t fl = 2;
        full[0] = 0x35; full[1] = 0;
        if (sdp_match(pat, pl)) {
            const size_t al = sdp_attrs(ids, il, full + 2, sizeof full - 2);
            full[1] = (uint8_t)al;
            fl += al;
        }
        sdp_attr_response(a, 0x07, tid, full, fl, max, p + used + 2 + u, plen - used - 2u - u);
        a2_log(a, "SDP: search + attributes -> %u bytes", (unsigned)fl);
        return;
    }
    default: sdp_error(a, tid, 0x0003); return;
    }
}

/* ---- AVDTP ------------------------------------------------------------------------------------------------------ */
enum { AV_CMD = 0, AV_ACCEPT = 2, AV_REJECT = 3, AV_GENERAL_REJECT = 1 };
enum { SIG_DISCOVER = 1, SIG_GET_CAPS = 2, SIG_SET_CONFIG = 3, SIG_GET_CONFIG = 4, SIG_RECONFIG = 5, SIG_OPEN = 6,
       SIG_START = 7, SIG_CLOSE = 8, SIG_SUSPEND = 9, SIG_ABORT = 10, SIG_SECURITY = 11, SIG_GET_ALL_CAPS = 12,
       SIG_DELAY_REPORT = 13 };
#define CAT_TRANSPORT 1
#define CAT_CODEC 7

static void av_send(br_a2dp_t* a, uint8_t label, uint8_t msg, uint8_t signal, const uint8_t* p, size_t n)
{
    uint8_t b[2 + 32];
    if (n > 32 || !a->sig.up) return;
    b[0] = (uint8_t)((label & 15u) << 4 | msg);
    b[1] = signal;
    if (n) memcpy(b + 2, p, n);
    l2_send(a, a->sig.dcid, b, 2 + n);
}
static void av_cmd(br_a2dp_t* a, uint8_t signal, const uint8_t* p, size_t n)
{
    a->label = (uint8_t)((a->label + 1u) & 15u);
    av_send(a, a->label, AV_CMD, signal, p, n);
}
static void local_caps(br_a2dp_t* a, uint8_t* out /* 10 */)
{
    const uint8_t c[10] = {CAT_TRANSPORT, 0, CAT_CODEC, 6, 0x00, 0x00, 0x20 | 0x10 | 0x0F, 0xF0 | 0x0C | 0x03, 2,
                           a->cfg.max_bitpool};
    memcpy(out, c, 10);
}
/* SBC codec information element (A2DP §4.3.2): 4 octets after media type / codec type. */
static int sbc_from_ie(const uint8_t* ie, size_t n, br_a2dp_stream_t* s)
{
    if (n < 6 || ie[1] != 0x00) return -1;
    const uint8_t o0 = ie[2], o1 = ie[3];
    s->freq = (o0 & 0x20) ? 44100 : (o0 & 0x10) ? 48000 : (o0 & 0x40) ? 32000 : 16000;
    s->mode = (o0 & 0x01) ? 3 : (o0 & 0x02) ? 2 : (o0 & 0x04) ? 1 : 0;
    s->blocks = (o1 & 0x10) ? 16 : (o1 & 0x20) ? 12 : (o1 & 0x40) ? 8 : 4;
    s->subbands = (o1 & 0x04) ? 8 : 4;
    s->alloc = (o1 & 0x01) ? 0 : 1;
    s->min_bitpool = ie[4];
    s->max_bitpool = ie[5];
    return 0;
}
/* Our choice for a sink capability: 44.1 kHz, joint, 16 blocks, 8 subbands, loudness when offered. */
static void choose_config(br_a2dp_t* a, const uint8_t* cap)
{
    const uint8_t o0 = cap[2], o1 = cap[3];
    const uint8_t f = (a->cfg.prefer_48k && (o0 & 0x10)) ? 0x10 : (o0 & 0x20) ? 0x20 : (o0 & 0x10) ? 0x10 : (o0 & 0x40) ? 0x40 : 0x80;
    const uint8_t m = (o0 & 0x01) ? 0x01 : (o0 & 0x02) ? 0x02 : (o0 & 0x04) ? 0x04 : 0x08;
    const uint8_t b = (o1 & 0x10) ? 0x10 : (o1 & 0x20) ? 0x20 : (o1 & 0x40) ? 0x40 : 0x80;
    const uint8_t sb = (o1 & 0x04) ? 0x04 : 0x08;
    const uint8_t al = (o1 & 0x01) ? 0x01 : 0x02;
    uint8_t maxbp = cap[5] < a->cfg.max_bitpool ? cap[5] : a->cfg.max_bitpool;
    if (maxbp < cap[4]) maxbp = cap[4];
    const uint8_t ie[6] = {0x00, 0x00, (uint8_t)(f | m), (uint8_t)(b | sb | al), cap[4], maxbp};
    memcpy(a->config_ie, ie, 6);
    sbc_from_ie(ie, 6, &a->stream);
    a->have_config = 1;
}
/* Service capabilities TLVs -> pointer to the media codec capability (len in *n) */
static const uint8_t* find_cat(const uint8_t* p, size_t n, uint8_t cat, size_t* len)
{
    for (size_t i = 0; i + 2 <= n;) {
        const uint8_t c = p[i], l = p[i + 1];
        if (i + 2 + l > n) break;
        if (c == cat) { *len = l; return p + i + 2; }
        i += 2u + l;
    }
    return NULL;
}

static void l2_progress(br_a2dp_t* a);
static void avrcp_play_changed(br_a2dp_t* a);

static void av_on_signal(br_a2dp_t* a, const uint8_t* m, size_t n)
{
    if (n < 2) return;
    if (m[0] & 0x0Cu) { a2_log(a, "AVDTP: fragmented signaling packet ignored"); return; }  /* packet type != single */
    const uint8_t label = m[0] >> 4, msg = m[0] & 3u, signal = m[1] & 0x3Fu;
    const uint8_t* p = m + 2;
    const size_t pn = n - 2;
    if (msg == AV_CMD) {
        switch (signal) {
        case SIG_DELAY_REPORT: av_send(a, label, AV_ACCEPT, signal, NULL, 0); return;
        case SIG_DISCOVER: {
            const uint8_t sep[2] = {(uint8_t)(INT_SEID << 2 | (a->have_config ? 2 : 0)), 0x00 /* audio, source */};
            av_send(a, label, AV_ACCEPT, signal, sep, 2);
            return;
        }
        case SIG_GET_CAPS:
        case SIG_GET_ALL_CAPS: {
            if (!pn || (p[0] >> 2) != INT_SEID) { const uint8_t e = 0x12; av_send(a, label, AV_REJECT, signal, &e, 1); return; }
            uint8_t c[10];
            local_caps(a, c);
            av_send(a, label, AV_ACCEPT, signal, c, 10);
            return;
        }
        case SIG_SET_CONFIG: {
            size_t cl = 0;
            const uint8_t* codec = pn >= 2 ? find_cat(p + 2, pn - 2, CAT_CODEC, &cl) : NULL;
            if (pn < 2 || (p[0] >> 2) != INT_SEID) { const uint8_t e[2] = {0, 0x12}; av_send(a, label, AV_REJECT, signal, e, 2); return; }
            if (a->have_config || !codec || cl < 6 || codec[1] != 0x00) {
                const uint8_t e[2] = {CAT_CODEC, (uint8_t)(a->have_config ? 0x13 : 0x29)};
                av_send(a, label, AV_REJECT, signal, e, 2);
                return;
            }
            memcpy(a->config_ie, codec, 6);
            sbc_from_ie(codec, 6, &a->stream);
            a->have_config = 1;
            a->peer_int = 1;
            a->sink_seid = (uint8_t)(p[1] >> 2);
            a->av_state = AV_CONFIGURED;
            a2_log(a, "AVDTP: sink configured SBC %lu Hz mode %u bitpool %u..%u", (unsigned long)a->stream.freq,
                 a->stream.mode, a->stream.min_bitpool, a->stream.max_bitpool);
            av_send(a, label, AV_ACCEPT, signal, NULL, 0);
            return;
        }
        case SIG_OPEN:
            if (!a->have_config) break;
            a->av_state = AV_NEED_MEDIA;
            av_send(a, label, AV_ACCEPT, signal, NULL, 0);
            l2_progress(a);
            return;
        case SIG_START:
            if (!a->have_config) break;
            av_send(a, label, AV_ACCEPT, signal, NULL, 0);
            a->av_state = AV_STREAMING;
            l2_progress(a);
            return;
        case SIG_SUSPEND:
        case SIG_CLOSE:
        case SIG_ABORT:
            av_send(a, label, AV_ACCEPT, signal, NULL, 0);
            if (signal != SIG_SUSPEND) a->have_config = 0;
            a->av_state = signal == SIG_SUSPEND ? AV_CONFIGURED : AV_IDLE;
            a->resuming = 0;
            a->resume_at = 0;  /* the sink paused: stay suspended until it or the application starts the stream */
            if (a->l2_state == L2_STREAMING) a->l2_state = L2_SIGNALING;
            if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_SUSPENDED, NULL);
            avrcp_play_changed(a);
            return;
        case SIG_GET_CONFIG:
            if (a->have_config && pn && (p[0] >> 2) == INT_SEID) {
                uint8_t c[2 + 2 + 6] = {CAT_TRANSPORT, 0, CAT_CODEC, 6};
                memcpy(c + 4, a->config_ie, 6);
                av_send(a, label, AV_ACCEPT, signal, c, sizeof c);
                return;
            }
            { const uint8_t e = 0x12; av_send(a, label, AV_REJECT, signal, &e, 1); }  /* BAD_ACP_SEID */
            return;
        case SIG_RECONFIG:
        case SIG_SECURITY: { const uint8_t e = 0x31; av_send(a, label, AV_REJECT, signal, &e, 1); return; }
        default: break;
        }
        av_send(a, label, AV_GENERAL_REJECT, signal, NULL, 0);
        return;
    }
    if (msg != AV_ACCEPT) {
        if (signal == SIG_START && a->av_state == AV_STREAMING) return;
        if (signal == SIG_START && a->resuming) {  /* still busy (a call, another source): stays suspended */
            a->resuming = 0;
            a->av_state = AV_CONFIGURED;
            a->l2_state = L2_SIGNALING;
            a->resume_at = 0;
            a2_log(a, "AVDTP: the sink refused START; stream stays suspended");
            if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_SUSPENDED, NULL);
            return;
        }
        if (signal == SIG_SUSPEND && a->av_state == AV_SUSPENDING) {  /* refused: the stream is still open */
            a->av_state = AV_STREAMING;
            l2_progress(a);
            return;
        }
        if (signal == SIG_GET_CAPS && a->av_state == AV_CAPS && a->sep_i + 1u < a->sep_n) {
            const uint8_t s = (uint8_t)(a->sep_cand[++a->sep_i] << 2);
            a->sink_seid = a->sep_cand[a->sep_i];
            av_cmd(a, SIG_GET_CAPS, &s, 1);
            return;
        }
        if (a->peer_int && (signal == SIG_DISCOVER || signal == SIG_GET_CAPS || signal == SIG_SET_CONFIG)) return;
        a2_log(a, "AVDTP: signal %u rejected (msg %u)", signal, msg);
        a->av_state = AV_FAIL;
        fail(a, "AVDTP command rejected");
        return;
    }
    if (a->peer_int && (signal == SIG_DISCOVER || signal == SIG_GET_CAPS || signal == SIG_GET_ALL_CAPS)) return;
    if (signal == SIG_DISCOVER && a->av_state == AV_DISCOVER) {
        /* Sinks often list several endpoints (SBC, AAC, vendor codecs) in any order: try each audio sink. */
        a->sep_n = 0; a->sep_i = 0;
        for (size_t i = 0; i + 1 < pn && a->sep_n < sizeof a->sep_cand; i += 2) {
            const uint8_t seid = p[i] >> 2, in_use = (p[i] >> 1) & 1u, media = p[i + 1] >> 4, tsep = (p[i + 1] >> 3) & 1u;
            if (tsep == 1 && media == 0 && !in_use) a->sep_cand[a->sep_n++] = seid;
        }
        if (!a->sep_n) { a->av_state = AV_FAIL; fail(a, "no audio sink endpoint"); return; }
        a->sink_seid = a->sep_cand[0];
        a->av_state = AV_CAPS;
        const uint8_t s = (uint8_t)(a->sink_seid << 2);
        av_cmd(a, SIG_GET_CAPS, &s, 1);
    } else if ((signal == SIG_GET_CAPS || signal == SIG_GET_ALL_CAPS) && a->av_state == AV_CAPS) {
        size_t cl = 0;
        const uint8_t* codec = find_cat(p, pn, CAT_CODEC, &cl);
        if (!codec || cl < 6 || codec[1] != 0x00) {
            a2_log(a, "AVDTP: sink endpoint %u is not SBC (codec %u)", a->sink_seid, codec && cl >= 2 ? codec[1] : 0xFF);
            if (a->sep_i + 1u < a->sep_n) {
                a->sink_seid = a->sep_cand[++a->sep_i];
                const uint8_t s = (uint8_t)(a->sink_seid << 2);
                av_cmd(a, SIG_GET_CAPS, &s, 1);
                return;
            }
            a->av_state = AV_FAIL;
            fail(a, "sink has no SBC");
            return;
        }
        {   /* the sink's full capability list for this endpoint, for diagnosis */
            char dump[2 * 40 + 1];
            const char* digits = "0123456789ABCDEF";
            const size_t dn = pn < 40 ? pn : 40;
            for (size_t i = 0; i < dn; ++i) { dump[2 * i] = digits[p[i] >> 4]; dump[2 * i + 1] = digits[p[i] & 15]; }
            dump[2 * dn] = 0;
            a2_log(a, "AVDTP: sink endpoint %u capabilities %s", a->sink_seid, dump);
        }
        choose_config(a, codec);
        a->av_state = AV_CONFIGURE;
        uint8_t c[2 + 2 + 2 + 6];
        c[0] = (uint8_t)(a->sink_seid << 2); c[1] = INT_SEID << 2;
        c[2] = CAT_TRANSPORT; c[3] = 0; c[4] = CAT_CODEC; c[5] = 6;
        memcpy(c + 6, a->config_ie, 6);
        av_cmd(a, SIG_SET_CONFIG, c, sizeof c);
    } else if (signal == SIG_SET_CONFIG && a->av_state == AV_CONFIGURE) {
        a->av_state = AV_OPEN;
        const uint8_t s = (uint8_t)(a->sink_seid << 2);
        av_cmd(a, SIG_OPEN, &s, 1);
    } else if (signal == SIG_OPEN && a->av_state == AV_OPEN) {
        a->av_state = AV_NEED_MEDIA;
        l2_progress(a);
    } else if (signal == SIG_START && a->av_state == AV_STARTING) {
        a->av_state = AV_STREAMING;
        l2_progress(a);
    } else if (signal == SIG_SUSPEND && a->av_state == AV_SUSPENDING) {
        a->av_state = AV_CONFIGURED;
        a->resuming = 0;
        a->resume_at = 0;
        a2_log(a, "AVDTP: stream suspended");
        if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_SUSPENDED, NULL);
        avrcp_play_changed(a);
    }
}

/* ---- L2CAP channel management ----------------------------------------------------------------------------------- */
static void l2_progress(br_a2dp_t* a)
{
    const uint32_t t = now(a);
    if (a->sig.up && (a->l2_state == L2_SIG_CONNECTING || a->l2_state == L2_WAIT_SINK)) {
        a->t_sig_up = t;
        if (a->sig.incoming) {
            a->l2_state = L2_SIGNALING_ACP;
            a2_log(a, "L2CAP: sink opened AVDTP signaling; waiting for its configuration");
        } else {
            a->l2_state = L2_SIGNALING;
            a->av_state = AV_DISCOVER;
            av_cmd(a, SIG_DISCOVER, NULL, 0);
        }
    }
    if (a->av_state == AV_NEED_MEDIA && !a->t_need_media) a->t_need_media = t ? t : 1;
    if (a->av_state == AV_NEED_MEDIA && !a->media.used && !a->peer_int) {
        a->l2_state = L2_MEDIA_CONNECTING;
        ch_connect(a, &a->media, MEDIA_SCID);
    }
    if (a->media.up && a->av_state == AV_NEED_MEDIA) {
        a->l2_state = L2_STARTING;
        a->av_state = AV_STARTING;
        const uint8_t s = (uint8_t)(a->sink_seid << 2);
        av_cmd(a, SIG_START, &s, 1);
    }
    if (a->av_state == AV_STREAMING && a->l2_state != L2_STREAMING && a->media.up) {
        a->l2_state = L2_STREAMING;
        a->resuming = 0;
        a->stream.media_cid = a->media.dcid;
        a->stream.media_mtu = a->media.peer_mtu;
        a2_log(a, "AVDTP: streaming, media CID 0x%04X MTU %u", a->media.dcid, a->media.peer_mtu);
        if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_STREAMING, &a->stream);
        avrcp_play_changed(a);
    }
}

static void l2_on_signaling(br_a2dp_t* a, const uint8_t* p, size_t n)
{
    for (size_t i = 0; i + 4 <= n;) {
        const uint8_t code = p[i], ident = p[i + 1];
        const uint16_t len = get16(p + i + 2);
        const uint8_t* d = p + i + 4;
        if (i + 4 + len > n) break;
        i += 4u + len;
        if (code == 0x02 && len >= 4) { /* connection request from the sink */
            const uint16_t psm = get16(d), scid = get16(d + 2);
            br_a2dp_ch_t* c = NULL;
            uint16_t mine = 0;
            if (psm == PSM_AVDTP && !a->sig.used) { c = &a->sig; mine = SIG_SCID; }
            else if (psm == PSM_AVDTP && !a->media.used && a->av_state == AV_NEED_MEDIA) { c = &a->media; mine = MEDIA_SCID; }
            else if (psm == PSM_SDP && !a->sdp.used) { c = &a->sdp; mine = SDP_SCID; }
            else if (psm == PSM_AVCTP && !a->avctp.used) { c = &a->avctp; mine = AVCTP_CID; }
            uint8_t r[8];
            if (!c) {
                put16(r, 0); put16(r + 2, scid); put16(r + 4, psm == PSM_AVDTP ? 0x0004 : 0x0002); put16(r + 6, 0);
                sig(a, 0x03, ident, r, 8);
                if (psm == PSM_AVCTP) a2_log(a, "headphone remote controls disabled (AVCTP refused)");
                else a2_log(a, "L2CAP: refused incoming PSM 0x%04X", psm);
                continue;
            }
            memset(c, 0, sizeof *c);
            c->used = 1; c->incoming = 1; c->scid = mine; c->dcid = scid; c->peer_mtu = 672;
            if ((c == &a->sig || c == &a->media) && a->l2_state == L2_OFF) {
                a->l2_state = L2_WAIT_SINK; a->t_l2_start = now(a);
            }
            if (c == &a->media) a->l2_state = L2_MEDIA_CONNECTING;
            put16(r, mine); put16(r + 2, scid); put16(r + 4, 0); put16(r + 6, 0);
            sig(a, 0x03, ident, r, 8);
            ch_cfg_req(a, scid);
            a2_log(a, "L2CAP: accepted incoming %s channel -> 0x%04X",
                   psm == PSM_SDP ? "SDP" : psm == PSM_AVCTP ? "AVCTP" : "AVDTP", mine);
        } else if (code == 0x03 && len >= 8) { /* connection response */
            br_a2dp_ch_t* c = ch_by_scid(a, get16(d + 2));
            const uint16_t result = get16(d + 4);
            if (!c) continue;
            if (result == 0) { c->dcid = get16(d); ch_cfg_req(a, c->dcid); }
            else if (result != 1) { a2_log(a, "L2CAP: connect refused %u", result); fail(a, "L2CAP connect refused"); }
        } else if (code == 0x04 && len >= 4) { /* configure request for one of our channels */
            br_a2dp_ch_t* c = ch_by_scid(a, get16(d));
            for (size_t k = 4; c && k + 2 <= len;) {
                const uint8_t t = d[k], l = d[k + 1];
                if ((t & 0x7F) == 0x01 && l == 2 && k + 4 <= len) c->peer_mtu = get16(d + k + 2);
                k += 2u + l;
            }
            uint8_t r[6];
            put16(r, c ? c->dcid : 0); put16(r + 2, 0); put16(r + 4, c ? 0 : 0x0002);
            sig(a, 0x05, ident, r, 6);
            if (c) c->cfg_in = 1;
        } else if (code == 0x05 && len >= 6) { /* response to our configure request */
            br_a2dp_ch_t* c = ch_by_scid(a, get16(d));
            const uint16_t result = get16(d + 4);
            if (c && result != 4) {  /* 4 = pending: the final response follows */
                c->cfg_out = result == 0;
                if (!c->cfg_out) { a2_log(a, "L2CAP: configuration result %u", result); fail(a, "L2CAP configuration refused"); }
            }
        } else if (code == 0x0A && len >= 2) { /* information request */
            const uint16_t type = get16(d);
            uint8_t r[12];
            put16(r, type);
            if (type == 2) { put16(r + 2, 0); memset(r + 4, 0, 4); sig(a, 0x0B, ident, r, 8); }
            else if (type == 3) { put16(r + 2, 0); memset(r + 4, 0, 8); r[4] = 0x02; sig(a, 0x0B, ident, r, 12); }
            else { put16(r + 2, 1); sig(a, 0x0B, ident, r, 4); }
        } else if (code == 0x08) {
            sig(a, 0x09, ident, d, len > 48 ? 48 : len);
        } else if (code == 0x06 && len >= 4) { /* disconnection request */
            sig(a, 0x07, ident, d, 4);
            br_a2dp_ch_t* c = ch_by_scid(a, get16(d));
            if (c) {
                c->up = 0;
                a2_log(a, "L2CAP: sink disconnected channel 0x%04X", c->scid);
                if (c == &a->media && a->l2_state == L2_STREAMING) {
                    a->l2_state = L2_SIGNALING;
                    if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_SUSPENDED, NULL);
                }
                c->used = 0;
            }
        }
    }
    br_a2dp_ch_t* cs[4] = {&a->sig, &a->media, &a->sdp, &a->avctp};
    for (int k = 0; k < 4; ++k)
        if (cs[k]->used && cs[k]->cfg_in && cs[k]->cfg_out && !cs[k]->up && cs[k]->dcid) cs[k]->up = 1;
    l2_progress(a);
}

/* AVRCP play status: 0x01 playing while the AVDTP stream is started, 0x02 paused otherwise. */
static uint8_t avrcp_play_status(const br_a2dp_t* a) { return a->av_state == AV_STREAMING ? 0x01 : 0x02; }

/* Completes a registered EVENT_PLAYBACK_STATUS_CHANGED notification (AVRCP 6.7.2): one CHANGED response, then the
 * controller registers again. */
static void avrcp_play_changed(br_a2dp_t* a)
{
    if (!a->avrcp_notify || !a->avctp.used || !a->avctp.up) return;
    a->avrcp_notify = 0;
    const uint8_t out[15] = {(uint8_t)(a->avrcp_notify_tid | 0x02), AVCTP_PID_AVRCP >> 8, AVCTP_PID_AVRCP & 0xFF,
                             0x0D /* CHANGED */, a->avrcp_notify_subunit, 0x00, 0x00, 0x19, 0x58, 0x31, 0, 0, 2,
                             0x01, avrcp_play_status(a)};
    l2_send(a, a->avctp.dcid, out, sizeof out);
    a2_log(a, "AVRCP: play status changed -> %s", out[14] == 0x01 ? "playing" : "paused");
}

/* AVCTP single-packet transport and the small AVRCP target surface used by headset controls. */
static void avctp_on(br_a2dp_t* a, const uint8_t* p, size_t n)
{
    if (n < 3) return;
    const uint8_t avctp = p[0];
    const uint8_t tid = avctp & 0xF0;
    const uint8_t packet_type = (avctp >> 2) & 0x03;
    const bool command = (avctp & 0x02) == 0;
    if (!command) return;
    if (packet_type != 0) {
        a2_log(a, "AVCTP: unsupported fragmented packet type %u", packet_type);
        return;
    }
    const uint16_t pid = (uint16_t)((uint16_t)p[1] << 8 | p[2]);
    uint8_t out[260] = {(uint8_t)(tid | 0x02), AVCTP_PID_AVRCP >> 8, AVCTP_PID_AVRCP & 0xFF};
    size_t out_len = 3;
    if (pid != AVCTP_PID_AVRCP) {
        out[0] |= 0x01; /* invalid profile identifier */
        out[1] = p[1]; out[2] = p[2];
        l2_send(a, a->avctp.dcid, out, out_len);
        a2_log(a, "AVCTP: rejected PID 0x%04X", pid);
        return;
    }
    if (n < 6 || n - 3 > sizeof(out) - 3) return; /* AV/C header is three octets */
    const uint8_t* avc = p + 3;
    const size_t avc_len = n - 3;
    uint8_t* rsp = out + 3;
    if (avc[2] == 0x7C && avc_len >= 5) { /* PASS THROUGH */
        const uint8_t op = avc[3] & 0x7F;
        const bool supported = op == 0x44 || op == 0x45 || op == 0x46 || op == 0x4B || op == 0x4C;
        rsp[0] = supported ? 0x09 : 0x08; /* ACCEPTED / NOT IMPLEMENTED */
        memcpy(rsp + 1, avc + 1, avc_len - 1);
        out_len += avc_len;
        if (supported) {
            const br_a2dp_remote_t event = {op, (uint8_t)((avc[3] & 0x80) == 0)};
            a2_log(a, "AVRCP: operation 0x%02X %s", op, event.pressed ? "pressed" : "released");
            if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_REMOTE, &event);
        } else a2_log(a, "AVRCP: unsupported pass-through operation 0x%02X", op);
    } else if (avc[2] == 0x30 && avc_len >= 3) { /* UNIT INFO */
        rsp[0] = 0x0C; rsp[1] = 0x07; rsp[2] = 0x30; rsp[3] = 0xFF;
        rsp[4] = 0x00; rsp[5] = 0xFF; rsp[6] = 0xFF;
        out_len = 10;
    } else if (avc[2] == 0x31 && avc_len >= 3) { /* SUBUNIT INFO: one panel subunit */
        rsp[0] = 0x0C; rsp[1] = avc[1]; rsp[2] = 0x31; rsp[3] = 0x48;
        memset(rsp + 4, 0xFF, 4);
        out_len = 11;
    } else if (avc[2] == 0x00 && avc_len >= 11 && avc[6] == 0x10 && avc[7] == 0 &&
               avc[8] == 0 && avc[9] == 1) { /* AVRCP GetCapabilities */
        const uint8_t cap = avc[10];
        rsp[0] = 0x0C; rsp[1] = avc[1]; rsp[2] = 0x00;
        memcpy(rsp + 3, avc + 3, 4); /* Company ID and PDU ID */
        rsp[7] = 0; /* single response packet */
        if (cap == 0x02) { /* company IDs: Bluetooth SIG */
            rsp[8] = 0; rsp[9] = 4;
            rsp[10] = cap; rsp[11] = 1; rsp[12] = 0x00; rsp[13] = 0x19; rsp[14] = 0x58;
            out_len = 18;
        } else if (cap == 0x03) { /* play-status-change notification */
            rsp[8] = 0; rsp[9] = 3;
            rsp[10] = cap; rsp[11] = 1; rsp[12] = 0x01;
            out_len = 16;
        } else {
            rsp[0] = 0x0A; /* REJECTED */
            rsp[7] = 0; rsp[8] = 0; rsp[9] = 1; rsp[10] = 0x01;
            out_len = 14;
        }
        a2_log(a, "AVRCP: GetCapabilities 0x%02X", cap);
    } else if (avc[2] == 0x00 && avc_len >= 15 && avc[6] == 0x31 && avc[7] == 0 &&
               avc[8] == 0 && avc[9] == 5 && avc[10] == 0x01) { /* RegisterNotification: play status */
        rsp[0] = 0x0F; rsp[1] = avc[1]; rsp[2] = 0x00;
        memcpy(rsp + 3, avc + 3, 4); /* Company ID and PDU ID */
        rsp[7] = 0; rsp[8] = 0; rsp[9] = 2;
        rsp[10] = 0x01; /* event: play status changed */
        rsp[11] = avrcp_play_status(a);
        out_len = 15;
        a->avrcp_notify = 1;
        a->avrcp_notify_tid = tid;
        a->avrcp_notify_subunit = avc[1];
        a2_log(a, "AVRCP: play-status notification registered (%s)",
               rsp[11] == 0x01 ? "playing" : "paused");
    } else {
        rsp[0] = 0x08; /* NOT IMPLEMENTED */
        memcpy(rsp + 1, avc + 1, avc_len - 1);
        out_len += avc_len;
        char dump[65];
        const char* digits = "0123456789ABCDEF";
        const size_t dump_n = avc_len < 32 ? avc_len : 32;
        for (size_t i = 0; i < dump_n; ++i) { dump[2 * i] = digits[avc[i] >> 4]; dump[2 * i + 1] = digits[avc[i] & 0x0F]; }
        dump[2 * dump_n] = 0;
        a2_log(a, "AVRCP: unsupported opcode 0x%02X data %s", avc[2], dump);
    }
    l2_send(a, a->avctp.dcid, out, out_len);
}

static void l2_on_frame(br_a2dp_t* a, uint16_t cid, const uint8_t* p, size_t n)
{
    if (cid == 0x0001) l2_on_signaling(a, p, n);
    else if (a->sig.used && cid == a->sig.scid) av_on_signal(a, p, n);
    else if (a->sdp.used && a->sdp.up && cid == a->sdp.scid) sdp_on(a, p, n);
    else if (a->avctp.used && a->avctp.up && cid == a->avctp.scid) avctp_on(a, p, n);
}

static void l2_start(br_a2dp_t* a)
{
    if (a->l2_state != L2_OFF) return;
    a->t_l2_start = now(a);
    a->l2_state = L2_WAIT_SINK;
}

/* ---- authentication + encryption -------------------------------------------------------------------------------- */
static void auth_start(br_a2dp_t* a)
{
    if (a->auth_state != AU_IDLE) return;
    a->io.random(a->io.ctx, a->au_rand, 16);
    a->auth_state = AU_RAND;
    lmp(a, OP_AU_RAND, 0, a->au_rand, 16);
}

/* Key size agreed: Kc from the ACO of the last authentication, reduced to the key size, then start encryption. */
static void enc_start(br_a2dp_t* a)
{
    a->io.random(a->io.ctx, a->en_rand, 16);
    uint8_t kc[16];
    br_e3(a->cfg.link_key, a->en_rand, a->aco, kc);
    br_e0_key_reduce(kc, a->key_size ? a->key_size : 16, a->kc);
    a->auth_state = AU_START_ENC;
    a->io.set_enc(a->io.ctx, 2, a->kc, a->cfg.own_addr); /* the sink encrypts its accept */
    lmp(a, OP_START_ENC_REQ, 0, a->en_rand, 16);
}

/* Returns 1 if consumed. */
static int auth_on(br_a2dp_t* a, uint8_t op, uint8_t tid, const uint8_t* p, size_t n)
{
    if (op == OP_AU_RAND && n >= 16) {
        if (!a->key_ok) { lmp_reject(a, tid, OP_AU_RAND, 0x06); return 1; }
        uint8_t sres[4], aco[12];
        br_e1(a->cfg.link_key, p, a->cfg.own_addr, sres, aco);
        memcpy(a->aco, aco, 12); /* Kc uses the ACO of the most recent authentication */
        lmp(a, OP_SRES, tid, sres, 4);
        return 1;
    }
    if (op == OP_SRES && a->auth_state == AU_RAND && n >= 4) {
        uint8_t sres[4], aco[12];
        br_e1(a->cfg.link_key, a->au_rand, a->cfg.peer_addr, sres, aco);
        if (memcmp(sres, p, 4) != 0) {
            a->auth_state = AU_FAIL;
            a2_log(a, "auth: SRES mismatch (wrong link key)");
            fail(a, "authentication failed (link key)");
            return 1;
        }
        memcpy(a->aco, aco, 12);
        a->auth_state = AU_ENC_MODE;
        const uint8_t mode = 1;
        lmp(a, OP_ENC_MODE_REQ, 0, &mode, 1);
        return 1;
    }
    if (op == OP_ACCEPTED && n >= 1 && p[0] == OP_ENC_MODE_REQ && a->auth_state == AU_ENC_MODE) {
        a->auth_state = AU_KEY_SIZE;
        const uint8_t sz = 16;
        lmp(a, OP_ENC_KEY_SIZE_REQ, 0, &sz, 1);
        return 1;
    }
    if (op == OP_ENC_KEY_SIZE_REQ) {
        /* Core Vol 2 Part C 4.2.5.4: a sink that cannot use our size answers with its own proposal. 7 is the
         * smallest size we take (the Core minimum; below that the key is not worth having). */
        const uint8_t sz = n ? p[0] : 0;
        if (a->auth_state != AU_KEY_SIZE) { lmp_accept(a, tid, OP_ENC_KEY_SIZE_REQ); return 1; }
        if (sz < 7 || sz > 16) {
            lmp_reject(a, tid, OP_ENC_KEY_SIZE_REQ, 0x20);
            a->auth_state = AU_FAIL;
            fail(a, "encryption key size too small");
            return 1;
        }
        a2_log(a, "sink proposed key size %u", sz);
        a->key_size = sz;
        lmp_accept(a, tid, OP_ENC_KEY_SIZE_REQ);
        enc_start(a);
        return 1;
    }
    if (op == OP_ACCEPTED && n >= 1 && p[0] == OP_ENC_KEY_SIZE_REQ && a->auth_state == AU_KEY_SIZE) {
        enc_start(a);
        return 1;
    }
    if (op == OP_ACCEPTED && n >= 1 && p[0] == OP_START_ENC_REQ && a->auth_state == AU_START_ENC) {
        a->auth_state = AU_ENCRYPTED;
        a->io.set_enc(a->io.ctx, 1, a->kc, a->cfg.own_addr);
        a2_log(a, "encryption on");
        if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_ENCRYPTED, NULL);
        { const uint8_t off = 0; a->name_state = 1; lmp(a, OP_NAME_REQ, 0, &off, 1); }  /* for the saved-device list */
        l2_start(a);
        return 1;
    }
    if (op == OP_NOT_ACCEPTED && n >= 2 &&
        (p[0] == OP_AU_RAND || p[0] == OP_ENC_MODE_REQ || p[0] == OP_ENC_KEY_SIZE_REQ || p[0] == OP_START_ENC_REQ)) {
        a->auth_state = AU_FAIL;
        a2_log(a, "auth/encryption refused: op %u err 0x%02X", p[0], p[1]);
        fail(a, p[0] == OP_AU_RAND && p[1] == 0x06 ? "sink has no key for us (pair again)" : "encryption refused");
        return 1;
    }
    return 0;
}

/* ---- SSP Just Works (initiator) --------------------------------------------------------------------------------- */
static void ssp_start(br_a2dp_t* a)
{
    if (a->ssp_state != SSP_IDLE) return;
    do a->io.random(a->io.ctx, a->d, 24);
    while (!br_p192_private_ok(a->d));
    br_p192_public(a->d, a->pk_x, a->pk_y);
    a->io.random(a->io.ctx, a->na, 16);
    a->ssp_state = SSP_IOCAP;
    lmp_ext(a, EXT_IO_CAP_REQ, 0, kIocap, 3);
}

static void ssp_send_chunk(br_a2dp_t* a)
{
    const uint8_t* src = a->ssp_chunk == 0 ? a->pk_x : a->ssp_chunk == 1 ? a->pk_x + 16 : a->pk_y + 8;
    uint8_t c[16];
    if (a->ssp_chunk == 1) { memcpy(c, a->pk_x + 16, 8); memcpy(c + 8, a->pk_y, 8); }
    else memcpy(c, src, 16);
    lmp(a, OP_ENCAP_PAYLOAD, 0, c, 16);
    ++a->ssp_chunk;
}

static int ssp_on(br_a2dp_t* a, uint8_t op, uint8_t ext, uint8_t tid, const uint8_t* p, size_t n)
{
    if (op == OP_ESCAPE4 && ext == EXT_IO_CAP_RES && a->ssp_state == SSP_IOCAP && n >= 3) {
        memcpy(a->peer_iocap, p, 3);
        a->ssp_state = SSP_KEY_HDR;
        a->ssp_chunk = 0;
        const uint8_t h[3] = {1, 1, 48};
        lmp(a, OP_ENCAP_HEADER, 0, h, 3);
        return 1;
    }
    if (a->ssp_state == SSP_IDLE || a->ssp_state == SSP_PAIRED || a->ssp_state == SSP_FAIL) return 0;
    if (op == OP_ACCEPTED && n >= 1 && p[0] == OP_ENCAP_HEADER && a->ssp_state == SSP_KEY_HDR) {
        a->ssp_state = SSP_KEY_PL;
        ssp_send_chunk(a);
        return 1;
    }
    if (op == OP_ACCEPTED && n >= 1 && p[0] == OP_ENCAP_PAYLOAD && a->ssp_state == SSP_KEY_PL) {
        if (a->ssp_chunk < 3) ssp_send_chunk(a);
        else a->ssp_state = SSP_PEER_KEY;
        return 1;
    }
    if (op == OP_ENCAP_HEADER) { a->peer_key_len = 0; lmp_accept(a, tid, OP_ENCAP_HEADER); return 1; }
    if (op == OP_ENCAP_PAYLOAD && n >= 16) {
        if (a->peer_key_len + 16u <= 48u) { memcpy(a->peer_key + a->peer_key_len, p, 16); a->peer_key_len += 16; }
        lmp_accept(a, tid, OP_ENCAP_PAYLOAD);
        if (a->peer_key_len == 48) {
            if (br_p192_dhkey(a->d, a->peer_key, a->peer_key + 24, a->dhkey) != 0) {
                a->ssp_state = SSP_FAIL;
                fail(a, "pairing: peer public key not on P-192");
            } else {
                a->ssp_state = SSP_WAIT_CONFIRM;
            }
        }
        return 1;
    }
    if (op == OP_SP_CONFIRM && n >= 16) {
        memcpy(a->cb, p, 16);
        a->ssp_state = SSP_WAIT_NUMBER;
        lmp(a, OP_SP_NUMBER, 0, a->na, 16);
        return 1;
    }
    if (op == OP_ACCEPTED && n >= 1 && p[0] == OP_SP_NUMBER) return 1;
    if (op == OP_SP_NUMBER && n >= 16) {
        memcpy(a->nb, p, 16);
        uint8_t cb[16];
        br_ssp_f1(a->peer_key, a->pk_x, 24, a->nb, 0, cb);
        lmp_accept(a, tid, OP_SP_NUMBER);
        if (memcmp(cb, a->cb, 16) != 0) {
            a->ssp_state = SSP_FAIL;
            fail(a, "pairing: confirm value mismatch");
            return 1;
        }
        static const uint8_t zero[16] = {0};
        uint8_t ea[16];
        br_ssp_f3(a->dhkey, 24, a->na, a->nb, zero, kIocap, a->cfg.own_addr, a->cfg.peer_addr, ea);
        a->ssp_state = SSP_WAIT_DHKEY;
        lmp(a, OP_DHKEY_CHECK, 0, ea, 16);
        return 1;
    }
    if (op == OP_ACCEPTED && n >= 1 && p[0] == OP_DHKEY_CHECK) return 1;
    if (op == OP_DHKEY_CHECK && n >= 16) {
        static const uint8_t zero[16] = {0};
        uint8_t eb[16];
        br_ssp_f3(a->dhkey, 24, a->nb, a->na, zero, a->peer_iocap, a->cfg.peer_addr, a->cfg.own_addr, eb);
        if (memcmp(eb, p, 16) != 0) {
            lmp_reject(a, tid, OP_DHKEY_CHECK, 0x05);
            a->ssp_state = SSP_FAIL;
            fail(a, "pairing: DHKey check failed");
            return 1;
        }
        lmp_accept(a, tid, OP_DHKEY_CHECK);
        br_ssp_f2(a->dhkey, 24, a->na, a->nb, BR_SSP_KEYID_BTLK, a->cfg.own_addr, a->cfg.peer_addr, a->cfg.link_key);
        a->cfg.have_key = 1;
        a->key_ok = 1;
        a->ssp_state = SSP_PAIRED;
        a2_log(a, "paired (SSP Just Works)");
        if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_PAIRED, a->cfg.link_key);
        auth_start(a);
        return 1;
    }
    if ((op == OP_NOT_ACCEPTED && n >= 2 &&
         (p[0] == OP_ENCAP_HEADER || p[0] == OP_ENCAP_PAYLOAD || p[0] == OP_SP_NUMBER || p[0] == OP_DHKEY_CHECK)) ||
        (op == OP_ESCAPE4 && ext == EXT_NOT_ACCEPTED && n >= 2 && p[1] == EXT_IO_CAP_REQ)) {
        a->ssp_state = SSP_FAIL;
        a2_log(a, "pairing refused (op %u, err 0x%02X)", p[0], n >= 3 ? p[n - 1] : p[1]);
        fail(a, "pairing refused (is the sink in pairing mode?)");
        return 1;
    }
    return 0;
}

/* ---- LMP responder ---------------------------------------------------------------------------------------------- */
static void respond(br_a2dp_t* a, uint8_t op, uint8_t ext, uint8_t tid, const uint8_t* p, size_t n)
{
    switch (op) {
    case OP_FEATURES_REQ: lmp(a, OP_FEATURES_RES, tid, kFeatures0, 8); return;
    case OP_VERSION_REQ: { const uint8_t v[5] = {0x08, 0xFF, 0xFF, 0x01, 0x00}; lmp(a, OP_VERSION_RES, tid, v, 5); return; }
    case OP_NAME_REQ: {
        const char* nm = a->cfg.name ? a->cfg.name : "Tab5";
        const size_t len = strlen(nm), off = n ? p[0] : 0;
        uint8_t r[16] = {0};
        r[0] = (uint8_t)off; r[1] = (uint8_t)len;
        if (off < len) memcpy(r + 2, nm + off, len - off > 14 ? 14 : len - off);
        lmp(a, OP_NAME_RES, tid, r, 16);
        return;
    }
    case OP_TIMING_ACC_REQ: { const uint8_t r[2] = {250, 10}; lmp(a, OP_TIMING_ACC_RES, tid, r, 2); return; }
    case OP_CLKOFFSET_REQ: { const uint8_t r[2] = {0, 0}; lmp(a, OP_CLKOFFSET_RES, tid, r, 2); return; }
    case OP_PAGE_MODE_REQ: case OP_PAGE_SCAN_MODE_REQ: case OP_QOS_REQ: case OP_HOST_CONN_REQ:
        lmp_accept(a, tid, op); return;
    case OP_KEY_SIZE_MASK_REQ: { const uint8_t r[2] = {0xFF, 0xFF}; lmp(a, OP_KEY_SIZE_MASK_RES, tid, r, 2); return; }
    case OP_SWITCH_REQ: case OP_MAX_SLOT_REQ: case OP_SNIFF_REQ: case OP_HOLD_REQ: case OP_INCR_POWER_REQ:
    case OP_DECR_POWER_REQ:
        lmp_reject(a, tid, op, 0x1A); return;
    case OP_ESCAPE4:
        if (ext == EXT_FEATURES_REQ) {
            const uint8_t page = n ? p[0] : 0;
            uint8_t r[10] = {page, 1};
            memcpy(r + 2, page == 0 ? kFeatures0 : page == 1 ? kFeatures1 : (const uint8_t*)"\0\0\0\0\0\0\0\0", 8);
            lmp_ext(a, EXT_FEATURES_RES, tid, r, 10);
            return;
        }
        if (ext == EXT_PING_REQ) { lmp_ext(a, EXT_PING_RES, tid, NULL, 0); return; }
        if (ext == EXT_ACCEPTED || ext == EXT_NOT_ACCEPTED || ext == EXT_FEATURES_RES || ext == EXT_PING_RES) return;
        { const uint8_t r[3] = {OP_ESCAPE4, ext, 0x19}; lmp_ext(a, EXT_NOT_ACCEPTED, tid, r, 3); }
        return;
    default: break;
    }
    for (size_t i = 0; i < sizeof kSilent; ++i)
        if (kSilent[i] == op) return;
    lmp_reject(a, tid, op, 0x19);
}

static void lmp_on(br_a2dp_t* a, const uint8_t* d, size_t n)
{
    if (!n) return;
    const uint8_t tid = d[0] & 1u, op = d[0] >> 1;
    uint8_t ext = 0;
    const uint8_t* p = d + 1;
    size_t pn = n - 1;
    if (op == OP_ESCAPE4) {
        if (!pn) return;
        ext = p[0]; ++p; --pn;
    }
    if (op == OP_DETACH) {
        const uint8_t reason = pn ? p[0] : 0;
        a2_log(a, "sink detached (reason 0x%02X)", reason);
        if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_DETACHED, &reason);
        return;
    }
    if (op == OP_ACCEPTED && pn >= 1 && p[0] == OP_HOST_CONN_REQ && !a->setup_sent) {
        /* setup_complete only after the sink accepted host_connection_req (it may ask for a role switch first) */
        a->setup_sent = 1;
        lmp(a, OP_SETUP_COMPLETE, 0, NULL, 0);
        return;
    }
    if (op == OP_SETUP_COMPLETE) {
        if (!a->peer_setup) { a->peer_setup = 1; a->t_setup = now(a); }
        return;
    }
    if (op == OP_NAME_RES && a->name_state == 1 && pn >= 2) {
        /* name_res: offset, total length, 14 bytes of the name */
        const size_t off = p[0], len = p[1] < BR_A2DP_NAME_MAX ? p[1] : BR_A2DP_NAME_MAX;
        for (size_t i = 0; i < 14 && off + i < len && 2 + i < pn; ++i) a->peer_name[off + i] = (char)p[2 + i];
        if (off + 14 < len) {
            const uint8_t next = (uint8_t)(off + 14);
            lmp(a, OP_NAME_REQ, 0, &next, 1);
            return;
        }
        a->name_state = 2;
        a->peer_name[len] = '\0';
        a2_log(a, "sink name '%s'", a->peer_name);
        if (len && a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_NAME, a->peer_name);
        return;
    }
    if (ssp_on(a, op, ext, tid, p, pn)) return;
    if (op != OP_ESCAPE4 && auth_on(a, op, tid, p, pn)) return;
    respond(a, op, ext, tid, p, pn);
}

/* ---- public API ------------------------------------------------------------------------------------------------- */
void br_a2dp_init(br_a2dp_t* a, const br_a2dp_cfg_t* cfg, const br_a2dp_io_t* io)
{
    memset(a, 0, sizeof *a);
    a->cfg = *cfg;
    a->io = *io;
    if (!a->cfg.max_bitpool) a->cfg.max_bitpool = 20;
    if (!a->cfg.avdtp_passive_ms) a->cfg.avdtp_passive_ms = 1500;
    a->key_ok = a->cfg.have_key;
}

void br_a2dp_connected(br_a2dp_t* a)
{
    const uint8_t v[5] = {0x08, 0xFF, 0xFF, 0x00, 0x00};
    lmp(a, OP_VERSION_REQ, 0, v, 5);
    lmp(a, OP_FEATURES_REQ, 0, kFeaturesReq, 8);
    lmp(a, OP_HOST_CONN_REQ, 0, NULL, 0);
}

void br_a2dp_rx(br_a2dp_t* a, uint8_t llid, const uint8_t* data, size_t len)
{
    if (llid == 3) { lmp_on(a, data, len); return; }
    if (llid == 2) a->rx_len = 0;
    else if (llid != 1 || !a->rx_len) return;
    if (a->rx_len + len > sizeof a->rx) { a->rx_len = 0; return; }
    memcpy(a->rx + a->rx_len, data, len);
    a->rx_len = (uint16_t)(a->rx_len + len);
    while (a->rx_len >= 4) {
        const uint16_t flen = get16(a->rx), cid = get16(a->rx + 2);
        if (a->rx_len < 4u + flen) break;
        l2_on_frame(a, cid, a->rx + 4, flen);
        memmove(a->rx, a->rx + 4 + flen, a->rx_len - 4u - flen);
        a->rx_len = (uint16_t)(a->rx_len - 4u - flen);
    }
}

void br_a2dp_poll(br_a2dp_t* a)
{
    if (a->failed) return;
    const uint32_t t = now(a);
    if (a->peer_setup && t - a->t_setup > 1000) {
        if (a->key_ok && a->auth_state == AU_IDLE) auth_start(a);
        else if (!a->key_ok && a->cfg.pair && a->ssp_state == SSP_IDLE) ssp_start(a);
        else if (!a->key_ok && !a->cfg.pair && a->ssp_state == SSP_IDLE) { fail(a, "no link key and pairing off"); return; }
    }
    if (a->l2_state == L2_WAIT_SINK && !a->sig.used && t - a->t_l2_start > a->cfg.avdtp_passive_ms) {
        a->l2_state = L2_SIG_CONNECTING;
        ch_connect(a, &a->sig, SIG_SCID);
    }
    if (a->l2_state == L2_SIGNALING_ACP && a->av_state == AV_IDLE && !a->have_config && t - a->t_sig_up > 3000) {
        a->l2_state = L2_SIGNALING;
        a->av_state = AV_DISCOVER;
        a2_log(a, "AVDTP: sink silent, running our discover");
        av_cmd(a, SIG_DISCOVER, NULL, 0);
    }
    if (a->resume_at && !a->resuming && a->av_state == AV_CONFIGURED && a->have_config && a->media.up &&
        (int32_t)(t - a->resume_at) >= 0) {
        a->resume_at = 0;
        a->resuming = 1;
        a->av_state = AV_STARTING;
        a->l2_state = L2_STARTING;
        a2_log(a, "AVDTP: restarting the suspended stream");
        const uint8_t s = (uint8_t)(a->sink_seid << 2);
        av_cmd(a, SIG_START, &s, 1);
    }
    if (a->av_state == AV_NEED_MEDIA && !a->media.used && a->t_need_media && t - a->t_need_media > 3000) {
        a->l2_state = L2_MEDIA_CONNECTING;
        ch_connect(a, &a->media, MEDIA_SCID);
    }
}

void br_a2dp_detach(br_a2dp_t* a, uint8_t reason) { lmp(a, OP_DETACH, 0, &reason, 1); }

int br_a2dp_streaming(const br_a2dp_t* a) { return a->l2_state == L2_STREAMING; }

int br_a2dp_suspend(br_a2dp_t* a)
{
    /* called again while the SUSPEND is unanswered: send it again (the caller flushed a blocked link) */
    if (a->av_state != AV_SUSPENDING && (a->av_state != AV_STREAMING || a->l2_state != L2_STREAMING)) return 0;
    if (!a->sig.up) return 0;
    a->av_state = AV_SUSPENDING;
    a->l2_state = L2_SIGNALING;
    const uint8_t s = (uint8_t)(a->sink_seid << 2);
    av_cmd(a, SIG_SUSPEND, &s, 1);
    return 1;
}

int br_a2dp_start(br_a2dp_t* a)
{
    if (a->av_state == AV_STREAMING || a->av_state == AV_STARTING) return 1;
    if (a->av_state != AV_CONFIGURED || !a->have_config || !a->media.up || !a->sig.up) return 0;
    a->resume_at = 0;
    a->resuming = 1;
    a->av_state = AV_STARTING;
    a->l2_state = L2_STARTING;
    a2_log(a, "AVDTP: starting the suspended stream");
    const uint8_t s = (uint8_t)(a->sink_seid << 2);
    av_cmd(a, SIG_START, &s, 1);
    return 1;
}

size_t br_a2dp_media_frame(const br_a2dp_t* a, uint16_t seq, uint32_t ts, const uint8_t* sbc, size_t sbc_len,
                           uint8_t n_frames, uint8_t* out, size_t cap)
{
    const size_t body = 12 + 1 + sbc_len;
    if (a->l2_state != L2_STREAMING || 4 + body > cap || body > a->stream.media_mtu) return 0;
    out[0] = (uint8_t)body; out[1] = (uint8_t)(body >> 8);
    out[2] = (uint8_t)a->stream.media_cid; out[3] = (uint8_t)(a->stream.media_cid >> 8);
    uint8_t* r = out + 4;
    r[0] = 0x80; r[1] = 96; r[2] = (uint8_t)(seq >> 8); r[3] = (uint8_t)seq;
    r[4] = (uint8_t)(ts >> 24); r[5] = (uint8_t)(ts >> 16); r[6] = (uint8_t)(ts >> 8); r[7] = (uint8_t)ts;
    r[8] = 0; r[9] = 0; r[10] = 0; r[11] = 1;
    r[12] = (uint8_t)(n_frames & 0x0Fu);
    memcpy(r + 13, sbc, sbc_len);
    return 4 + body;
}
