#include "br/br_a2dp_src.h"

#include <stdarg.h>
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
static const uint8_t kFeatures0[8] = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x80};
static const uint8_t kFeatures1[8] = {0x01, 0, 0, 0, 0, 0, 0, 0}; /* SSP host support */
/* What the lab sent in its first LMP_features_req (kept: the Bose accepted it every time). */
static const uint8_t kFeaturesReq[8] = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00};
static const uint8_t kIocap[3] = {0x03, 0x00, 0x04}; /* NoInputNoOutput, no OOB, MITM not required + bonding */

enum { SSP_IDLE, SSP_IOCAP, SSP_KEY_HDR, SSP_KEY_PL, SSP_PEER_KEY, SSP_WAIT_CONFIRM, SSP_WAIT_NUMBER, SSP_WAIT_DHKEY,
       SSP_PAIRED, SSP_FAIL };
enum { AU_IDLE, AU_RAND, AU_ENC_MODE, AU_KEY_SIZE, AU_START_ENC, AU_ENCRYPTED, AU_FAIL };
enum { L2_OFF, L2_WAIT_SINK, L2_SIG_CONNECTING, L2_SIGNALING, L2_SIGNALING_ACP, L2_MEDIA_CONNECTING, L2_STARTING,
       L2_STREAMING };
enum { AV_IDLE, AV_DISCOVER, AV_CAPS, AV_CONFIGURE, AV_OPEN, AV_CONFIGURED, AV_NEED_MEDIA, AV_STARTING, AV_STREAMING,
       AV_FAIL };

#define PSM_AVDTP 0x0019
#define SIG_SCID 0x0041
#define MEDIA_SCID 0x0042
#define OUR_MTU 672
#define INT_SEID 1

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
    uint8_t f[4 + 64];
    if (n > 64) return;
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
    return NULL;
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
    const uint8_t f = (o0 & 0x20) ? 0x20 : (o0 & 0x10) ? 0x10 : (o0 & 0x40) ? 0x40 : 0x80;
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

static void av_on_signal(br_a2dp_t* a, const uint8_t* m, size_t n)
{
    if (n < 2) return;
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
            if (a->l2_state == L2_STREAMING) a->l2_state = L2_SIGNALING;
            if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_SUSPENDED, NULL);
            return;
        case SIG_GET_CONFIG:
        case SIG_RECONFIG:
        case SIG_SECURITY: { const uint8_t e = 0x31; av_send(a, label, AV_REJECT, signal, &e, 1); return; }
        default: break;
        }
        av_send(a, label, AV_GENERAL_REJECT, signal, NULL, 0);
        return;
    }
    if (msg != AV_ACCEPT) {
        if (signal == SIG_START && a->av_state == AV_STREAMING) return;
        if (a->peer_int && (signal == SIG_DISCOVER || signal == SIG_GET_CAPS || signal == SIG_SET_CONFIG)) return;
        a2_log(a, "AVDTP: signal %u rejected (msg %u)", signal, msg);
        a->av_state = AV_FAIL;
        fail(a, "AVDTP command rejected");
        return;
    }
    if (a->peer_int && (signal == SIG_DISCOVER || signal == SIG_GET_CAPS || signal == SIG_GET_ALL_CAPS)) return;
    if (signal == SIG_DISCOVER && a->av_state == AV_DISCOVER) {
        for (size_t i = 0; i + 1 < pn; i += 2) {
            const uint8_t seid = p[i] >> 2, in_use = (p[i] >> 1) & 1u, media = p[i + 1] >> 4, tsep = (p[i + 1] >> 3) & 1u;
            if (tsep == 1 && media == 0 && !in_use) {
                a->sink_seid = seid;
                a->av_state = AV_CAPS;
                const uint8_t s = (uint8_t)(seid << 2);
                av_cmd(a, SIG_GET_CAPS, &s, 1);
                return;
            }
        }
        a->av_state = AV_FAIL;
        fail(a, "no audio sink endpoint");
    } else if ((signal == SIG_GET_CAPS || signal == SIG_GET_ALL_CAPS) && a->av_state == AV_CAPS) {
        size_t cl = 0;
        const uint8_t* codec = find_cat(p, pn, CAT_CODEC, &cl);
        if (!codec || cl < 6 || codec[1] != 0x00) { a->av_state = AV_FAIL; fail(a, "sink has no SBC"); return; }
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
        a->stream.media_cid = a->media.dcid;
        a->stream.media_mtu = a->media.peer_mtu;
        a2_log(a, "AVDTP: streaming, media CID 0x%04X MTU %u", a->media.dcid, a->media.peer_mtu);
        if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_STREAMING, &a->stream);
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
            uint8_t r[8];
            if (!c) {
                put16(r, 0); put16(r + 2, scid); put16(r + 4, psm == PSM_AVDTP ? 0x0004 : 0x0002); put16(r + 6, 0);
                sig(a, 0x03, ident, r, 8);
                a2_log(a, "L2CAP: refused incoming PSM 0x%04X", psm);
                continue;
            }
            memset(c, 0, sizeof *c);
            c->used = 1; c->incoming = 1; c->scid = mine; c->dcid = scid; c->peer_mtu = 672;
            if (a->l2_state == L2_OFF) { a->l2_state = L2_WAIT_SINK; a->t_l2_start = now(a); }
            if (c == &a->media) a->l2_state = L2_MEDIA_CONNECTING;
            put16(r, mine); put16(r + 2, scid); put16(r + 4, 0); put16(r + 6, 0);
            sig(a, 0x03, ident, r, 8);
            ch_cfg_req(a, scid);
            a2_log(a, "L2CAP: accepted incoming AVDTP channel -> 0x%04X", mine);
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
            if (c) {
                c->cfg_out = get16(d + 4) == 0;
                if (!c->cfg_out) fail(a, "L2CAP configuration refused");
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
    br_a2dp_ch_t* cs[2] = {&a->sig, &a->media};
    for (int k = 0; k < 2; ++k)
        if (cs[k]->used && cs[k]->cfg_in && cs[k]->cfg_out && !cs[k]->up && cs[k]->dcid) cs[k]->up = 1;
    l2_progress(a);
}

static void l2_on_frame(br_a2dp_t* a, uint16_t cid, const uint8_t* p, size_t n)
{
    if (cid == 0x0001) l2_on_signaling(a, p, n);
    else if (a->sig.used && cid == a->sig.scid) av_on_signal(a, p, n);
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
    if (op == OP_ENC_KEY_SIZE_REQ) { lmp_accept(a, tid, OP_ENC_KEY_SIZE_REQ); return 1; }
    if (op == OP_ACCEPTED && n >= 1 && p[0] == OP_ENC_KEY_SIZE_REQ && a->auth_state == AU_KEY_SIZE) {
        a->io.random(a->io.ctx, a->en_rand, 16);
        uint8_t kc[16];
        br_e3(a->cfg.link_key, a->en_rand, a->aco, kc);
        br_e0_key_reduce(kc, 16, a->kc);
        a->auth_state = AU_START_ENC;
        a->io.set_enc(a->io.ctx, 2, a->kc, a->cfg.own_addr); /* the sink encrypts its accept */
        lmp(a, OP_START_ENC_REQ, 0, a->en_rand, 16);
        return 1;
    }
    if (op == OP_ACCEPTED && n >= 1 && p[0] == OP_START_ENC_REQ && a->auth_state == AU_START_ENC) {
        a->auth_state = AU_ENCRYPTED;
        a->io.set_enc(a->io.ctx, 1, a->kc, a->cfg.own_addr);
        a2_log(a, "encryption on");
        if (a->io.event) a->io.event(a->io.ctx, BR_A2DP_EV_ENCRYPTED, NULL);
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
    if (a->av_state == AV_NEED_MEDIA && !a->media.used && a->t_need_media && t - a->t_need_media > 3000) {
        a->l2_state = L2_MEDIA_CONNECTING;
        ch_connect(a, &a->media, MEDIA_SCID);
    }
}

void br_a2dp_detach(br_a2dp_t* a, uint8_t reason) { lmp(a, OP_DETACH, 0, &reason, 1); }

int br_a2dp_streaming(const br_a2dp_t* a) { return a->l2_state == L2_STREAMING; }

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
