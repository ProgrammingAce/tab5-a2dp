/* br_a2dp_src against a simulated A2DP sink (LMP responder side of SSP, authentication both ways, encryption,
 * L2CAP, AVDTP as initiator or passive). Checks sequencing and that both sides derive the same keys. */
#include <stdio.h>
#include <string.h>

#include "br/br_a2dp_src.h"
#include "br/br_e0.h"
#include "br/br_p192.h"
#include "br/br_safer.h"
#include "br/br_ssp.h"
#include "test.h"

/* ---- harness ---------------------------------------------------------------------------------------------------- */
typedef struct { uint8_t llid, len; uint8_t d[700]; uint16_t n; } msg_t;
#define QN 256
typedef struct { msg_t m[QN]; int head, tail; } queue_t;
static void q_push(queue_t* q, uint8_t llid, const uint8_t* d, size_t n)
{
    msg_t* m = &q->m[q->tail++ % QN];
    m->llid = llid; m->n = (uint16_t)n; memcpy(m->d, d, n);
}
static int q_pop(queue_t* q, msg_t* out)
{
    if (q->head == q->tail) return 0;
    *out = q->m[q->head++ % QN];
    return 1;
}

static uint32_t rng = 1;
static void rnd(uint8_t* o, size_t n) { for (size_t i = 0; i < n; ++i) { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; o[i] = (uint8_t)rng; } }

typedef struct {
    queue_t to_sink, to_src;
    uint32_t t;
    int enc_mode, enc_rx_before_start;
    uint8_t kc[16];
    int ev_paired, ev_encrypted, ev_streaming, ev_failed, ev_name, ev_suspended;
    char name[64];
    uint8_t link_key[16];
    br_a2dp_stream_t stream;
    char fail_reason[80];
} world_t;

static void io_send(void* c, uint8_t llid, const uint8_t* d, size_t n) { q_push(&((world_t*)c)->to_sink, llid, d, n); }
static void io_set_enc(void* c, int mode, const uint8_t kc[16], const uint8_t addr[6])
{
    (void)addr;
    world_t* w = c;
    w->enc_mode = mode;
    memcpy(w->kc, kc, 16);
}
static void io_rand(void* c, uint8_t* o, size_t n) { (void)c; rnd(o, n); }
static uint32_t io_now(void* c) { return ((world_t*)c)->t; }
static void io_event(void* c, int ev, const void* arg)
{
    world_t* w = c;
    if (ev == BR_A2DP_EV_PAIRED) { ++w->ev_paired; memcpy(w->link_key, arg, 16); }
    if (ev == BR_A2DP_EV_ENCRYPTED) ++w->ev_encrypted;
    if (ev == BR_A2DP_EV_SUSPENDED) ++w->ev_suspended;
    if (ev == BR_A2DP_EV_NAME) { ++w->ev_name; snprintf(w->name, sizeof w->name, "%s", (const char*)arg); }
    if (ev == BR_A2DP_EV_STREAMING) { ++w->ev_streaming; w->stream = *(const br_a2dp_stream_t*)arg; }
    if (ev == BR_A2DP_EV_FAILED) { ++w->ev_failed; snprintf(w->fail_reason, sizeof w->fail_reason, "%s", (const char*)arg); }
}

/* ---- simulated sink --------------------------------------------------------------------------------------------- */
static const uint8_t A[6] = {0x1B, 0xCA, 0x22, 0x00, 0x00, 0x00}; /* central (us), LSB first */
static const uint8_t B[6] = {0xE0, 0xCD, 0x16, 0xBC, 0x58, 0xE4}; /* sink */

typedef struct {
    world_t* w;
    int allow_pairing, role_switch, sink_int, wrong_key;
    int aac_first;     /* SEID 1 is an AAC endpoint (the source must move on to SEID 2) */
    int key_counter;   /* answers key size 16 with its own proposal */
    int suspend_once;  /* suspends the stream once it started; then expects the source's START */
    int key_size, caps_asked[3], suspended, starts, get_config_ok;
    int sdp_check;     /* looks up the source's SDP record first (24-byte chunks: continuation) */
    uint16_t sdp_src_cid;
    int sdp_in, sdp_out, sdp_sent, sdp_done, sdp_chunks;
    uint8_t sdp_buf[256];
    int sdp_len;
    uint8_t key[16];
    int have_key;
    /* SSP */
    uint8_t d[24], x[24], y[24], peer[48], dh[24], na[16], nb[16], iocap_a[3];
    int peer_len, chunk;
    /* auth */
    uint8_t rand_b[16], aco[12];
    int auth_central_sent;
    int host_conn_accepted, setup_before_accept, setup_seen;
    /* L2CAP / AVDTP */
    uint16_t sig_src_cid, media_src_cid; /* the source's CIDs */
    int sig_up_in, sig_up_out, media_up_in, media_up_out, av_step, started;
    uint8_t ident;
    uint8_t rx[1024];
    int rx_len;
} sink_t;

static void s_lmp(sink_t* s, uint8_t op, uint8_t tid, const uint8_t* p, size_t n)
{
    uint8_t b[17];
    b[0] = (uint8_t)(op << 1 | tid);
    memcpy(b + 1, p, n);
    q_push(&s->w->to_src, 3, b, 1 + n);
}
static void s_ext(sink_t* s, uint8_t ext, uint8_t tid, const uint8_t* p, size_t n)
{
    uint8_t b[17];
    b[0] = (uint8_t)(127 << 1 | tid);
    b[1] = ext;
    memcpy(b + 2, p, n);
    q_push(&s->w->to_src, 3, b, 2 + n);
}
static void s_acc(sink_t* s, uint8_t tid, uint8_t op) { s_lmp(s, 3, tid, &op, 1); }
/* L2CAP frame to the source, fragmented to 27-byte DH1 payloads */
static void s_l2(sink_t* s, uint16_t cid, const uint8_t* p, size_t n)
{
    uint8_t f[700];
    f[0] = (uint8_t)n; f[1] = (uint8_t)(n >> 8); f[2] = (uint8_t)cid; f[3] = (uint8_t)(cid >> 8);
    memcpy(f + 4, p, n);
    for (size_t off = 0; off < n + 4; off += 27) q_push(&s->w->to_src, off ? 1 : 2, f + off, (n + 4 - off) < 27 ? n + 4 - off : 27);
}
static void s_sig(sink_t* s, uint8_t code, uint8_t ident, const uint8_t* d, size_t n)
{
    uint8_t c[64];
    c[0] = code; c[1] = ident; c[2] = (uint8_t)n; c[3] = 0;
    memcpy(c + 4, d, n);
    s_l2(s, 1, c, 4 + n);
}
static void s_av(sink_t* s, uint8_t label, uint8_t msg, uint8_t signal, const uint8_t* p, size_t n)
{
    uint8_t b[64];
    b[0] = (uint8_t)(label << 4 | msg); b[1] = signal;
    memcpy(b + 2, p, n);
    s_l2(s, s->sig_src_cid, b, 2 + n);
}
static void s_send_key_chunk(sink_t* s)
{
    uint8_t pk[48], c[16];
    memcpy(pk, s->x, 24); memcpy(pk + 24, s->y, 24);
    memcpy(c, pk + 16 * s->chunk, 16);
    s_lmp(s, 62, 1, c, 16);
    ++s->chunk;
}
static void s_av_step(sink_t* s)
{
    if (!s->sink_int || !(s->sig_up_in && s->sig_up_out)) return;
    if (s->av_step == 0) { s->av_step = 1; s_av(s, 1, 0, 1, NULL, 0); } /* discover */
}

static void sink_l2_frame(sink_t* s, uint16_t cid, const uint8_t* p, size_t n)
{
    if (cid == 0x0001) {
        for (size_t i = 0; i + 4 <= n;) {
            const uint8_t code = p[i], ident = p[i + 1];
            const uint16_t len = (uint16_t)(p[i + 2] | p[i + 3] << 8);
            const uint8_t* d = p + i + 4;
            i += 4u + len;
            if (code == 0x02) { /* source connects (passive sink) */
                const uint16_t scid = (uint16_t)(d[2] | d[3] << 8);
                const uint16_t mine = s->sig_src_cid ? 0x71 : 0x70;
                if (!s->sig_src_cid) s->sig_src_cid = scid; else s->media_src_cid = scid;
                const uint8_t r[8] = {(uint8_t)mine, 0, (uint8_t)scid, (uint8_t)(scid >> 8), 0, 0, 0, 0};
                s_sig(s, 0x03, ident, r, 8);
                const uint8_t c[8] = {(uint8_t)scid, (uint8_t)(scid >> 8), 0, 0, 1, 2, 0xA0, 0x02};
                s_sig(s, 0x04, ++s->ident, c, 8);
            } else if (code == 0x03 && d[2] == 0x60) { /* our SDP channel */
                s->sdp_src_cid = (uint16_t)(d[0] | d[1] << 8);
                const uint8_t c[8] = {d[0], d[1], 0, 0, 1, 2, 0xA0, 0x02};
                s_sig(s, 0x04, ++s->ident, c, 8);
            } else if (code == 0x04 && d[0] == 0x60) {
                const uint8_t r[6] = {(uint8_t)s->sdp_src_cid, (uint8_t)(s->sdp_src_cid >> 8), 0, 0, 0, 0};
                s_sig(s, 0x05, ident, r, 6);
                s->sdp_in = 1;
            } else if (code == 0x05 && d[0] == 0x60) {
                s->sdp_out = 1;
            } else if (code == 0x03) { /* response to our connect (sink as initiator) */
                const uint16_t dcid = (uint16_t)(d[0] | d[1] << 8), scid = (uint16_t)(d[2] | d[3] << 8);
                if (scid == 0x70) s->sig_src_cid = dcid; else s->media_src_cid = dcid;
                const uint8_t c[8] = {(uint8_t)dcid, (uint8_t)(dcid >> 8), 0, 0, 1, 2, 0x20, 0x03};
                s_sig(s, 0x04, ++s->ident, c, 8);
            } else if (code == 0x04) { /* source's configure request */
                const uint16_t dcid = (uint16_t)(d[0] | d[1] << 8);
                const uint16_t src = dcid == 0x70 ? s->sig_src_cid : s->media_src_cid;
                const uint8_t r[6] = {(uint8_t)src, (uint8_t)(src >> 8), 0, 0, 0, 0};
                s_sig(s, 0x05, ident, r, 6);
                if (dcid == 0x70) s->sig_up_in = 1; else s->media_up_in = 1;
            } else if (code == 0x05) {
                const uint16_t scid = (uint16_t)(d[0] | d[1] << 8);
                if (scid == 0x70) s->sig_up_out = 1; else s->media_up_out = 1;
            }
        }
        if (s->sdp_in && s->sdp_out && !s->sdp_sent) {
            s->sdp_sent = 1; /* ServiceSearchAttributeRequest: AudioSource, max 24 bytes, all attributes */
            const uint8_t q[] = {0x06, 0x00, 0x01, 0x00, 0x0F, 0x35, 0x03, 0x19, 0x11, 0x0A, 0x00, 24,
                                 0x35, 0x05, 0x0A, 0x00, 0x00, 0xFF, 0xFF, 0x00};
            s_l2(s, s->sdp_src_cid, q, sizeof q);
        }
        s_av_step(s);
        return;
    }
    if (cid == 0x60 && n >= 7 && p[0] == 0x07) { /* SDP response: collect, follow the continuation */
        const int cnt = p[5] << 8 | p[6];
        memcpy(s->sdp_buf + s->sdp_len, p + 7, (size_t)cnt);
        s->sdp_len += cnt;
        ++s->sdp_chunks;
        const uint8_t* cont = p + 7 + cnt;
        if (cont[0]) {
            uint8_t q[32] = {0x06, 0x00, (uint8_t)(1 + s->sdp_chunks), 0x00, 0, 0x35, 0x03, 0x19, 0x11, 0x0A, 0x00, 24,
                             0x35, 0x05, 0x0A, 0x00, 0x00, 0xFF, 0xFF};
            memcpy(q + 19, cont, 1u + cont[0]);
            q[4] = (uint8_t)(14 + 1 + cont[0]);
            s_l2(s, s->sdp_src_cid, q, 19u + 1u + cont[0]);
        } else {
            s->sdp_done = 1;
        }
        return;
    }
    if (cid != 0x70 || n < 2) return; /* AVDTP signaling on our CID 0x70 */
    const uint8_t label = p[0] >> 4, msg = p[0] & 3, signal = p[1] & 0x3F;
    if (msg == 0) { /* command from the source */
        if (signal == 1) { const uint8_t r[4] = {1 << 2, 1 << 3 /* audio sink */, 2 << 2, 1 << 3}; s_av(s, label, 2, 1, r, 4); }
        else if (signal == 2 || signal == 12) {
            const int seid = p[2] >> 2;
            if (seid >= 1 && seid <= 2) ++s->caps_asked[seid];
            const uint8_t sbc[] = {1, 0, 7, 6, 0, 0, 0xFF, 0xFF, 2, 53, 4, 2, 2, 0};
            const uint8_t aac[] = {1, 0, 7, 8, 0, 2, 0x80, 0x01, 0x8C, 0x84, 0xE2, 0x00};
            if (s->aac_first && seid == 1) s_av(s, label, 2, signal, aac, sizeof aac);
            else s_av(s, label, 2, signal, sbc, sizeof sbc);
        } else if (signal == 3 || signal == 6 || signal == 7) {
            s_av(s, label, 2, signal, NULL, 0);
            if (signal == 7) { s->started = 1; ++s->starts; }
            if (signal == 7 && s->suspend_once && !s->suspended) {
                s->suspended = 1;
                const uint8_t q = 1 << 2;
                s_av(s, 9, 0, 9, &q, 1); /* SUSPEND our (sink) endpoint */
                s_av(s, 10, 0, 4, &q, 1); /* GET_CONFIGURATION of the source's endpoint (SEID 1) */
            }
            if (signal == 6 && !s->sink_int) { /* passive sink: the source opens the media channel */ }
        }
        return;
    }
    /* responses to the sink's commands (sink as initiator) */
    if (msg == 2 && signal == 4 && n >= 2 + 4 + 6 && p[2] == 1 && p[4] == 7) s->get_config_ok = 1;
    if (msg != 2) return;
    if (signal == 1) { const uint8_t q = 1 << 2; s_av(s, 2, 0, 2, &q, 1); }            /* get caps of the source */
    else if (signal == 2) {                                                             /* configure the source */
        const uint8_t c[] = {1 << 2, 1 << 2, 1, 0, 7, 6, 0, 0, 0x21, 0x15, 2, 20};
        s_av(s, 3, 0, 3, c, sizeof c);
    } else if (signal == 3) { const uint8_t q = 1 << 2; s_av(s, 4, 0, 6, &q, 1); }      /* open */
    else if (signal == 6) {                                                             /* media channel */
        const uint8_t c[4] = {0x19, 0, 0x71, 0};
        s_sig(s, 0x02, ++s->ident, c, 4);
    }
}

static void sink_on(sink_t* s, const msg_t* m)
{
    if (m->llid != 3) {
        if (m->llid == 2) s->rx_len = 0;
        memcpy(s->rx + s->rx_len, m->d, m->n);
        s->rx_len += m->n;
        while (s->rx_len >= 4) {
            const int fl = s->rx[0] | s->rx[1] << 8, cid = s->rx[2] | s->rx[3] << 8;
            if (s->rx_len < 4 + fl) break;
            sink_l2_frame(s, (uint16_t)cid, s->rx + 4, (size_t)fl);
            memmove(s->rx, s->rx + 4 + fl, (size_t)(s->rx_len - 4 - fl));
            s->rx_len -= 4 + fl;
        }
        return;
    }
    const uint8_t tid = m->d[0] & 1, op = m->d[0] >> 1;
    const uint8_t* p = m->d + 1;
    if (op == 1) { /* name_req: a name longer than one fragment */
        static const char nm[] = "Soundcore H630 Headphones";
        uint8_t r[16] = {p[0], (uint8_t)(sizeof nm - 1)};
        for (int i = 0; i < 14 && p[0] + i < (int)sizeof nm - 1; ++i) r[2 + i] = (uint8_t)nm[p[0] + i];
        s_lmp(s, 2, tid, r, 16);
    } else if (op == 37) { const uint8_t v[5] = {8, 0x0A, 0, 0x3B, 0x2E}; s_lmp(s, 38, tid, v, 5); }
    else if (op == 39) { const uint8_t f[8] = {0xFF, 0xFF, 0x8F, 0xFE, 0xDB, 0xFF, 0x5B, 0x87}; s_lmp(s, 40, tid, f, 8); }
    else if (op == 51) {
        if (s->role_switch) {
            const uint8_t so[8] = {0}; s_lmp(s, 52, 1, so, 8);
            const uint8_t sw[4] = {0x22, 1, 0, 0}; s_lmp(s, 19, 1, sw, 4);
        } else {
            s_acc(s, tid, 51); s->host_conn_accepted = 1; s_lmp(s, 49, 1, NULL, 0);
        }
    } else if (op == 4 && p[0] == 19) { /* our switch was refused: now accept the host connection */
        s_acc(s, 0, 51); s->host_conn_accepted = 1; s_lmp(s, 49, 1, NULL, 0);
    } else if (op == 49) {
        s->setup_seen = 1;
        if (!s->host_conn_accepted) s->setup_before_accept = 1;
    } else if (op == 127 && p[0] == 25) { /* io_capability_req */
        if (!s->allow_pairing) { const uint8_t r[3] = {127, 25, 0x18}; s_ext(s, 2, tid, r, 3); return; }
        memcpy(s->iocap_a, p + 1, 3);
        const uint8_t r[3] = {3, 0, 4};
        s_ext(s, 26, tid, r, 3);
        do rnd(s->d, 24); while (!br_p192_private_ok(s->d));
        br_p192_public(s->d, s->x, s->y);
        rnd(s->nb, 16);
    } else if (op == 61) { s->peer_len = 0; s_acc(s, tid, 61); }
    else if (op == 62) {
        memcpy(s->peer + s->peer_len, p, 16); s->peer_len += 16; s_acc(s, tid, 62);
        if (s->peer_len == 48) { /* our key now */
            CHECK(br_p192_dhkey(s->d, s->peer, s->peer + 24, s->dh) == 0);
            const uint8_t h[3] = {1, 1, 48}; s_lmp(s, 61, 1, h, 3); s->chunk = 0;
        }
    } else if (op == 3 && p[0] == 61) s_send_key_chunk(s);
    else if (op == 3 && p[0] == 62) {
        if (s->chunk < 3) s_send_key_chunk(s);
        else { uint8_t cb[16]; br_ssp_f1(s->x, s->peer, 24, s->nb, 0, cb); s_lmp(s, 63, 1, cb, 16); }
    } else if (op == 64) { memcpy(s->na, p, 16); s_acc(s, tid, 64); s_lmp(s, 64, 1, s->nb, 16); }
    else if (op == 65) {
        static const uint8_t z[16] = {0};
        uint8_t ea[16], eb[16];
        br_ssp_f3(s->dh, 24, s->na, s->nb, z, s->iocap_a, A, B, ea);
        CHECK(memcmp(ea, p, 16) == 0);
        s_acc(s, tid, 65);
        const uint8_t iob[3] = {3, 0, 4};
        br_ssp_f3(s->dh, 24, s->nb, s->na, z, iob, B, A, eb);
        s_lmp(s, 65, 1, eb, 16);
        br_ssp_f2(s->dh, 24, s->na, s->nb, 0x62746C6Bu, A, B, s->key);
        s->have_key = 1;
    } else if (op == 11) { /* au_rand from the source: sink proves itself, then authenticates the source */
        uint8_t sres[4];
        uint8_t k[16];
        memcpy(k, s->key, 16);
        if (s->wrong_key) k[0] ^= 1;
        br_e1(k, p, B, sres, s->aco);
        s_lmp(s, 12, tid, sres, 4);
        if (!s->auth_central_sent) { s->auth_central_sent = 1; rnd(s->rand_b, 16); s_lmp(s, 11, 1, s->rand_b, 16); }
    } else if (op == 12) { /* sres from the source for our rand_b */
        uint8_t sres[4], aco[12];
        br_e1(s->key, s->rand_b, A, sres, aco);
        CHECK(memcmp(sres, p, 4) == 0);
        memcpy(s->aco, aco, 12); /* most recent authentication */
    } else if (op == 16 && s->key_counter && p[0] == 16) {
        const uint8_t sz = 10;
        s_lmp(s, 16, 1, &sz, 1); /* counter-proposal (a new transaction from the peripheral) */
        s->key_size = 10;
    } else if (op == 15 || op == 16) s_acc(s, tid, op);
    else if (op == 17) {
        uint8_t kc[16], ks[16];
        br_e3(s->key, p, s->aco, kc);
        br_e0_key_reduce(kc, s->key_size ? s->key_size : 16, ks);
        CHECK(memcmp(ks, s->w->kc, 16) == 0);
        s->w->enc_rx_before_start = s->w->enc_mode == 2;
        s_acc(s, tid, 17);
        if (s->sdp_check) { const uint8_t c[4] = {0x01, 0, 0x60, 0}; s_sig(s, 0x02, ++s->ident, c, 4); } /* SDP */
        if (s->sink_int) { const uint8_t c[4] = {0x19, 0, 0x70, 0}; s_sig(s, 0x02, ++s->ident, c, 4); }
    }
}

static void run(world_t* w, br_a2dp_t* a, sink_t* s, uint32_t ms)
{
    for (uint32_t step = 0; step < ms; step += 10) {
        msg_t m;
        for (int k = 0; k < 64; ++k) {
            int moved = 0;
            if (q_pop(&w->to_sink, &m)) { sink_on(s, &m); moved = 1; }
            if (q_pop(&w->to_src, &m)) { br_a2dp_rx(a, m.llid, m.d, m.n); moved = 1; }
            if (!moved) break;
        }
        w->t += 10;
        br_a2dp_poll(a);
    }
}

static int g_aac_first, g_key_counter, g_suspend_once, g_sdp; /* options for the next scenario() */
static void scenario(int pair, int have_key, const uint8_t* key, int role_switch, int sink_int, int wrong_key,
                     int allow_pairing, world_t* w, sink_t* s, br_a2dp_t* a)
{
    memset(w, 0, sizeof *w);
    memset(s, 0, sizeof *s);
    s->aac_first = g_aac_first; s->key_counter = g_key_counter; s->suspend_once = g_suspend_once; s->sdp_check = g_sdp;
    g_aac_first = g_key_counter = g_suspend_once = g_sdp = 0;
    s->w = w; s->allow_pairing = allow_pairing; s->role_switch = role_switch; s->sink_int = sink_int;
    s->wrong_key = wrong_key;
    br_a2dp_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.own_addr, A, 6); memcpy(cfg.peer_addr, B, 6);
    cfg.pair = (uint8_t)pair;
    if (have_key) { memcpy(cfg.link_key, key, 16); memcpy(s->key, key, 16); cfg.have_key = 1; s->have_key = 1; }
    cfg.max_bitpool = 20;
    const br_a2dp_io_t io = {w, io_send, io_set_enc, io_rand, io_now, io_event};
    br_a2dp_init(a, &cfg, &io);
    br_a2dp_connected(a);
    run(w, a, s, 20000);
}

void run_a2dp_tests(void)
{
    static world_t w;
    static sink_t s;
    static br_a2dp_t a;
    /* S1: Bose-like: role switch first, pairing, the sink opens AVDTP and configures us */
    scenario(1, 0, NULL, 1, 1, 0, 1, &w, &s, &a);
    CHECK(!s.setup_before_accept && s.setup_seen);
    CHECK(w.ev_paired == 1 && memcmp(w.link_key, s.key, 16) == 0);
    CHECK(w.ev_encrypted == 1 && w.enc_mode == 1 && w.enc_rx_before_start);
    CHECK(w.ev_streaming == 1 && w.stream.media_cid == 0x71 && w.stream.max_bitpool == 20 && w.stream.mode == 3);
    CHECK(s.started && !w.ev_failed);
    CHECK(w.ev_name == 1 && strcmp(w.name, "Soundcore H630 Headphones") == 0);
    if (w.ev_failed) fprintf(stderr, "S1 failed: %s\n", w.fail_reason);
    uint8_t key[16];
    memcpy(key, s.key, 16);
    /* S2: stored key, passive sink: we discover and configure (bitpool <= our 20, sink max 53) */
    scenario(0, 1, key, 0, 0, 0, 0, &w, &s, &a);
    CHECK(w.ev_paired == 0 && w.ev_encrypted == 1 && w.ev_streaming == 1 && !w.ev_failed);
    CHECK(w.stream.media_cid == 0x71 && w.stream.max_bitpool == 20 && w.stream.freq == 44100 && w.stream.blocks == 16);
    if (w.ev_failed) fprintf(stderr, "S2 failed: %s\n", w.fail_reason);
    /* S3: the sink has a different key -> authentication fails */
    scenario(0, 1, key, 0, 0, 1, 0, &w, &s, &a);
    CHECK(w.ev_failed && w.ev_encrypted == 0 && strstr(w.fail_reason, "authentication"));
    /* S4: pairing refused (sink not in pairing mode) */
    scenario(1, 0, NULL, 0, 1, 0, 0, &w, &s, &a);
    CHECK(w.ev_failed && strstr(w.fail_reason, "pairing"));
    /* S5: AAC endpoint listed first, then SBC: the source skips to SEID 2 */
    g_aac_first = 1;
    scenario(0, 1, key, 0, 0, 0, 0, &w, &s, &a);
    CHECK(s.caps_asked[1] == 1 && s.caps_asked[2] == 1 && w.ev_streaming == 1 && !w.ev_failed);
    if (w.ev_failed) fprintf(stderr, "S5 failed: %s\n", w.fail_reason);
    /* S6: the sink proposes a 10-byte encryption key: both reduce Kc to 10 bytes (checked in the sink at start_enc) */
    g_key_counter = 1;
    scenario(0, 1, key, 0, 0, 0, 0, &w, &s, &a);
    CHECK(a.key_size == 10 && w.ev_encrypted == 1 && w.ev_streaming == 1 && !w.ev_failed);
    if (w.ev_failed) fprintf(stderr, "S6 failed: %s\n", w.fail_reason);
    /* S7: the sink suspends once streaming started: the source answers GET_CONFIGURATION and restarts the stream */
    g_suspend_once = 1;
    scenario(0, 1, key, 0, 0, 0, 0, &w, &s, &a);
    CHECK(s.suspended && w.ev_suspended == 1 && s.starts == 2 && w.ev_streaming == 2 && s.get_config_ok && !w.ev_failed);
    if (w.ev_failed) fprintf(stderr, "S7 failed: %s\n", w.fail_reason);
    /* S8: the sink reads our SDP record first (in 24-byte pieces): A2DP Source over AVDTP 1.3, then streams */
    g_sdp = 1;
    scenario(0, 1, key, 0, 0, 0, 0, &w, &s, &a);
    {
        static const uint8_t src_uuid[] = {0x19, 0x11, 0x0A}, avdtp[] = {0x19, 0x00, 0x19, 0x09, 0x01, 0x03};
        int has_src = 0, has_avdtp = 0;
        for (int i = 0; i + 6 <= s.sdp_len; ++i) {
            has_src |= !memcmp(s.sdp_buf + i, src_uuid, 3);
            has_avdtp |= !memcmp(s.sdp_buf + i, avdtp, 6);
        }
        CHECK(s.sdp_done && s.sdp_chunks >= 3 && s.sdp_buf[0] == 0x35 && s.sdp_buf[2] == 0x35);
        CHECK(s.sdp_len == 2 + s.sdp_buf[1] && has_src && has_avdtp);
        CHECK(w.ev_streaming == 1 && !w.ev_failed);
    }
    /* media frame */
    scenario(0, 1, key, 0, 1, 0, 0, &w, &s, &a);
    uint8_t f[128], sbc[35] = {0x9C};
    const size_t n = br_a2dp_media_frame(&a, 7, 896, sbc, sizeof sbc, 1, f, sizeof f);
    CHECK(n == 4 + 13 + 35 && f[2] == 0x71 && f[4] == 0x80 && f[7] == 7 && f[16] == 1);
    /* Remote controls stay disabled without disturbing an active media stream. */
    w.to_sink.head = w.to_sink.tail = 0;
    const int suspended = w.ev_suspended, streams = w.ev_streaming;
    const uint8_t avctp_connect[] = {8, 0, 1, 0, 2, 0x66, 4, 0, 0x17, 0, 0x88, 0};
    br_a2dp_rx(&a, 2, avctp_connect, sizeof avctp_connect);
    msg_t reply;
    CHECK(q_pop(&w.to_sink, &reply) && reply.n == 16);
    CHECK(reply.d[4] == 3 && reply.d[5] == 0x66 && reply.d[12] == 2 && reply.d[13] == 0);
    CHECK(br_a2dp_streaming(&a) && !w.ev_failed && w.ev_suspended == suspended);
    /* Stray play/pause messages on an unaccepted control CID have no effect. */
    uint8_t control[] = {8, 0, 0x44, 0, 0, 0x11, 0x0e, 0, 0x48, 0x7c, 0x44, 0};
    br_a2dp_rx(&a, 2, control, sizeof control);
    control[10] = 0x46;
    br_a2dp_rx(&a, 2, control, sizeof control);
    CHECK(br_a2dp_streaming(&a) && !w.ev_failed && w.ev_suspended == suspended && w.ev_streaming == streams);
    CHECK(w.to_sink.head == w.to_sink.tail);
}
