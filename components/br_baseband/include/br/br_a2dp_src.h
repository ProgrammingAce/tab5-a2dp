#pragma once
/* A2DP source host engine for the native Classic link: LMP (setup, responder, SSP Just Works P-192 pairing, E1
 * authentication, E0 encryption setup, detach), L2CAP (signaling, two AVDTP channels) and AVDTP/A2DP source
 * signaling (as initiator or acceptor; SBC). Pure C, no I/O: the caller moves packets between this engine and the
 * radio (C6 ACL FIFO) through br_a2dp_io_t and feeds received payloads with br_a2dp_rx().
 *
 * Ported from the lab tools that streamed to a Bose speaker (tools/br_lab/lmp.py, l2cap.py, avdtp.py) including
 * the measured conventions: LMP 128-bit values and P-192 coordinates little-endian; f3 IOcap = the LMP order (C SSP
 * functions take little-endian arrays); Kc from the ACO of the most recent authentication; the peripheral's
 * accepted(start_encryption_req) is already encrypted (set_enc mode 2 = decrypt RX only, before sending it);
 * setup_complete only after accepted(host_connection_req); a bonded sink may open AVDTP itself.
 *
 * Byte arrays: addresses and keys little-endian (index 0 = LSB). Times in ms from io.now_ms. */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    BR_A2DP_EV_LOG = 0,        /* arg: const char* */
    BR_A2DP_EV_PAIRED = 1,     /* arg: const uint8_t link_key[16] (little-endian) */
    BR_A2DP_EV_ENCRYPTED = 2,  /* arg: NULL */
    BR_A2DP_EV_STREAMING = 3,  /* arg: const br_a2dp_stream_t* */
    BR_A2DP_EV_FAILED = 4,     /* arg: const char* reason */
    BR_A2DP_EV_DETACHED = 5,   /* arg: const uint8_t* reason code */
    BR_A2DP_EV_SUSPENDED = 6,  /* arg: NULL (the stream is suspended or closed: by the sink, or by br_a2dp_suspend().
                                * It stays suspended until the sink starts it or br_a2dp_start() is called; then
                                * BR_A2DP_EV_STREAMING is reported again) */
    BR_A2DP_EV_NAME = 7,       /* arg: const char* (the sink's user-friendly name, UTF-8, read after encryption) */
    BR_A2DP_EV_REMOTE = 8,     /* arg: br_a2dp_remote_t; AVRCP pass-through key event */
};

typedef struct {
    uint8_t operation; /* AVRCP PASS THROUGH operation ID */
    uint8_t pressed;   /* 1 on press, 0 on release */
} br_a2dp_remote_t;

typedef struct {
    uint16_t media_cid; /* peer's CID of the media channel: L2CAP frames for media go to this CID */
    uint16_t media_mtu;
    uint32_t freq;
    uint8_t mode;     /* SBC channel mode: 0 mono, 1 dual, 2 stereo, 3 joint (the SBC header encoding) */
    uint8_t blocks;   /* 4, 8, 12, 16 */
    uint8_t subbands; /* 4, 8 */
    uint8_t alloc;    /* 0 loudness, 1 SNR (SBC header encoding) */
    uint8_t min_bitpool, max_bitpool;
} br_a2dp_stream_t;

typedef struct {
    void* ctx;
    /* llid 3: one LMP PDU (<= 17 bytes, send as DM1). llid 2: one whole L2CAP frame (4-byte header + payload);
     * the caller fragments it (first fragment LLID 2, the rest LLID 1). */
    void (*send)(void* ctx, uint8_t llid, const uint8_t* data, size_t len);
    /* mode 0 off, 1 encrypt TX and decrypt RX, 2 decrypt RX only; Kc' and the central's BD_ADDR (ours). */
    void (*set_enc)(void* ctx, int mode, const uint8_t kc[16], const uint8_t central_addr[6]);
    void (*random)(void* ctx, uint8_t* out, size_t n);
    uint32_t (*now_ms)(void* ctx);
    void (*event)(void* ctx, int ev, const void* arg);
} br_a2dp_io_t;

typedef struct {
    uint8_t own_addr[6];  /* central (us) */
    uint8_t peer_addr[6]; /* the sink */
    uint8_t link_key[16];
    uint8_t have_key;     /* authenticate with link_key */
    uint8_t pair;         /* no key (or it was refused): run SSP Just Works first */
    uint8_t max_bitpool;  /* our SEP and the configuration we choose stay <= this (link budget) */
    uint16_t avdtp_passive_ms; /* let the sink open AVDTP itself first (default 1500) */
    uint8_t prefer_48k;   /* choose 48 kHz when the sink offers it (default 44.1 kHz) */
    const char* name;     /* LMP_name_res (default "Tab5") */
} br_a2dp_cfg_t;

#define BR_A2DP_L2CAP_BUF 1024
#define BR_A2DP_NAME_MAX 48 /* longer names are cut */

typedef struct {
    uint16_t scid, dcid, peer_mtu;
    uint8_t used, incoming, cfg_in, cfg_out, up;
} br_a2dp_ch_t;

typedef struct br_a2dp {
    br_a2dp_cfg_t cfg;
    br_a2dp_io_t io;
    int failed;
    /* LMP setup */
    uint8_t setup_sent, peer_setup;
    uint32_t t_setup;
    /* SSP */
    uint8_t ssp_state, ssp_chunk, peer_key_len;
    uint8_t d[24], pk_x[24], pk_y[24], peer_key[48], dhkey[24], na[16], nb[16], cb[16], peer_iocap[3];
    /* authentication + encryption */
    uint8_t auth_state, key_ok;
    uint8_t au_rand[16], aco[12], en_rand[16], kc[16];
    /* L2CAP */
    uint8_t ident;
    uint8_t rx[BR_A2DP_L2CAP_BUF];
    uint16_t rx_len;
    br_a2dp_ch_t sig, media, sdp, avctp; /* incoming SDP and AVCTP control channels */
    uint8_t l2_state;
    uint32_t t_l2_start, t_sig_up, t_need_media;
    /* AVDTP */
    uint8_t label, av_state, sink_seid, peer_int, have_config;
    uint8_t config_ie[6];
    br_a2dp_stream_t stream;
    /* sink endpoints from discover (audio sinks not in use), tried in order until one offers SBC */
    uint8_t sep_cand[8], sep_n, sep_i;
    /* resuming = our START for a suspended stream is out (resume_at: unused, kept for layout) */
    uint8_t resuming;
    uint32_t resume_at;
    uint8_t key_size; /* negotiated encryption key size (16 unless the sink proposes 7..15) */
    /* remote name (LMP_name_req after encryption; 14-byte fragments) */
    uint8_t name_state, name_len;
    char peer_name[BR_A2DP_NAME_MAX + 1];
    /* AVRCP: a registered play-status notification waiting for the next change */
    uint8_t avrcp_notify, avrcp_notify_tid, avrcp_notify_subunit;
} br_a2dp_t;

void br_a2dp_init(br_a2dp_t* a, const br_a2dp_cfg_t* cfg, const br_a2dp_io_t* io);
/* The baseband connection exists: send version_req, features_req, host_connection_req. */
void br_a2dp_connected(br_a2dp_t* a);
/* One verified, decrypted payload from the peripheral: llid 3 = LMP PDU, 1/2 = L2CAP fragment. */
void br_a2dp_rx(br_a2dp_t* a, uint8_t llid, const uint8_t* data, size_t len);
/* Timers; call every few tens of ms. */
void br_a2dp_poll(br_a2dp_t* a);
/* Sends LMP_detach (0x13 = remote user terminated); end the baseband link once it is acknowledged. */
void br_a2dp_detach(br_a2dp_t* a, uint8_t reason);
/* 1 once AVDTP is streaming; then the stream parameters. */
int br_a2dp_streaming(const br_a2dp_t* a);
/* Source-initiated AVDTP SUSPEND (nothing to play, or the headset asked for a pause). Stop feeding media first.
 * Returns 1 if the suspend is on its way (BR_A2DP_EV_SUSPENDED follows), 0 if the stream is not started.
 * Calling it again before the answer sends the command again. */
int br_a2dp_suspend(br_a2dp_t* a);
/* AVDTP START for a suspended stream. Returns 1 if started or starting (BR_A2DP_EV_STREAMING follows), 0 if there
 * is no configured, suspended stream. */
int br_a2dp_start(br_a2dp_t* a);
/* Builds the L2CAP frame for one RTP media packet (12-byte RTP + 1-byte SBC header + frames) into out; returns the
 * frame length (send with llid 2), 0 if not streaming or too long. */
size_t br_a2dp_media_frame(const br_a2dp_t* a, uint16_t seq, uint32_t timestamp, const uint8_t* sbc, size_t sbc_len,
                           uint8_t n_frames, uint8_t* out, size_t cap);

#ifdef __cplusplus
}
#endif
