/*
 * Tab5 native A2DP: radio lab. See radio_lab.h for the protocol and safety rules.
 *
 * Subcommands (parameters after "BRL1" + subcommand byte; little endian):
 *   0x00 PING                        -> lab_version u8, br_mode u8, in_trial u8, fw version string
 *   0x01 ENTER_BR                    -> wifi_was_started u8
 *   0x02 EXIT_BR                     -> (none)
 *   0x03 TONE   fn u8, mhz u16, power u8, ms u32 (0 = until STOP)
 *                                    -> started; event when ms elapses: (none)
 *   0x04 STOP                        -> (none)
 *   0x05 HOP    fn u8, f1 u16, f2 u16, period_us u16, count u16
 *               carrier on, alternate f1/f2 every period_us (busy-wait, total <= 2 s)
 *                                    -> started; event: calls u16, call_us min u16, max u16, avg u16, late u16
 *   0x06 RX_COUNT fn u8, mhz u16, access_address u32, ms u32
 *               BLE 1M receiver, frequency forced with fn (fn 0xFF = plain BLE channel, mhz must be even)
 *                                    -> started; event: total u32, correct u32, rssi i8, rx_freq i32
 *   0x07 PEEK   addr u32, count u8 (1..60)            -> values u32[count]
 *   0x08 POKE   addr u32, value u32                    -> (none)
 *   0x09 CALL   fn u8, a0..a3 i32                      -> return value i32
 *   0x0A RXFREQ                                         -> phy_get_rx_freq() i32
 *   0x0B BLE_TX fn u8, mhz u16, syncw u32, len u8, type u8, power u8, num u16
 *               BLE 1M packets (type: PHY_BLE_TYPE_*), frequency forced with fn (0xFF = plain BLE channel)
 *                                    -> started; event when sent: (none)
 *   0x0C FORCE  en u8, mhz u16   phy_force_freq_set(en, mhz, 0, 0). Also OUTSIDE BR mode: forces the PLL under the
 *               running BLE controller (gate G2 uses a normal BLE scan with the receiver forced to an odd MHz)
 *                                    -> return value i32
 *   0x0D CHANMAP chan u8, value i16 (-1 = no override)   Remap BLE channel `chan` in the controller's
 *               channel->frequency lookup (hook on r_ble_phy_chan_to_freq). Also OUTSIDE BR mode.
 *                                    -> 40 bytes: the original table value for channels 0..39
 *   0x0F REBOOT                                         -> (none), then esp_restart()
 *
 * Frequency functions (fn), all called as f(a0, a1, a2, a3) with what the spike used:
 *   0 phy_force_freq_set(1, mhz, 0, 0)   1 phy_set_freq(mhz)          2 bt_set_chn(mhz)
 *   3 bt_rx_force(1, mhz)                 4 set_chanfreq(mhz)          5 chip_v7_set_chan(mhz)
 *   6 phy_ble_set_chan_base(mhz)          7 rftest_set_chan(mhz)
 * Which of these actually retune (and how fast) is what gates G1/G2 measure.
 */
#include "radio_lab.h"
#include "cis_c6.h"
#include "br/br.h"
#include "br/br_fast.h"
#include "sbc_beep.h"

#include <string.h>

#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_bt.h"
#include "esp_log.h"
#include "esp_phy_cert_test.h"
#include "esp_rom_regi2c.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "fw_guard.h"
#include "soc/soc.h"

static const char *TAG = "radio_lab";

int slave_bt_send_to_host(const uint8_t *h4, uint16_t len);

typedef int (*int4_fn_t)(int, int, int, int);
extern int phy_force_freq_set(int, int, int, int);
extern int phy_set_freq(int, int, int, int);
extern int phy_get_rx_freq(int, int, int, int);
extern int bt_set_chn(int, int, int, int);
extern int bt_rx_force(int, int, int, int);
extern int set_chanfreq(int, int, int, int);
extern int chip_v7_set_chan(int, int, int, int);
extern int phy_ble_set_chan_base(int, int, int, int);
extern int rftest_set_chan(int, int, int, int);

static const int4_fn_t k_fns[] = {
	phy_force_freq_set, phy_set_freq, bt_set_chn, bt_rx_force,
	set_chanfreq, chip_v7_set_chan, phy_ble_set_chan_base, rftest_set_chan,
};
#define N_FNS (sizeof(k_fns) / sizeof(k_fns[0]))
#define FN_NONE 0xFF

static const uint8_t k_magic[4] = { 'B', 'R', 'L', '1' };

/* Hook (cmake/ble_hooks.txt): the BLE controller's channel index -> frequency lookup. With an override set, one
 * channel (normally 37) is sent to another frequency while its whitening/CRC stay those of that channel. */
extern uint8_t orig_r_ble_phy_chan_to_freq(uint8_t chan);
static volatile int16_t s_remap_value = -1;
static volatile uint8_t s_remap_chan = 0xFF;

IRAM_ATTR uint8_t r_ble_phy_chan_to_freq(uint8_t chan)
{
	if ((chan == s_remap_chan || (s_remap_chan == 254 && chan >= 37 && chan <= 39)) && s_remap_value >= 0) return (uint8_t)s_remap_value;
	return orig_r_ble_phy_chan_to_freq(chan);
}

/* Seen in IDF 5.5.5 ble_lll_scan.c.o: reset reads context from a0,
 * descriptor from a1; +0x144 stores advertising AA to descriptor +48.
 * Caller r_ble_lll_scan_start ignores return. No undocumented register writes.
 * Configure only with scanning stopped; the next scan start applies the override. */
extern void orig_r_ble_lll_scan_reset_link_state(void *context, void *descriptor);
static volatile uint32_t s_scan_aa;
static volatile bool s_scan_aa_enabled;
static volatile uint32_t s_scan_reset_count;
static volatile uint32_t s_scan_applied_count;
static volatile uint32_t s_scan_last_aa;
static void * volatile s_scan_state;
static volatile uint8_t s_scan_profile;
static volatile uint32_t s_scan_word0_before, s_scan_word0_after;
static volatile uint32_t s_scan_word36_before, s_scan_word36_after;
static volatile uint32_t s_scan_word20_before;
static volatile uint32_t s_scan_word20_after;

void r_ble_lll_scan_reset_link_state(void *context, void *descriptor)
{
	orig_r_ble_lll_scan_reset_link_state(context, descriptor);
	s_scan_state = descriptor;
	volatile uint32_t *aa = (volatile uint32_t *)((uint8_t *)descriptor + 48);
	if (s_scan_aa_enabled) {
		*aa = s_scan_aa;
		++s_scan_applied_count;
	}
	/* dtm_hal_rstLst +0x26..0x30 sets bit27 of word+20; scan reset
	 * +0x3c..0x48 clears it. Meaning is an experimental hypothesis.
	 * Preserve all other fields, including frequency and buffer pointers. */
	volatile uint32_t *word20 = (volatile uint32_t *)((uint8_t *)descriptor + 20);
	s_scan_word20_before = *word20;
	s_scan_word0_before = ((volatile uint32_t *)descriptor)[0];
	s_scan_word36_before = ((volatile uint32_t *)descriptor)[9];
	if (s_scan_aa_enabled) {
		if (s_scan_profile == 1) *word20 |= 1u << 27;
		/* scan_reset +0xC6..0xD0 sets CRC-word bit27; DTM reset leaves
		 * it clear. conn_reset +0x62 sets word0 bit31, absent in scan.
		 * Test only these observed differences; do not assign meanings. */
		if (s_scan_profile == 3 || s_scan_profile == 5)
			((volatile uint32_t *)descriptor)[9] &= ~(1u << 27);
		if (s_scan_profile == 4 || s_scan_profile == 5)
			((volatile uint32_t *)descriptor)[0] |= 1u << 31;
	}
	s_scan_word0_after = ((volatile uint32_t *)descriptor)[0];
	s_scan_word36_after = ((volatile uint32_t *)descriptor)[9];
	s_scan_word20_after = *word20;
	s_scan_last_aa = *aa;
	++s_scan_reset_count;
}

/* ble_lll_scan_rx_process: a2 is RX descriptor; +8 low 20 bits points
 * into 0x40800000 RAM. Original reads status at buffer+12 before filtering.
 * Observe only: preserve original return and never bypass CRC/length checks. */
extern int orig_r_ble_lll_scan_rx_process(void *context, void *state, void *rx);
static volatile uint32_t s_scan_rx_count;
static volatile uint32_t s_scan_rx_buffer_count;
static volatile uint32_t s_scan_rx_status;
static volatile uint16_t s_scan_rx_header;
int r_ble_lll_scan_rx_process(void *context, void *state, void *rx)
{
	if (s_scan_aa_enabled) {
		++s_scan_rx_count;
		uint32_t offset = ((volatile uint32_t *)rx)[2] & 0xFFFFFu;
		if (offset) {
			s_scan_rx_status = *(volatile uint32_t *)(0x40800000u + offset + 12u);
			/* scan_rx_process reads +28; scan_copy_into_mbuf reads +29
			 * as length (IDF 5.5.5 ble_lll_scan.c.o, +0x4c). Copy just
			 * these observed header bytes; do not trust that length. */
			const volatile uint8_t *header = (const volatile uint8_t *)(0x40800000u + offset + 28u);
			s_scan_rx_header = (uint16_t)(header[0] | ((uint16_t)header[1] << 8));
			++s_scan_rx_buffer_count;
		}
	}
	return orig_r_ble_lll_scan_rx_process(context, state, rx);
}

/* IDF 5.5.5 ble_phy.c.o r_ble_phy_isr reads these interrupt status
 * registers at +0x36/+0x46. Snapshot before original acknowledges them.
 * Bit meanings deliberately left unnamed until controlled measurements. */
extern void orig_r_ble_phy_isr(void);
static volatile uint32_t s_irq_count;
static volatile uint32_t s_irq_last[2];
static volatile uint32_t s_irq_bits[2][32];
IRAM_ATTR void r_ble_phy_isr(void)
{
	if (s_scan_aa_enabled) {
		const uint32_t words[2] = {
			*(volatile uint32_t *)0x600A130Cu,
			*(volatile uint32_t *)0x600A131Cu,
		};
		++s_irq_count;
		for (unsigned bank = 0; bank < 2; ++bank) {
			s_irq_last[bank] = words[bank];
			for (unsigned bit = 0; bit < 32; ++bit)
				if (words[bank] & (1u << bit)) ++s_irq_bits[bank][bit];
		}
	}
	orig_r_ble_phy_isr();
}

/* dtm_hal.c.o rstLst takes context=a0, descriptor=a1 (same +48 AA,
 * +36 CRC layout); rxProcess reads (rx+8)&0xfffff then status+12.
 * Observe original DTM setup and error status without mutating either. */
extern void orig_dtm_hal_rstLst(void *context, void *descriptor);
extern void *orig_r_ble_lll_get_rxed_buffer(void *state, void *current);
static void * volatile s_dtm_state;
static volatile bool s_dtm_capture;
/* txCreateCtx also calls rstLst once BEFORE schedEvent arms the first event: G4 hop events count after it. */
static volatile bool s_hop_armed;
static volatile uint8_t s_dtm_raw_mode;
static uint32_t s_dtm_raw_aa, s_dtm_raw_tail;
static uint8_t s_dtm_tx_cap = 255;
static uint32_t s_dtm_crc_init = 0x555555;
static uint8_t *volatile s_tx_body; /* DTM TX payload (data+16) of raw mode 2; ID events send only body[0..1] */
/* Per-event TX cap override (page FHS): applied once by the next rstLst raw-mode write. */
static volatile bool s_cap_override;
static volatile uint8_t s_cap_now;
static uint8_t s_page_force_x = 0xFF;
static uint8_t s_page_tx_cap;
static uint16_t s_page_tx_end_us;
static volatile bool s_page_tx_now;
static void *s_page_tx_ctx;
static void page_prepare_forced_tx(uint8_t *body);
static bool lab_ram_span(uint32_t address, unsigned length);
static volatile bool s_dtm_awake;
static volatile bool s_dtm_native_clock;
static volatile bool s_dtm_in_schedule;
static volatile uint32_t s_dtm_sleep_skipped;
extern uint32_t orig_r_ble_lll_sleep_enable_now(void);
extern uint32_t r_ble_lll_timer_current_tick_get(void);
extern uint32_t orig_r_ble_lll_timer_current_tick_get(void);
extern void r_ble_lll_sleep_disable(int restart_timer);
IRAM_ATTR uint32_t r_ble_lll_timer_current_tick_get(void)
{
	/* sleep_timer_tick_get +0x16..0x26 reads this native register when
	 * sleep is disabled. Scope the diagnostic to DTM deadline computation. */
	if (s_dtm_capture && s_dtm_native_clock && s_dtm_in_schedule)
		return *(volatile uint32_t *)0x600A1924u;
	return orig_r_ble_lll_timer_current_tick_get();
}
uint32_t r_ble_lll_sleep_enable_now(void)
{
	/* ble_lll_sleep.c.o +0xC/+0x58: official sleep-disabled path returns
	 * current LL tick without enabling sleep. Match it only for opt-in DTM.
	 * Measured 1.4.199: DTM clock freezes with no ISR after enable_now. */
	if (s_dtm_capture && s_dtm_awake) {
		++s_dtm_sleep_skipped;
		return r_ble_lll_timer_current_tick_get();
	}
	return orig_r_ble_lll_sleep_enable_now();
}
static volatile uint32_t s_dtm_resets, s_dtm_rx, s_dtm_status;
static volatile uint16_t s_dtm_header;
static volatile uint32_t s_dtm_words[16];
extern int orig_dtm_hal_schedEvent(void *context, int kind);
extern void orig_dtm_hal_isr(void);
static volatile uint32_t s_dtm_sched_calls, s_dtm_irqs, s_dtm_sched_address;
static volatile uint32_t s_dtm_sched_words[16];
int dtm_hal_schedEvent(void *context, int kind)
{
	/* ble_ll.c.o r_ble_ll_reset +0x4c calls sleep_disable(0) to wake
	 * and synchronize the native/synthesized clocks. Merely skipping
	 * sleep_enable_now leaves an already sleeping radio asleep. Run in
	 * the original DTM controller context, before it computes deadlines. */
	if (s_dtm_capture && s_dtm_awake) r_ble_lll_sleep_disable(0);
	/* dtm_hal_schedEvent +0x4/+0xc: ls=context+20, scheduler=ls+88.
	 * Save entry before original advances the scheduler list; snapshot after
	 * successful programming. Allocation persists until HCI Test End. */
	void *state = *(void **)((uint8_t *)context + 20);
	volatile uint32_t *scheduler = *(volatile uint32_t **)((uint8_t *)state + 88);
	if (s_dtm_capture && s_dtm_raw_mode == 2 && kind == 1 && lab_ram_span((uint32_t)state, 120)) {
		/* dtm_hal_allocMemory +0x102 allocates255-byte TX payload;
		 * txCreateCtx +0xac/+0xb0 writes header at data+16/+17.
		 * Supply a deterministic body before the first scheduler start.
		 * This still has native BLE preamble/CRC: not an exact68bit ID. */
		uint32_t desc = ((volatile uint32_t *)state)[24];
		if (lab_ram_span(desc, 12)) {
			uint32_t offset = ((volatile uint32_t *)desc)[2] & 0xFFFFFu;
			uint32_t data = offset ? SOC_DRAM_LOW | offset : 0;
			if (lab_ram_span(data, 273)) {
				uint8_t *body = (uint8_t *)data + 16;
				memset(body, 0, 257);
				s_tx_body = body;
				for (unsigned i = 0; i < 4; ++i) body[i] = s_dtm_raw_tail >> (8*i);
				page_prepare_forced_tx(body);
				if (s_page_force_x < 32) s_page_tx_ctx = context;
			}
		}
	}
	bool previous = s_dtm_in_schedule;
	s_dtm_in_schedule = true;
	int result = orig_dtm_hal_schedEvent(context, kind);
	s_dtm_in_schedule = previous;
	if (result == 0) s_hop_armed = true; /* the first DTM event is running; later rstLst calls are per event */
	if (s_dtm_capture && result == 0 && scheduler) {
		s_dtm_sched_address = (uint32_t)scheduler;
		for (unsigned i = 0; i < 16; ++i) s_dtm_sched_words[i] = scheduler[i];
		++s_dtm_sched_calls;
	}
	return result;
}
IRAM_ATTR void dtm_hal_isr(void)
{
	if (s_dtm_capture) ++s_dtm_irqs;
	bool previous = s_dtm_in_schedule;
	s_dtm_in_schedule = true;
	orig_dtm_hal_isr();
	s_dtm_in_schedule = previous;
}

/* G4 slot hopping (seen in code, dtm_hal.c.o rescheduleNextEvent.part.0): per DTM event it calls
 * rstLst(ctx, ls) FIRST, then takes item = ls+88, start = ctx+24 + ctx+4 (ticks = us, measured 1250 us
 * period), keeps item+20 bits8..14 (frequency value) and hands the item to r_ble_lll_sched_run. So the
 * item at ls+88 here is the next event's: its frequency and the interval can be set per event. */
static volatile bool s_hop_on;
static uint8_t s_hop_f[2] = {0xFF, 0xFF};
static uint16_t s_hop_itvl_us;
static volatile uint32_t s_hop_events, s_hop_bad;
static volatile uint32_t s_hop_start[48];
/* G4 RX interleave (TX-mode DTM): events alternate TX on f1 / RX on f2. An RX event opens s_hop_early us
 * before its grid slot (interval 625-early before it, 625+early after it) for s_hop_window us. */
static volatile bool s_hop_rx;
static uint8_t s_hop_early;
static uint16_t s_hop_late; /* opt-in RX delay; complement the following interval to keep the TX grid */
static uint32_t s_hop_ls44_value; /* raw link-state+44 for RX events; 0 = leave DTM's value */
static uint16_t s_hop_end;        /* item+48 = start + s_hop_end for RX events */
static volatile bool s_hop_rx_now;
static void *volatile s_hop_ctx;
static volatile uint32_t s_hop_rx_events, s_hop_run_bad;
static uint32_t s_hop_ls44;
static volatile bool s_hop_ls44_saved;
/* G5 inquiry train: TX/RX pair p = (k+1)>>1 (RX event k even listens after TX event k-1) uses table entry
 * seg*16 + p%16, seg = (p / (16*repeats)) % (n/16): train A (entries 0..15) for `repeats` passes, then train B. */
static uint8_t s_train_n;
static uint16_t s_train_repeats = 1;
static uint8_t s_train_tx[32], s_train_rx[32];
IRAM_ATTR static uint32_t train_idx(uint32_t p)
{
	return ((p / (16u * s_train_repeats)) % (s_train_n / 16u)) * 16u + (p & 15u);
}
/* Train table order used by g4_inquiry.py: entries 0..15 = X 24..31,0..7 (train A), 16..31 = X 8..23 (train B). */
IRAM_ATTR static uint8_t train_x(uint32_t idx) { return (uint8_t)(idx < 16 ? (24u + idx) & 31u : 8u + (idx - 16u)); }

/* T4.2 page reaction (central). Pair p: TX our ID (target DAC) on page-scan f(X), RX on the first response f(X).
 * When the RX event that ended just before TX event k holds a fresh DAC match, TX event k becomes the FHS
 * (master page response, N = 1: frequency X+1/Y1=0, whitening (X+1)|0x60, built by RL_PAGE) and the following
 * RX event listens for the peripheral's second ID on X+1/Y1=1. */
#define PAGE_FHS_BYTES 38 /* air bits 68..365 (trailer, header, FHS payload) = DTM body[4..41] */
static volatile bool s_page_on;
static uint8_t s_page_fhs[32][PAGE_FHS_BYTES];
static uint8_t s_page_fhs_f[32], s_page_resp2_f[32];
/* Direct FHS control: isolate packet bytes/TX length from the reaction scheduler. */
static void page_prepare_forced_tx(uint8_t *body)
{
	if (s_page_force_x < 32)
		memcpy(body + 4, s_page_fhs[s_page_force_x], PAGE_FHS_BYTES);
}
static volatile uint8_t s_page_state; /* 0 paging, 2 resp2 RX scheduled, 3 FHS TX scheduled */
static volatile uint8_t s_page_x;
static volatile uint32_t s_page_last_stamp;
static volatile uint32_t s_page_resp1, s_page_fhs_sent, s_page_resp2, s_page_resp2_miss, s_page_rx_checks, s_page_bad;
static volatile uint32_t s_page_resp2_k[8];
/* 1.4.219 FHS timing log (first 8 FHS): Bose ID RX stamp, hook-time tick, previous event start (ctx+24),
 * interval written for the FHS event (ctx+4). FHS start = prev_start + interval. */
static volatile uint32_t s_page_dbg[8][4];
static volatile uint8_t s_page_dbg_n;
static volatile bool s_page_dbg_pending;
/* 1.4.224: ACTUAL starts (ctx+24 read at the following hook, after any rescheduler late-loop advance) of the
 * logged FHS TX event and of the resp2 RX event after it, as offsets from that reaction's ID stamp.
 * 0xFFFF = not reached. s_page_act_i = index of the s_page_dbg row the pending reaction belongs to. */
static volatile uint16_t s_page_act[8][2];
static volatile uint8_t s_page_act_i = 0xFF;
/* 1.4.224: fixed-X page (0xFF = off). When set, the reaction uses this X for FHS/resp2 instead of the X of the
 * train table entry, so a table whose every entry holds this X's frequencies pages a single X. */
static volatile uint8_t s_page_xfix = 0xFF;
static volatile uint32_t s_page_xf_agree, s_page_xf_differ; /* 1.4.245: frequency-derived X vs counter-derived X */
/* 1.4.247: peers whose DAC tail gives a BLE length byte of 56..80 need an FHS frame longer than one slot, which
 * overlaps the peripheral's second response (resp2). r2skip: do not wait for resp2, enter the connection after the
 * FHS anyway, and fall back to paging (provisional end, FIFO kept) when no reply arrives in the first
 * PAGE_PROV_SLOTS central slots (the FIFO sends nothing before slot 16). */
#define PAGE_PROV_SLOTS 12u
static volatile bool s_page_r2skip, s_conn_prov;
static volatile uint32_t s_page_r2skips, s_conn_prov_ends;
/* 1.4.248: a long FHS ends after the next event should have been armed, and the scheduler slips a whole slot (C6
 * log: resp2 RX at FHS+1875). r2late L: start the RX event after an FHS L us late and the following TX (the first
 * central slot) L us early, so the first POLL stays at FHS+1250. s_t3: actual starts of FHS (absolute), resp2 RX and
 * the first central TX (both relative to the FHS) for the first 8 FHS. */
static volatile uint16_t s_page_r2late;
/* 1.4.253 shifted FHS (any peer address). The FHS goes out as a DTM frame whose AA + 16-bit header carry sync bits
 * 0..47, so its BLE length byte was the peer's sync bits 40..47: only 40..80 could be paged (~16 % of addresses; the
 * frame must hold the FHS and end before the peer's next reply). With shift on, the whole BR packet (preamble, sync,
 * trailer, header, FHS payload: 366 bits) starts right after the BLE header instead, so the header is ours: length
 * PAGE_SHIFT_LEN for every peer. The AA (sync bits 0..31) stays, the event starts PAGE_SHIFT_US early so the BR
 * access code is on air exactly where it was (AA start - 4 us before, AA start + 48 us now), and the next event
 * starts that much later. The frame ends ~390 us after the BR packet start: resp2 needs no r2skip. */
#define PAGE_SHIFT_LEN 46u /* ceil(366 / 8) */
#define PAGE_SHIFT_US 52u
static volatile bool s_page_shift;
static uint8_t s_page_fhs_full[32][PAGE_SHIFT_LEN]; /* air bits 0..365 */
static volatile uint32_t s_page_shift_sent;
/* 1.4.263: BR modulation index. PHY register 0x600A043C bits 0..23 over 0x600A0438 scales the TX deviation (BLE 0.5;
 * 0x9BF7CE/0xF3B333 -> h 0.35, measured). Set for TX events only (written before each event is armed): with the
 * scaled value in force across received packets the link's TX carrier ends up ~150 kHz low. 0 = off. */
#define MOD_REG 0x600A043Cu
static volatile uint32_t s_mod_tx, s_mod_orig;
/* 1.4.264: the register scales the receiver too (DTM RX of h 0.5 packets: 225 vs 1748), so receive with the original
 * value. The hook for an RX event runs 300-400 us into the preceding TX packet: wait until that packet has ended
 * (its start + s_mod_tx_us, bounded) before restoring. Connection state only (paging keeps the BLE value). */
static volatile uint16_t s_mod_tx_us = 430;
static volatile uint32_t s_mod_waits, s_mod_wait_max;
static volatile int32_t s_itvl_adj;
static volatile bool s_r2_adj;
static volatile uint32_t s_t3[8][3];
static volatile uint8_t s_t3_n, s_t3_i = 0xFF;
/* 1.4.249: the event index k = round((prev - s_hop_ref) / 625) decides TX/RX by parity. When the connection grid
 * (set by the FHS) sat ~312 us off the ref grid, k flipped between neighbours (~200 jumps/s, ~20 % of RX events
 * became TX: 40 % no-reply links). The RX hook after an FHS re-anchors s_hop_ref on the FHS's actual start.
 * s_conn_phase: histogram of (prev - ref) mod 625 at central-slot hooks, 8 bins of 78 us centred on 0. */
static volatile uint32_t s_conn_phase[8], s_reanchors;
/* 1.4.225: reaction emulation (every s_page_kick pairs a TX hook in state 0 acts as if a response arrived, through
 * the identical reactive path) and a separate RX window for the resp2 RX that follows an FHS. 0 = off/same. */
static volatile uint16_t s_page_kick;
static volatile uint32_t s_page_kicks;
static volatile uint32_t s_page_r2_ls44;
/* 1.4.228: TX setup lead. rescheduleNextEvent writes item+44 = start - sched_env lead after rstLst; the hardware
 * sequencer starts setting up the item there. Measured: a TX after an RX whose window runs past ~ls44 1028 is
 * silently dropped. s_tx_lead (us, 0 = native) rewrites item+44 = start - s_tx_lead for TX events in the sched_run
 * hook. s_lead_seen = native start - item+44 of the last TX event (read before any change). */
static volatile uint16_t s_tx_lead;
/* 1.4.229: RX max length experiment. dtm_hal_rstLst sets ls+8 bits 20..27 = 0xFF (seen in code; mirrors the TX cap
 * in ls+0 bits 20..27). s_rx_max (1..255, 0 = native) is written there for RX events only. Hypothesis under test:
 * the receiver stops accepting an AA once a max-length packet no longer fits before the window end. */
static volatile uint8_t s_rx_max;
static volatile uint32_t s_rx_ls8_seen;
static volatile uint32_t s_lead_seen;
/* 1.4.225: second detection path. r_ble_lll_get_rxed_buffer runs when the controller processes a received packet;
 * it flags a page response (word == sync tail, new stamp) at that moment. s_page_det_rxed = 1: the reaction uses this
 * flag instead of page_rx_fresh. Logged either way: first 8 hits (tick when flagged, packet stamp). */
static volatile uint8_t s_page_det_rxed;
static volatile bool s_page_rxed_got;
static volatile uint32_t s_page_rxed_calls, s_page_rxed_hits, s_page_rxed_last;
static volatile uint32_t s_page_rxed_log[8][2];
/* 1.4.227: arming trace for the first 3 reactions. Stage 0 = the reaction hook (FHS TX event), 1 = next hook (resp2
 * RX), 2 = the hook after. Per stage: [0] hook tick, [1] item (ls+88) the hook edited, [2] f | rx<<8 | (k&0xFFFF)<<16,
 * [3] r_ble_lll_sched_run calls until the next hook | dtm ISR count low16 <<16 at the hook,
 * [4] item armed by the first sched_run (0x600A18FC), [5] its freq field | item+2 flags<<8 | (tick&0xFFFF)<<16. */
static volatile uint32_t s_tr[3][3][6];
static volatile uint8_t s_tr_row, s_tr_stage = 0xFF;
static volatile bool s_tr_pending;

/* 1.4.259: RF frequency memory (libphy phy_hw_freq.o): per-channel entries the hardware writes to the RF PLL over
 * I2C at each channel change. pll_dac_mem_update_new(v) stores one value in all 85 type-1 entries ("PLL DAC"):
 * candidate for the FSK modulation gain (BLE h 0.5 vs BR 0.28-0.35). */
/* 1.4.262: the PHY's own I2C master (RF blocks 0x62/0x63/0x67, host 1); host | 0x80 = system regi2c path */
extern uint8_t rom_chip_i2c_readReg(uint32_t block, uint32_t host, uint32_t reg);
extern void rom_chip_i2c_writeReg(uint32_t block, uint32_t host, uint32_t reg, uint32_t data);
extern uint32_t get_freq_mem_param(int which);
extern uint32_t get_freq_mem_addr(uint32_t a, uint32_t b, uint32_t chan, uint32_t type);
extern uint32_t read_rf_freq_mem_new(uint32_t addr, uint32_t sel);
extern void pll_dac_mem_update_new(uint32_t v);
static uint32_t freq_mem_read(uint32_t chan, uint32_t type, uint32_t sel)
{
	const uint32_t prm = get_freq_mem_param(2);
	return read_rf_freq_mem_new(get_freq_mem_addr((prm >> 16) & 0xFFu, (prm >> 8) & 0xFFu, chan, type), sel);
}

/* Same read path as raw_match_worker (DTM RX buffer behind ls+8): fresh timestamp and word == sync bits 32..63. */
/* 1.4.232: page detection compare mask, see lab page mask (RL_PAGE mode 11). */
static volatile uint32_t s_page_mask = 0xFFFFFFFFu;
IRAM_ATTR static bool page_rx_fresh(void *descriptor)
{
	const volatile uint32_t *ls = (const volatile uint32_t *)descriptor;
	uint32_t off = ls[2] & 0xFFFFFu;
	if (off < 4) return false;
	const uint32_t desc = (SOC_DRAM_LOW | off) - 4u;
	if ((desc & 3u) || desc < SOC_DRAM_LOW || desc >= SOC_DRAM_HIGH - 12) return false;
	off = ((const volatile uint32_t *)desc)[2] & 0xFFFFFu;
	const uint32_t data = off ? (SOC_DRAM_LOW | off) : 0;
	if (!data || (data & 3u) || data >= SOC_DRAM_HIGH - 32) return false;
	const volatile uint32_t *d = (const volatile uint32_t *)data;
	const uint32_t stamp = d[4], word = d[7];
	++s_page_rx_checks;
	if (stamp == s_page_last_stamp) return false;
	s_page_last_stamp = stamp;
	return ((word ^ s_dtm_raw_tail) & s_page_mask) == 0;
}

/* 1.4.230: detection from the buffer the RX event was set up with. At the RX event's hook (after orig rstLst
 * re-pointed ls+8 for it) remember the data address; at the following TX hook read stamp/word from it. */
static volatile uint32_t s_rx_saved_data, s_rx_saved_last;
/* 1.4.232: compare mask for page detection (det 0/2). With rxmax < 55 the radio stores the header rewritten
 * (measured word 00070083 for tail B05B3783): only the first byte after the AA (sync bits 32..39) survives, so
 * mask 0x000000FF checks 32 AA bits + 8 sync bits. */
/* 1.4.230: det 3 = detection by the rawmatch worker (polls the RX buffer during the RX event, which still sees packets
 * the controller later discards, e.g. with rxmax < the ID's BLE length byte). Flag + tick; the TX hook accepts it if
 * younger than s_poll_max_age ticks (us). */
static volatile bool s_page_poll_got;
static volatile uint32_t s_page_poll_tick, s_page_poll_hits, s_page_poll_used, s_page_poll_stale;
#define PAGE_POLL_MAX_AGE_US 1000u
IRAM_ATTR static uint32_t ls8_data(const volatile uint32_t *ls)
{
	uint32_t off = ls[2] & 0xFFFFFu;
	if (off < 4) return 0;
	const uint32_t desc = (SOC_DRAM_LOW | off) - 4u;
	if ((desc & 3u) || desc < SOC_DRAM_LOW || desc >= SOC_DRAM_HIGH - 12) return 0;
	off = ((const volatile uint32_t *)desc)[2] & 0xFFFFFu;
	const uint32_t data = off ? (SOC_DRAM_LOW | off) : 0;
	return (!data || (data & 3u) || data >= SOC_DRAM_HIGH - 32) ? 0 : data;
}
IRAM_ATTR static bool page_rx_saved(void)
{
	const uint32_t data = s_rx_saved_data;
	if (!data) return false;
	const volatile uint32_t *d = (const volatile uint32_t *)data;
	const uint32_t stamp = d[4], word = d[7];
	if (stamp == s_rx_saved_last) return false;
	s_rx_saved_last = stamp;
	return ((word ^ s_dtm_raw_tail) & s_page_mask) == 0;
}

/* 1.4.233: T4.2 step 3, connection state (central). Armed by RL_PAGE mode 12 with OUR LAP/UAP (must equal the
 * own address in the FHS, whose CLK27_2 is 0). After the peripheral's second ID the next TX event is the first
 * central slot (FHS + 1250 us): access code switches to ours, each TX event sends POLL (LT_ADDR 1) on
 * br_hop_connection(our addr, CLK) with CLK = 4(n+1) for central slot n, the following RX event listens on CLK+2.
 * Our LAP's sync bits 40..47 are the BLE length byte: TX cap = that length (40..55, else the frame aborts).
 * Replies are detected from the RX-time buffer with the page compare mask. After s_conn_slots slots: back to paging. */
#define CONN_RING 512u     /* 1.4.234: frequency ring, refilled by conn_fill_task ahead of the radio */
#define CONN_POLL_BYTES 8 /* air bits 68..125 (trailer + header) */
#define CONN_LOG_N 48
#define CONN_LOG_BYTES 48 /* RX buffer bytes from data+28 (sync bits 32..63 first) */
static volatile bool s_conn_armed;
static uint8_t s_conn_len;
static uint32_t s_conn_aa, s_conn_tail, s_conn_save_aa, s_conn_save_tail;
static uint8_t s_conn_poll[64][CONN_POLL_BYTES];
static uint8_t s_conn_f_tx[CONN_RING], s_conn_f_rx[CONN_RING];
static volatile uint32_t s_conn_n, s_conn_slots, s_conn_fill, s_conn_underrun;
static volatile bool s_conn_ready, s_conn_refill;
static uint32_t s_conn_a28;
static uint32_t s_conn_aa_lap; static uint8_t s_conn_aa_uap;
static volatile uint8_t s_conn_rxmax;   /* RX max length on connection RX events (0 = page setting) */
static volatile uint32_t s_conn_ls44;   /* ls+44 on connection RX events (0 = page setting) */
static uint8_t s_conn_log[CONN_LOG_N][CONN_LOG_BYTES];
static uint32_t s_conn_log_slot[CONN_LOG_N];
static volatile uint8_t s_conn_log_n;
/* 1.4.235: with rxmax 44 our packets are valid for the radio and it moves on through its RX buffer ring, so the
 * buffer recorded at the RX hook goes stale after a few receptions. Connection detection = recorded buffer OR the
 * buffer ls+8 points to at the TX hook (separate stamp memory); counters per path. */
static volatile uint32_t s_conn_hit_saved, s_conn_hit_now, s_conn_now_last;
static volatile uint32_t s_conn_buf_trace[32][2]; /* first 32 connection TX hooks: recorded RX buffer, ls+8 buffer now */
/* 1.4.236: return received buffers to the RX ring like DTM RX mode does (dtm_hal_recycleSchItem +0xee..0x102:
 * while (rx = get_rxed_buffer(ls, 0)) { status = data+12 low24 (0 = OK); append_rx_buffer(ls, rx); }). Our TX-mode
 * events never did this, so valid receptions (length byte <= rxmax) used up the ring and RX stopped. */
IRAM_ATTR void *r_ble_lll_get_rxed_buffer(void *state, void *current);
extern void r_ble_lll_append_rx_buffer(void *state, void *rx);
static volatile uint32_t s_conn_drained, s_conn_hit_rxed, s_conn_rxed_last;
/* 1.4.238: log only non-NULL replies. Precomputed air bits 72..125 (FEC-1/3 header, whitened) of NULL with LT_ADDR 1
 * for every clk6 and flow/arqn/seqn combination; a reply whose header matches one of them is not logged. In the RX
 * buffer the header starts at byte 4 + 4 bits (air bit 72 = data+28 bit 36). */
static uint64_t s_conn_null_hdr[64][8];
/* 1.4.240: NULL test after 1/3-FEC majority decoding (18 bits), so single bit errors per triple no longer count as
 * "other"; the log is a ring (s_conn_log_count = total entries ever written; entry i lives at i % CONN_LOG_N). */
static uint32_t s_conn_null_mv[64][8];
static volatile uint32_t s_conn_log_count;
IRAM_ATTR static uint32_t conn_maj18(uint64_t h)
{
	uint32_t r = 0;
	for (unsigned i = 0; i < 18; ++i) {
		const unsigned v = (unsigned)((h >> (3 * i)) & 1u) + (unsigned)((h >> (3 * i + 1)) & 1u) + (unsigned)((h >> (3 * i + 2)) & 1u);
		if (v >= 2) r |= 1u << i;
	}
	return r;
}
/* 1.4.239: LMP transmit queue. Each entry is a DM1 (LT_ADDR 1, LLID 3 = LMP, ARQN 1, fixed SEQN) pre-encoded for all
 * 64 clk6 values (air bits 68.., <= 298 bits = 38 bytes). It is sent in `repeat` consecutive central slots starting
 * at connection slot `start`; repeats carry the same SEQN, so the peripheral accepts one copy and ACKs/ignores the
 * rest (no ARQN parsing needed). POLLs carry ARQN 1 to acknowledge whatever the peripheral sends. */
#define LMP_Q 4
#define LMP_PKT_BYTES 38
typedef struct { uint16_t start, repeat; uint8_t used, nbytes, enc; uint8_t pkt[64][LMP_PKT_BYTES]; } lmp_q_t;
/* 1.4.242: E0 encryption of queued DM1 payloads. When on, an entry is encoded for its exact slots (pkt[i] = slot start+i,
 * CLK = 4(slot+1)), each with its own E0 keystream (Kc', central BD_ADDR index 0 = LSB). POLL has no payload. */
static volatile bool s_enc_on;
static volatile bool s_enc_rx; /* 1.4.244: decrypt received packets (verify task); s_enc_on = also encrypt TX */
static uint8_t s_enc_kc[16], s_enc_addr[6];
static lmp_q_t s_lmp_q[LMP_Q];
static volatile uint32_t s_lmp_sent;
static volatile uint32_t s_conn_nulls, s_conn_others;
IRAM_ATTR static uint64_t conn_hdr_bits(const volatile uint8_t *b) /* 54 bits from bit 36 of b */
{
	uint64_t v = 0;
	for (unsigned i = 0; i < 54; ++i) {
		const unsigned bit = 36 + i;
		v |= (uint64_t)((b[bit >> 3] >> (bit & 7)) & 1u) << i;
	}
	return v;
}
IRAM_ATTR static uint32_t conn_rx_now(const volatile uint32_t *ls)
{
	const uint32_t data = ls8_data(ls);
	if (!data) return 0;
	const volatile uint32_t *d = (const volatile uint32_t *)data;
	const uint32_t stamp = d[4], word = d[7];
	if (stamp == s_conn_now_last || stamp == s_rx_saved_last) return 0;
	s_conn_now_last = stamp;
	return ((word ^ s_dtm_raw_tail) & s_page_mask) == 0 ? data : 0;
}
static volatile uint32_t s_conn_entries, s_conn_rx, s_conn_tx;
/* 1.4.245: supervision timeout (slots without any reply; 0 = off) and host-requested end of the connection */
static volatile uint32_t s_conn_sup = 4000, s_conn_last_rx_n, s_conn_sup_ends, s_conn_host_ends;
static volatile bool s_conn_end_req;
static volatile uint16_t s_conn_rx_first[16];
static volatile uint8_t s_conn_rx_first_n;
IRAM_ATTR static void conn_set_tail(uint8_t *body, uint32_t tail)
{
	for (unsigned i = 0; i < 4; ++i) body[i] = (uint8_t)(tail >> (8 * i));
}
/* 1.4.244: ACL FIFO with ARQ in both directions (replaces the 64-variant LMP queue for --fifo hosts).
 *
 * TX: the host (or the A2DP stream task) queues fragments (DM1 for LMP, DH1 for L2CAP); each is stored once as plain
 * payload bits (payload header + body + CRC). conn_fill_task precomputes, per central slot, the payload mask
 * (whitening after the header xor the E0 keystream, br_fast_mask); at the TX hook the ISR builds the head fragment for
 * this exact slot from a header table [clk6][POLL/DM1/DH1][ARQN][SEQN] + br_fast_payload (XOR + FEC 2/3 table). The
 * head stays in the FIFO until the peripheral's reply in the same slot pair carries ARQN = 1 (then SEQN toggles).
 *
 * RX: the reply header is FEC-majority decoded, de-whitened and HEC-checked in the ISR. A data packet (DM1/DH1) is
 * NAKed (our ARQN 0) until the verify task has decoded one copy with a good CRC (decrypting when encryption is on);
 * the next copy with the same SEQN is then ACKed and the verified copy is the one logged for the host. A packet
 * already ACKed (our ACK lost) is ACKed again and not logged twice. No reply / bad HEC -> NAK. */
#define FIFO_N 64
#define MASK_N 64
#define MASK_AHEAD 40
typedef struct { uint8_t type; uint8_t nbits; uint8_t plain[BR_FAST_PAYLOAD_BYTES]; } fifo_e_t;
static fifo_e_t s_fifo[FIFO_N];
static volatile uint32_t s_fifo_head, s_fifo_tail; /* head = oldest unacknowledged, tail = next free */
static volatile bool s_fifo_on;
static volatile uint8_t s_tx_seqn, s_tx_inflight, s_rx_arqn;
static volatile uint16_t s_fifo_last_tag;
static uint8_t s_mask[MASK_N][BR_FAST_PAYLOAD_BYTES];
static volatile uint32_t s_mask_slot[MASK_N];
static volatile uint32_t s_mask_fill;
static volatile bool s_mask_reset;
static uint64_t s_hdr_tab[64][3][2][2]; /* body bits 0..57: access-code trailer (4) + header (54) */
static uint16_t s_fec_tab[1024];
static uint32_t s_hw18[64];
static uint8_t s_hec_tab[1024];
static uint8_t s_conn_head[8]; /* air bits 0..35 of our packets (preamble + sync 0..31), for the verify decode */
static volatile uint32_t s_fifo_tx, s_fifo_retx, s_fifo_acked, s_fifo_nomask, s_rx_nak, s_rx_ack, s_rx_hecfail,
	s_rx_verified, s_rx_verify_fail, s_rx_dup, s_rx_noreply, s_mask_us_max, s_mask_n;
/* verify hand-off (ISR -> task): 0 idle, 1 pending, 2 verified */
static volatile uint8_t s_rxv_state, s_rxv_seqn, s_rx_acked_seqn = 0xFF;
static uint8_t s_rxv_buf[CONN_LOG_BYTES];
static volatile uint32_t s_rxv_slot;
static TaskHandle_t s_rxv_task;
/* A2DP stream test (1.4.244): loops k_sbc_beep as RTP media packets into the FIFO, paced at real time */
static volatile bool s_stream_on;
static volatile uint16_t s_stream_dcid;
static volatile uint8_t s_stream_fpp;
static volatile uint32_t s_stream_max, s_stream_pkts, s_stream_frames, s_stream_full, s_stream_skips;
/* 1.4.246: host-fed SBC frames (page mode 24, pushed by the P4's encoder; handled in the HCI receive path) */
#define SBC_RING_N 128
#define SBC_FRAME_MAX 64
static uint8_t s_sbc_ring[SBC_RING_N][SBC_FRAME_MAX];
static uint8_t s_sbc_len[SBC_RING_N]; /* 1.4.252: per-frame length (the host adapts the bitpool mid-stream) */
static volatile uint32_t s_sbc_w, s_sbc_r, s_sbc_drops, s_sbc_in;
static volatile uint8_t s_sbc_flen, s_stream_src; /* source: 1 built-in beep, 2 host frames */
/* 1.4.258: media in DM1 (2/3 FEC, 17 bytes) instead of DH1 (27 bytes, no FEC): for sinks that lose payload bits */
static volatile bool s_stream_dm1;
static volatile uint8_t s_stream_frag; /* 1.4.260: DH1 fragment bytes (0 = 27); diagnostics: success vs length */

IRAM_ATTR static inline uint32_t fifo_count(void) { return s_fifo_tail - s_fifo_head; }
/* 1.4.254: per-channel link statistics (RF channel 0..78 = 2402..2480 MHz): central slots and slots without a reply,
 * by our TX channel and by the peripheral's reply channel. Wi-Fi shows up as a block of ~20 bad channels, radio
 * time-sharing in the peer as uniform loss. lab page chanq [0]. */
static uint32_t s_ch_tx_n[79], s_ch_tx_miss[79], s_ch_rx_n[79], s_ch_rx_miss[79];
/* 1.4.255: the peripheral's reply to our data packets (decoded headers only): ARQN=1, FLOW=0 (stop), packet type */
static uint32_t s_rep_n, s_rep_arqn1, s_rep_flow0, s_rep_type[16];

/* The ISR part, called at the TX hook of central slot n with the reply to slot n-1 (data = RX buffer or 0). Writes
 * this slot's packet into dst (= body + 4, LMP_PKT_BYTES). */
IRAM_ATTR static void fifo_slot(uint8_t *dst, uint32_t n, uint32_t data, bool is_null)
{
	/* 1. the reply to slot n-1: header via FEC majority + de-whitening + HEC */
	bool hdr_ok = false;
	uint32_t v = 0;
	const uint32_t c6rx = ((4u * n + 2u) >> 1) & 63u;
	if (data) {
		const uint32_t raw = conn_maj18(conn_hdr_bits((const volatile uint8_t *)data + 28)) ^ s_hw18[c6rx];
		v = raw & 0x3FFu;
		hdr_ok = s_hec_tab[v] == (uint8_t)(raw >> 10) && (v & 7u) == 1u;
		if (!hdr_ok) ++s_rx_hecfail;
	} else if (n > 0) {
		++s_rx_noreply;
	}
	if (n > 0) {
		const uint8_t ftx = s_conn_f_tx[(n - 1u) % CONN_RING], frx = s_conn_f_rx[(n - 1u) % CONN_RING];
		if (ftx < 79 && frx < 79) {
			++s_ch_tx_n[ftx]; ++s_ch_rx_n[frx];
			if (!data) { ++s_ch_tx_miss[ftx]; ++s_ch_rx_miss[frx]; }
		}
	}
	const uint32_t type = (v >> 3) & 15u, peer_arqn = (v >> 8) & 1u, peer_seqn = (v >> 9) & 1u;
	/* 2. our packet of slot n-1: acknowledged? */
	if (s_tx_inflight && hdr_ok) {
		++s_rep_n; s_rep_arqn1 += peer_arqn; s_rep_flow0 += !((v >> 7) & 1u); ++s_rep_type[type];
	}
	if (s_tx_inflight) {
		if (hdr_ok && peer_arqn) { s_fifo_head = s_fifo_head + 1u; s_tx_seqn ^= 1u; ++s_fifo_acked; }
		else ++s_fifo_retx;
		s_tx_inflight = 0;
	}
	/* 3. our ARQN for the peripheral's packet */
	if (!data || !hdr_ok) {
		s_rx_arqn = 0;
	} else if (is_null || type == BR_TYPE_NULL || type == BR_TYPE_POLL) {
		/* no CRC packet: ARQN keeps referring to the last data packet */
	} else if (type != BR_TYPE_DM1 && type != BR_TYPE_DH1) {
		s_rx_arqn = 0;
	} else if (peer_seqn == s_rx_acked_seqn) {
		s_rx_arqn = 1; ++s_rx_dup;           /* our ACK was lost: acknowledge again, logged already */
	} else if (s_rxv_state == 2 && s_rxv_seqn == peer_seqn) {
		s_rx_arqn = 1; s_rx_acked_seqn = (uint8_t)peer_seqn; s_rxv_state = 0; ++s_rx_ack;
	} else {
		s_rx_arqn = 0; ++s_rx_nak;
		if (s_rxv_state == 2) s_rxv_state = 0;  /* verified a different SEQN: stale */
		if (s_rxv_state == 0) {
			const volatile uint8_t *src = (const volatile uint8_t *)data + 28;
			for (unsigned i = 0; i < CONN_LOG_BYTES; ++i) s_rxv_buf[i] = src[i];
			s_rxv_slot = n - 1u; s_rxv_seqn = (uint8_t)peer_seqn; s_rxv_state = 1;
			if (s_rxv_task) vTaskNotifyGiveFromISR(s_rxv_task, NULL);
		}
	}
	/* 4. this slot's packet */
	for (unsigned i = 0; i < LMP_PKT_BYTES; ++i) dst[i] = 0;
	const uint32_t c6 = ((4u * (n + 1u)) >> 1) & 63u;
	const uint32_t mi = n % MASK_N;
	const fifo_e_t *e = NULL;
	if (n >= 16 && fifo_count()) {
		if (s_mask_slot[mi] == n) e = &s_fifo[s_fifo_head % FIFO_N];
		else ++s_fifo_nomask;
	}
	const uint64_t h = s_hdr_tab[c6][e ? (e->type == BR_TYPE_DM1 ? 1 : 2) : 0][s_rx_arqn][e ? s_tx_seqn : 0];
	for (unsigned i = 0; i < 8; ++i) dst[i] = (uint8_t)(h >> (8 * i));
	if (e) {
		br_fast_payload(e->type, e->plain, e->nbits, s_mask[mi], s_fec_tab, dst, 58);
		s_tx_inflight = 1; ++s_fifo_tx;
	}
}

/* Precomputes payload masks for upcoming central slots (task context). Encryption state is read per slot. */
static void fifo_masks(void)
{
	if (!s_fifo_on) return;
	if (s_mask_reset) {
		for (unsigned i = 0; i < MASK_N; ++i) s_mask_slot[i] = 0xFFFFFFFFu;
		s_mask_fill = s_page_state == 4 ? s_conn_n + 2u : 0u;
		s_mask_reset = false;
	}
	const uint32_t now = s_page_state == 4 ? s_conn_n : 0u;
	if (s_mask_fill < now + 1u) s_mask_fill = now + 1u; /* fell behind: skip what the radio already passed */
	while (s_mask_fill < now + MASK_AHEAD && s_mask_fill < s_conn_slots) {
		const uint32_t s = s_mask_fill, mi = s % MASK_N;
		const int64_t t0 = esp_timer_get_time();
		s_mask_slot[mi] = 0xFFFFFFFFu;
		br_fast_mask(4u * (s + 1u), s_enc_on ? s_enc_kc : NULL, s_enc_addr, s_mask[mi]);
		s_mask_slot[mi] = s;
		s_mask_fill = s + 1u;
		const uint32_t us = (uint32_t)(esp_timer_get_time() - t0);
		if (us > s_mask_us_max) s_mask_us_max = us;
		++s_mask_n;
		if (s_mask_reset) return;
	}
}

/* Verify task: full decode (de-whitening, FEC, decryption, CRC) of one received copy; logs it for the host. */
static void fifo_verify_task(void *unused)
{
	(void)unused;
	static uint8_t air[8 + CONN_LOG_BYTES + 4];
	static br_pkt_t vp;
	static br_e0_t ve0;
	for (;;) {
		ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
		if (s_rxv_state != 1) continue;
		memset(air, 0, sizeof air);
		for (unsigned b = 0; b < 36; ++b) if (br_bit_get(s_conn_head, b)) air[b >> 3] |= (uint8_t)(1u << (b & 7));
		for (unsigned b = 0; b < 8 * CONN_LOG_BYTES; ++b)
			if ((s_rxv_buf[b >> 3] >> (b & 7)) & 1u) air[(36 + b) >> 3] |= (uint8_t)(1u << ((36 + b) & 7));
		const uint32_t clk = 4u * (s_rxv_slot + 1u) + 2u;
		br_status_t rc = BR_ERR_CRC;
		for (int attempt = s_enc_rx ? 0 : 1; attempt < 2 && rc != BR_OK; ++attempt) {
			/* attempt 0: decrypted (the peripheral encrypts from its LMP_accepted(start_encryption_req) on), 1: plain */
			if (attempt == 0) br_e0_init(&ve0, s_enc_kc, s_enc_addr, clk);
			const br_link_ctx_t ctx = { .lap = s_conn_aa_lap, .uap = s_conn_aa_uap, .clk6 = (uint8_t)((clk >> 1) & 63u),
			                            .sync_tolerance = 4, .e0 = attempt == 0 ? &ve0 : NULL };
			memset(&vp, 0, sizeof vp);
			rc = br_packet_decode(air, 36 + 8 * CONN_LOG_BYTES, &ctx, &vp);
		}
		if (rc == BR_OK && vp.hdr.seqn == s_rxv_seqn && (vp.hdr.type == BR_TYPE_DM1 || vp.hdr.type == BR_TYPE_DH1)) {
			const unsigned e = s_conn_log_count % CONN_LOG_N;
			memcpy(s_conn_log[e], s_rxv_buf, CONN_LOG_BYTES);
			s_conn_log_slot[e] = s_rxv_slot;
			s_conn_log_count = s_conn_log_count + 1u;
			if (s_conn_log_n < CONN_LOG_N) ++s_conn_log_n;
			++s_rx_verified;
			s_rxv_state = 2;
		} else {
			++s_rx_verify_fail;
			s_rxv_state = 0;
		}
	}
}

/* Queues one fragment (task context). Returns false when full. */
static bool fifo_push(uint8_t type, uint8_t llid, const uint8_t *data, unsigned len)
{
	if (fifo_count() >= FIFO_N || (type == BR_TYPE_DM1 && len > 17) || len > 27) return false;
	fifo_e_t *e = &s_fifo[s_fifo_tail % FIFO_N];
	e->type = type;
	e->nbits = (uint8_t)br_fast_plain(llid, 1, data, len, s_conn_aa_uap, e->plain);
	s_fifo_tail = s_fifo_tail + 1u;
	return true;
}

/* A2DP stream test: builds L2CAP (media CID) + RTP + SBC payload header + s_stream_fpp beep frames, fragments into
 * DH1 (27 bytes: LLID 2 then 1) and queues when the whole packet fits; paces packets at real time with 150 ms lead. */
static void stream_task(void *unused)
{
	(void)unused;
	static uint8_t pkt[4 + 13 + 15 * SBC_FRAME_MAX];
	uint32_t frame = 0, seq = 0, ts = 0;
	int64_t t0 = 0;
	bool was_on = false;
	for (;;) {
		if (!s_stream_on || s_page_state != 4 || !s_fifo_on) { was_on = false; vTaskDelay(10); continue; }
		if (!was_on) { was_on = true; t0 = esp_timer_get_time(); frame = seq = ts = 0; }
		if (s_stream_max && s_stream_pkts >= s_stream_max) { s_stream_on = false; continue; }
		const unsigned fpp = s_stream_fpp;
		if (s_stream_src == 2) {
			/* host frames: the P4 paces in real time; send whenever a packet's worth is buffered */
			if (!s_sbc_flen || s_sbc_w - s_sbc_r < fpp) { vTaskDelay(1); continue; }
			unsigned body = 13u;
			for (unsigned f = 0; f < fpp; ++f) body += s_sbc_len[(s_sbc_r + f) % SBC_RING_N];
			const unsigned fl = s_stream_dm1 ? 17u : (s_stream_frag ? s_stream_frag : 27u);
			const unsigned total = 4u + body, frags = (total + fl - 1u) / fl;
			if (FIFO_N - fifo_count() < frags) { ++s_stream_full; vTaskDelay(1); continue; }
			pkt[0] = (uint8_t)body; pkt[1] = (uint8_t)(body >> 8); pkt[2] = (uint8_t)s_stream_dcid; pkt[3] = (uint8_t)(s_stream_dcid >> 8);
			uint8_t *r = pkt + 4;
			r[0] = 0x80; r[1] = 96; r[2] = (uint8_t)(seq >> 8); r[3] = (uint8_t)seq;
			r[4] = (uint8_t)(ts >> 24); r[5] = (uint8_t)(ts >> 16); r[6] = (uint8_t)(ts >> 8); r[7] = (uint8_t)ts;
			r[8] = 0; r[9] = 0; r[10] = 0; r[11] = 1; r[12] = (uint8_t)fpp;
			for (unsigned f = 0, o = 13; f < fpp; ++f) {
				const unsigned e = (s_sbc_r + f) % SBC_RING_N;
				memcpy(r + o, s_sbc_ring[e], s_sbc_len[e]);
				o += s_sbc_len[e];
			}
			s_sbc_r = s_sbc_r + fpp;
			for (unsigned off = 0; off < total; off += fl)
				(void)fifo_push(s_stream_dm1 ? BR_TYPE_DM1 : BR_TYPE_DH1, off ? 1u : 2u, pkt + off, total - off < fl ? total - off : fl);
			ts += fpp * 128u; ++seq; ++s_stream_pkts; s_stream_frames += fpp;
			continue;
		}
		const int64_t due = t0 + (int64_t)frame * 128 * 1000000 / 44100 - 150000;
		const int64_t now = esp_timer_get_time();
		if (now < due) { vTaskDelay(1); continue; }
		if (now - due > 400000) {
			/* 1.4.245: the link fell behind by more than the sink's buffer: drop stale audio, resume at real time */
			const uint32_t skip = (uint32_t)((now - due - 150000) * 44100 / 128 / 1000000);
			frame += skip; ts += skip * 128u; ++s_stream_skips;
			continue;
		}
		const unsigned body = 13u + fpp * SBC_BEEP_FRAME_BYTES, total = 4u + body;
		const unsigned frags = (total + 26u) / 27u;
		if (FIFO_N - fifo_count() < frags) { ++s_stream_full; vTaskDelay(1); continue; }
		pkt[0] = (uint8_t)body; pkt[1] = (uint8_t)(body >> 8); pkt[2] = (uint8_t)s_stream_dcid; pkt[3] = (uint8_t)(s_stream_dcid >> 8);
		uint8_t *r = pkt + 4;
		r[0] = 0x80; r[1] = 96; r[2] = (uint8_t)(seq >> 8); r[3] = (uint8_t)seq;
		r[4] = (uint8_t)(ts >> 24); r[5] = (uint8_t)(ts >> 16); r[6] = (uint8_t)(ts >> 8); r[7] = (uint8_t)ts;
		r[8] = 0; r[9] = 0; r[10] = 0; r[11] = 1; r[12] = (uint8_t)fpp;
		for (unsigned f = 0; f < fpp; ++f)
			memcpy(r + 13 + f * SBC_BEEP_FRAME_BYTES, k_sbc_beep + ((frame + f) % SBC_BEEP_FRAMES) * SBC_BEEP_FRAME_BYTES,
			       SBC_BEEP_FRAME_BYTES);
		for (unsigned off = 0; off < total; off += 27u)
			(void)fifo_push(BR_TYPE_DH1, off ? 1u : 2u, pkt + off, total - off < 27u ? total - off : 27u);
		frame += fpp; ts += fpp * 128u; ++seq;
		++s_stream_pkts; s_stream_frames += fpp;
	}
}

/* Tables for the fast path (task context, at arm time). */
static void fifo_tables(uint8_t ouap, const uint8_t *poll_air)
{
	br_fast_fec23_table(s_fec_tab);
	for (unsigned v = 0; v < 1024; ++v) s_hec_tab[v] = br_hec((uint16_t)v, ouap);
	const uint64_t trailer = (uint64_t)(s_conn_poll[0][0] & 0x0Fu);
	static const uint8_t types[3] = {BR_TYPE_POLL, BR_TYPE_DM1, BR_TYPE_DH1};
	for (unsigned c = 0; c < 64; ++c) {
		s_hw18[c] = br_fast_header_whitening((uint8_t)c);
		for (unsigned t = 0; t < 3; ++t)
			for (unsigned a = 0; a < 2; ++a)
				for (unsigned s = 0; s < 2; ++s) {
					const br_header_t hh = { .lt_addr = 1, .type = types[t], .flow = 1, .arqn = (uint8_t)a, .seqn = (uint8_t)s };
					s_hdr_tab[c][t][a][s] = trailer | (br_fast_header(&hh, ouap, (uint8_t)c) << 4);
				}
	}
	memset(s_conn_head, 0, sizeof s_conn_head);
	for (unsigned b = 0; b < 36; ++b) if (br_bit_get(poll_air, b)) s_conn_head[b >> 3] |= (uint8_t)(1u << (b & 7));
}

static void fifo_reset(bool on, uint8_t first_seqn)
{
	s_fifo_on = false;
	s_stream_on = false;
	s_fifo_head = s_fifo_tail = 0; s_fifo_last_tag = 0;
	s_tx_seqn = first_seqn & 1u; s_tx_inflight = 0; s_rx_arqn = 0;
	s_rxv_state = 0; s_rx_acked_seqn = 0xFF;
	s_fifo_tx = s_fifo_retx = s_fifo_acked = s_fifo_nomask = s_rx_nak = s_rx_ack = s_rx_hecfail = 0;
	s_rx_verified = s_rx_verify_fail = s_rx_dup = s_rx_noreply = s_mask_us_max = s_mask_n = 0;
	s_stream_pkts = s_stream_frames = s_stream_full = s_stream_skips = 0;
	s_sbc_w = s_sbc_r = 0; s_sbc_drops = s_sbc_in = 0; s_sbc_flen = 0;
	s_mask_reset = true;
	if (on && !s_rxv_task) xTaskCreate(fifo_verify_task, "conn_verify", 4096, NULL, configMAX_PRIORITIES - 2, &s_rxv_task);
	s_fifo_on = on;
}

static TaskHandle_t s_conn_task;
static void conn_fill_slot(uint32_t i)
{
	const uint32_t clk = (4u * (i + 1u)) & 0x0FFFFFFFu; /* CLK27..0 */
	s_conn_f_tx[i % CONN_RING] = (uint8_t)br_hop_connection(s_conn_a28, clk);
	s_conn_f_rx[i % CONN_RING] = (uint8_t)br_hop_connection(s_conn_a28, clk + 2u);
}
/* (Re)build slots 0.. into the ring; only while no connection runs (state != 4). */
static void conn_fill_from(uint32_t first)
{
	s_conn_fill = first;
	const uint32_t last = s_conn_slots < CONN_RING ? s_conn_slots : CONN_RING;
	for (uint32_t i = first; i < last; ++i) conn_fill_slot(i);
	s_conn_fill = last;
}
/* Keeps the ring ahead of the radio during a connection; rebuilds it after one ends. */
static void conn_fill_task(void *unused)
{
	(void)unused;
	for (;;) {
		if (s_conn_armed && s_conn_refill && s_page_state != 4) {
			conn_fill_from(0);
			s_conn_refill = false; s_conn_ready = true;
		} else if (s_conn_armed && s_page_state == 4) {
			while (s_conn_fill < s_conn_slots && s_conn_fill < s_conn_n + CONN_RING - 32u) {
				conn_fill_slot(s_conn_fill);
				s_conn_fill = s_conn_fill + 1u;
			}
		}
		if (s_conn_armed) fifo_masks();
		vTaskDelay(1);
	}
}

/* 1.4.237: event index from the scheduled time, not from the number of hook calls. A valid reception can make the
 * controller run the rescheduler (and this hook) an extra time; counting calls then flipped TX/RX parity mid-
 * connection (measured: our POLL frames appeared in the peripheral's slots). k = (previous start - first start)/625
 * rounded; a second call with the same k re-applies the same configuration without advancing any state machine. */
static uint32_t s_hop_ref, s_hop_last_k = 0xFFFFFFFFu;
static uint8_t s_hop_last_f = 0xFF;
static bool s_hop_last_rx;
static volatile uint32_t s_hop_dups, s_hop_jumps;
static uint32_t s_conn_k0;
/* 1.4.250 diagnostics: hook latency (now - previous start) histogram during the connection, 16 bins of 100 us, and
 * the first 32 event jumps: k - k0, k - last_k, last event rx, phase (prev - ref) mod 625 + 312 offset, latency. */
static volatile uint32_t s_lat_hist[2][16];
static volatile uint32_t s_jl[32][4];
static volatile uint8_t s_jl_n;
/* 1.4.251: late-hook slot skip. When the hook that arms a central TX runs more than s_late_skip_us after the previous
 * (RX) event started, the TX can no longer start at +625: the scheduler would slide it one slot into the peripheral's
 * slot and break the TX/RX pattern (measured: a missed reply -> long RX -> late hook -> pushed TX -> missed POLL ->
 * 40 % no-reply links). Instead the TX is armed for the next central slot (k + 2, +1250 us): one POLL lost. */
static volatile uint16_t s_late_skip_us;
static volatile uint32_t s_late_skips;

IRAM_ATTR static void dtm_hop_event(void *context, void *descriptor)
{
	uint32_t item = ((volatile uint32_t *)descriptor)[22];
	/* inline lab_ram_span: this runs from the radio ISR path, keep it in IRAM */
	if ((item & 3u) || item < SOC_DRAM_LOW || item >= SOC_DRAM_HIGH - 56) { ++s_hop_bad; return; }
	const uint32_t prev = *(volatile uint32_t *)((uint8_t *)context + 24); /* previous start */
	if (s_hop_events == 0) { s_hop_ref = prev; s_hop_last_k = 0xFFFFFFFFu; }
	uint32_t k = (uint32_t)(prev - s_hop_ref + 312u) / 625u;
	const bool dup = (k == s_hop_last_k);
	if (dup) ++s_hop_dups;
	else if (s_hop_last_k != 0xFFFFFFFFu && k > s_hop_last_k + 1u) {
		++s_hop_jumps;
		if (s_page_state == 4 && s_jl_n < 32) {
			volatile uint32_t *j = s_jl[s_jl_n++];
			j[0] = k - s_conn_k0; j[1] = (k - s_hop_last_k) | ((uint32_t)s_hop_last_rx << 8) | ((uint32_t)s_conn_prov << 9);
			j[2] = (prev - s_hop_ref + 312u) % 625u;
			j[3] = r_ble_lll_timer_current_tick_get() - prev;
		}
	}
	if (s_page_state == 4 && !dup) {
		const uint32_t lat = (r_ble_lll_timer_current_tick_get() - prev) / 100u;
		s_lat_hist[s_hop_last_rx ? 1 : 0][lat < 15u ? lat : 15u]++;
	}
	bool late_skip = false;
	if (!dup && s_late_skip_us && s_page_on && s_page_state == 4 && s_hop_rx && (k & 1u) &&
	    r_ble_lll_timer_current_tick_get() - prev > s_late_skip_us) {
		k += 2u; late_skip = true; ++s_late_skips;
	}
	if (!dup && k < 48) s_hop_start[k] = prev;
	/* RX mode: event k (k=0 is the 2nd DTM event; the 1st, from schedEvent, is TX) is RX when k is even. */
	const bool rx = dup ? s_hop_last_rx : (s_hop_rx && !(k & 1));
	uint8_t f = s_hop_rx ? s_hop_f[rx ? 1 : 0] : s_hop_f[k & 1];
	if (dup) { f = s_hop_last_f; goto apply; }
	if (s_hop_rx && s_train_n) {
		const uint32_t p = (k + 1) >> 1;
		f = rx ? s_train_rx[train_idx(p)] : s_train_tx[train_idx(p)];
		if (s_page_on) {
			if (!rx) {
				/* TX event k: RX event k-1 (pair p-1) has just ended. */
				bool got = page_rx_fresh(descriptor);
				const bool got_saved = page_rx_saved();
				if (s_page_det_rxed == 1) { got = s_page_rxed_got; }
				else if (s_page_det_rxed == 2) { got = got_saved; }
				else if (s_page_det_rxed == 3) {
					got = false;
					if (s_page_poll_got) {
						const uint32_t age = r_ble_lll_timer_current_tick_get() - s_page_poll_tick;
						if (age < PAGE_POLL_MAX_AGE_US) { got = true; ++s_page_poll_used; } else ++s_page_poll_stale;
						s_page_poll_got = false;
					}
				}
				s_page_rxed_got = false;
				if (s_page_kick && s_page_state == 0 && p >= 1 && (p % s_page_kick) == 0) { got = true; ++s_page_kicks; }
				if (s_page_state == 2 && s_page_act_i < 8) {
					/* this hook follows the resp2 RX event: ctx+24 is its actual start */
					s_page_act[s_page_act_i][1] = (uint16_t)(*(volatile uint32_t *)((uint8_t *)context + 24) -
					                                         s_page_dbg[s_page_act_i][0]);
					s_page_act_i = 0xFF;
				}
				if (s_page_state == 2) {
					if (s_r2_adj) { s_itvl_adj = -(int32_t)s_page_r2late; s_r2_adj = false; }
					if (s_t3_i < 8) s_t3[s_t3_i][1] = *(volatile uint32_t *)((uint8_t *)context + 24) - s_t3[s_t3_i][0];
					if (s_page_r2skip && !got) { got = true; ++s_page_r2skips; }
					if (got) { if (s_page_resp2 < 8) s_page_resp2_k[s_page_resp2] = k; ++s_page_resp2; }
					else ++s_page_resp2_miss;
					s_page_state = 0;
					uint8_t *body = s_tx_body;
					if (got && s_conn_armed && s_conn_ready && s_conn_slots && body &&
					    (uint32_t)body >= SOC_DRAM_LOW && (uint32_t)body < SOC_DRAM_HIGH - 64) {
						/* this TX event is the first central slot: switch to our access code */
						s_conn_save_aa = s_dtm_raw_aa; s_conn_save_tail = s_dtm_raw_tail;
						s_dtm_raw_aa = s_conn_aa; s_dtm_raw_tail = s_conn_tail;
						conn_set_tail(body, s_conn_tail);
						for (unsigned i = 4 + CONN_POLL_BYTES; i < 64; ++i) body[i] = 0;
						s_rx_saved_last = 0;
						s_conn_n = 0; s_conn_k0 = k; ++s_conn_entries; s_conn_ready = false;
						s_conn_last_rx_n = 0; s_conn_end_req = false;
						s_conn_prov = s_page_r2skip;
						s_page_state = 4;
					}
				}
				if (s_page_state == 0 && s_page_shift && s_tx_body) conn_set_tail(s_tx_body, s_dtm_raw_tail);
				if (s_page_state != 4 && s_t3_i < 8 && s_t3[s_t3_i][1] && !s_t3[s_t3_i][2]) s_t3_i = 0xFF;
				if (s_page_state == 4) {
					s_conn_phase[((prev - s_hop_ref + 312u) % 625u) * 8u / 625u]++;
					uint8_t *body = s_tx_body;
					s_conn_n = (k - s_conn_k0) >> 1; /* central slot from absolute time */
					/* drain the controller's received-buffer queue: detector + log source, then hand buffers back */
					uint32_t rxed_data = 0;
					for (unsigned guard = 0; guard < 8; ++guard) {
						void *rxd = r_ble_lll_get_rxed_buffer(descriptor, NULL);
						if (!rxd) break;
						const uint32_t off = ((volatile uint32_t *)rxd)[2] & 0xFFFFFu;
						if (off && off < 0x7FFE0u) {
							const volatile uint32_t *d = (const volatile uint32_t *)(0x40800000u + off);
							if (((d[7] ^ s_dtm_raw_tail) & s_page_mask) == 0 && d[4] != s_conn_rxed_last) {
								s_conn_rxed_last = d[4];
								rxed_data = 0x40800000u + off;
							}
						}
						r_ble_lll_append_rx_buffer(descriptor, rxd);
						++s_conn_drained;
					}
					uint32_t now_data = 0, reply_data = 0;
					bool reply_null = false;
					if (s_conn_n < 32) {
						s_conn_buf_trace[s_conn_n][0] = s_rx_saved_data;
						s_conn_buf_trace[s_conn_n][1] = ls8_data((const volatile uint32_t *)descriptor);
					}
					if (s_conn_n > 0 && !got_saved && !rxed_data) now_data = conn_rx_now((const volatile uint32_t *)descriptor);
					if (s_conn_n > 0 && (rxed_data || got_saved || now_data)) {
						++s_conn_rx;
						if (rxed_data) ++s_conn_hit_rxed; else if (got_saved) ++s_conn_hit_saved; else ++s_conn_hit_now;
						if (rxed_data && !got_saved) { now_data = rxed_data; }
						if (s_conn_rx_first_n < 16) s_conn_rx_first[s_conn_rx_first_n++] = (uint16_t)(s_conn_n - 1);
						const uint32_t data = got_saved ? s_rx_saved_data : now_data;
						bool is_null = false;
						if (data) {
							const uint64_t h = conn_hdr_bits((const volatile uint8_t *)data + 28);
							const uint32_t c6 = ((4u * s_conn_n + 2u) >> 1) & 63u; /* peripheral slot of slot n-1 */
							const uint32_t m = conn_maj18(h);
							for (unsigned v = 0; v < 8; ++v) if (m == s_conn_null_mv[c6][v]) { is_null = true; break; }
							if (is_null) ++s_conn_nulls; else ++s_conn_others;
						}
						reply_data = data; reply_null = is_null;
						if (data && !is_null && !s_fifo_on) {
							const unsigned e = s_conn_log_count % CONN_LOG_N;
							const volatile uint8_t *srcb = (const volatile uint8_t *)data + 28;
							for (unsigned i = 0; i < CONN_LOG_BYTES; ++i) s_conn_log[e][i] = srcb[i];
							s_conn_log_slot[e] = s_conn_n - 1;
							s_conn_log_count = s_conn_log_count + 1u;
							if (s_conn_log_n < CONN_LOG_N) ++s_conn_log_n;
						}
					}
					if (reply_data) { s_conn_last_rx_n = s_conn_n; s_conn_prov = false; }
					const bool sup = s_conn_sup && s_conn_n > s_conn_last_rx_n + s_conn_sup;
					if (sup) ++s_conn_sup_ends;
					if (s_conn_end_req) ++s_conn_host_ends;
					const bool prov_end = s_conn_prov && s_conn_n >= PAGE_PROV_SLOTS;
					if (prov_end) ++s_conn_prov_ends;
					const bool end_now = sup || s_conn_end_req || prov_end;
					s_conn_end_req = false;
					if (s_conn_n < s_conn_slots && s_conn_n >= s_conn_fill) ++s_conn_underrun;
					if (!end_now && s_conn_n < s_conn_slots && s_conn_n < s_conn_fill && body) {
						const uint32_t clk = 4u * ((uint32_t)s_conn_n + 1u);
						const lmp_q_t *lq = NULL;
						for (unsigned qi = 0; qi < LMP_Q; ++qi)
							if (s_lmp_q[qi].used && s_conn_n >= s_lmp_q[qi].start &&
							    s_conn_n < (uint32_t)s_lmp_q[qi].start + s_lmp_q[qi].repeat) { lq = &s_lmp_q[qi]; break; }
						if (lq) {
							const uint8_t *src = lq->enc ? lq->pkt[s_conn_n - lq->start] : lq->pkt[(clk >> 1) & 63u];
							for (unsigned i = 0; i < LMP_PKT_BYTES; ++i) body[4 + i] = src[i];
							++s_lmp_sent;
						} else if (s_fifo_on) {
							fifo_slot(body + 4, s_conn_n, reply_data, reply_null);
						} else {
							const uint8_t *src = s_conn_poll[(clk >> 1) & 63u];
							for (unsigned i = 0; i < CONN_POLL_BYTES; ++i) body[4 + i] = src[i];
							for (unsigned i = 4 + CONN_POLL_BYTES; i < 4 + LMP_PKT_BYTES; ++i) body[i] = 0;
						}
						f = s_conn_f_tx[s_conn_n % CONN_RING];
						s_cap_now = s_conn_len; s_cap_override = true;
						++s_conn_tx;
					} else {
						/* end of the connection test: back to paging with the DAC. A provisional (r2skip) entry that never
						 * got a reply sent nothing from the FIFO: keep it for the next attempt. */
						if (!s_conn_prov) s_fifo_head = s_fifo_tail;
						s_conn_prov = false;
						s_tx_inflight = 0; s_rx_arqn = 0; s_rxv_state = 0;
						s_rx_acked_seqn = 0xFF; s_tx_seqn = 1; s_stream_on = false; s_mask_reset = true;
						s_dtm_raw_aa = s_conn_save_aa; s_dtm_raw_tail = s_conn_save_tail;
						if (body) conn_set_tail(body, s_conn_save_tail);
						s_rx_saved_last = 0;
						s_page_state = 0;
						s_conn_refill = true; /* conn_fill_task rebuilds slots 0.. for the next connection */
					}
				} else if (s_page_state == 0 && got && p >= 1) {
					/* 1.4.245: X from the frequency the radio actually listened on (the RX event that just ended):
					 * every X has its own response frequency, so this does not depend on the event counter, which
					 * slips against the air grid. Falls back to the counter when the frequency is not in the train. */
					uint8_t xc = train_x(train_idx(p - 1)), xf = 0xFF;
					if (s_hop_last_rx)
						for (unsigned ti = 0; ti < s_train_n; ++ti)
							if (s_train_rx[ti] == s_hop_last_f) { xf = train_x(ti); break; }
					if (xf < 32) { if (xf == xc) ++s_page_xf_agree; else ++s_page_xf_differ; }
					s_page_x = s_page_xfix < 32 ? s_page_xfix : (xf < 32 ? xf : xc);
					++s_page_resp1;
					uint8_t *body = s_tx_body;
					if (body && (uint32_t)body >= SOC_DRAM_LOW && (uint32_t)body < SOC_DRAM_HIGH - 64) {
						if (s_page_shift) {
							const uint8_t *src = s_page_fhs_full[s_page_x];
							body[0] = 0; body[1] = PAGE_SHIFT_LEN;  /* PDU type 0, no CTE; our length */
							for (unsigned i = 0; i < PAGE_SHIFT_LEN; ++i) body[2 + i] = src[i];
							s_cap_now = PAGE_SHIFT_LEN; s_cap_override = true;
							s_itvl_adj -= (int32_t)PAGE_SHIFT_US;
							++s_page_shift_sent;
						} else {
							const uint8_t *src = s_page_fhs[s_page_x];
							for (unsigned i = 0; i < PAGE_FHS_BYTES; ++i) body[4 + i] = src[i];
							s_cap_now = s_page_tx_cap; s_cap_override = true;
						}
						f = s_page_fhs_f[s_page_x];
						++s_page_fhs_sent;
						s_page_state = 3;
						s_tr_pending = true;
						s_page_tx_now = true;
						s_page_tx_ctx = context;
						if (s_page_dbg_n < 8) {
							volatile uint32_t *r = s_page_dbg[s_page_dbg_n];
							r[0] = s_page_last_stamp;
							r[1] = r_ble_lll_timer_current_tick_get();
							r[2] = *(volatile uint32_t *)((uint8_t *)context + 24);
							s_page_dbg_pending = true;
							s_page_act[s_page_dbg_n][0] = s_page_act[s_page_dbg_n][1] = 0xFFFF;
							s_page_act_i = s_page_dbg_n;
						}
					} else {
						++s_page_bad;
					}
				}
			} else if (s_page_state == 4) {
				if (s_t3_i < 8) {  /* this hook follows the first central TX: ctx+24 is its actual start */
					s_t3[s_t3_i][2] = *(volatile uint32_t *)((uint8_t *)context + 24) - s_t3[s_t3_i][0];
					s_t3_i = 0xFF;
				}
				const uint32_t n = (k - s_conn_k0 - 1u) >> 1; /* the central slot this RX follows */
				if (n < s_conn_slots && n < s_conn_fill) { f = s_conn_f_rx[n % CONN_RING]; s_conn_n = n + 1u; }
			} else if (s_page_state == 3) {
				/* this hook follows the FHS TX event: ctx+24 is its actual start */
				if (s_page_act_i < 8)
					s_page_act[s_page_act_i][0] = (uint16_t)(*(volatile uint32_t *)((uint8_t *)context + 24) -
					                                         s_page_dbg[s_page_act_i][0]);
				f = s_page_resp2_f[s_page_x];
				s_page_state = 2;
				if (s_page_r2skip && s_page_r2late) { s_itvl_adj = s_page_r2late; s_r2_adj = true; }
				if (s_page_shift) s_itvl_adj += (int32_t)PAGE_SHIFT_US;  /* the FHS event started that much early */
				s_hop_ref = prev + (s_page_shift ? PAGE_SHIFT_US : 0u) - k * 625u;  /* 1.4.249: grid starts at the FHS */
				++s_reanchors;
				if (s_t3_n < 8) {
					s_t3[s_t3_n][0] = *(volatile uint32_t *)((uint8_t *)context + 24);
					s_t3[s_t3_n][1] = s_t3[s_t3_n][2] = 0;
					s_t3_i = s_t3_n++;
				}
			}
		}
	}
apply:
	if (s_mod_tx) {
		volatile uint32_t *mr = (volatile uint32_t *)MOD_REG;
		if (s_page_state != 4) {
			if (*mr != s_mod_orig) *mr = s_mod_orig;
		} else if (!rx) {
			*mr = s_mod_tx;  /* the reply in the RX event before has ended */
		} else {
			const uint32_t start = *(volatile uint32_t *)((uint8_t *)context + 24);  /* the TX event still on air */
			const uint32_t t0 = r_ble_lll_timer_current_tick_get();
			uint32_t now = t0;
			while ((int32_t)(now - (start + s_mod_tx_us)) < 0 && now - t0 < 250u) now = r_ble_lll_timer_current_tick_get();
			if (now != t0) { ++s_mod_waits; if (now - t0 > s_mod_wait_max) s_mod_wait_max = now - t0; }
			*mr = s_mod_orig;
		}
	}
	if (f <= 78) {
		volatile uint32_t *w = (volatile uint32_t *)item;
		w[5] = (w[5] & 0xFFFF80FFu) | ((uint32_t)f << 8);
	}
	if (s_hop_rx) {
		/* ble_lll_scan.c.o scan_restart +0x90/+0x2c4: link-state+44 = RX window length in us from the item
		 * start (0x3FFFFFFF = continuous); DTM RX writes 0 and then listens until a packet arrives. */
		volatile uint32_t *ls = (volatile uint32_t *)descriptor;
		if (rx) { s_rx_ls8_seen = ls[2]; s_rx_saved_data = ls8_data(ls); }
		const bool conn_rx = rx && s_page_on && s_page_state == 4;
		const uint8_t rxm = (conn_rx && s_conn_rxmax) ? s_conn_rxmax : s_rx_max;
		if (rx && rxm) ls[2] = (ls[2] & ~0x0FF00000u) | ((uint32_t)rxm << 20);
		if (rx && s_hop_ls44_value) {
			if (!s_hop_ls44_saved) { s_hop_ls44 = ls[11]; s_hop_ls44_saved = true; }
			/* s_page_state was set to 2 above when this RX is the resp2 RX after an FHS */
			ls[11] = (conn_rx && s_conn_ls44) ? s_conn_ls44 :
			         (s_page_on && s_page_state == 2 && s_page_r2_ls44) ? s_page_r2_ls44 : s_hop_ls44_value;
		} else if (!rx && s_hop_ls44_saved) {
			ls[11] = s_hop_ls44;
		}
	}
	if (s_hop_itvl_us) {
		uint32_t itvl = s_hop_itvl_us;
		if (s_hop_rx) itvl = rx ? itvl - s_hop_early + s_hop_late : itvl + s_hop_early - s_hop_late;
		itvl = (uint32_t)((int32_t)itvl + s_itvl_adj);
		if (late_skip) itvl += 1250u;
		s_itvl_adj = 0;
		*(volatile uint32_t *)((uint8_t *)context + 4) = itvl; /* interval ticks (1 tick = 1 us) */
		*((volatile uint8_t *)context + 1) = 0;                 /* sub-tick remainder */
	}
	if (s_page_dbg_pending) {
		s_page_dbg[s_page_dbg_n][3] = *(volatile uint32_t *)((uint8_t *)context + 4);
		s_page_dbg_pending = false;
		++s_page_dbg_n;
	}
	s_hop_ctx = context;
	s_hop_rx_now = rx;
	s_hop_events = k + 1;
	s_hop_last_k = k; s_hop_last_f = f; s_hop_last_rx = rx;
	if (s_tr_stage != 0xFF && ++s_tr_stage >= 3) { s_tr_stage = 0xFF; ++s_tr_row; }
	if (s_tr_stage == 0xFF && s_tr_pending) { s_tr_pending = false; if (s_tr_row < 3) s_tr_stage = 0; }
	if (s_tr_stage != 0xFF) {
		volatile uint32_t *r = s_tr[s_tr_row][s_tr_stage];
		r[0] = r_ble_lll_timer_current_tick_get(); r[1] = item;
		r[2] = f | ((uint32_t)rx << 8) | ((k & 0xFFFFu) << 16);
		r[3] = (s_dtm_irqs & 0xFFFFu) << 16; r[4] = r[5] = 0;
	}
}

/* ble_lll_sched.c.o: r_ble_lll_sched_run() arms the hardware sequencer on the item whose address the caller
 * just wrote to 0x600A18FC (dtm rescheduleNextEvent.part.0 +0x9e). For a flagged RX event, turn the TX item
 * into an RX item exactly as DTM's own RX path does (item+2: clear 0x50, set 0x40; item+28 = 255) and end
 * the window at start + s_hop_window (item+48 = ctx+24 + window, same absolute ticks as the original). */
extern void orig_r_ble_lll_sched_run(void);
IRAM_ATTR void r_ble_lll_sched_run(void)
{
	if (s_tr_stage != 0xFF) {
		volatile uint32_t *r = s_tr[s_tr_row][s_tr_stage];
		if ((r[3] & 0xFFFFu) == 0) {
			const uint32_t it = SOC_DRAM_LOW | (*(volatile uint32_t *)0x600A18FCu & 0xFFFFFu);
			r[4] = it;
			if (!(it & 3u) && it < SOC_DRAM_HIGH - 56)
				r[5] = ((((volatile uint32_t *)it)[5] >> 8) & 0x7Fu) | ((uint32_t)((volatile uint8_t *)it)[2] << 8) |
				       ((r_ble_lll_timer_current_tick_get() & 0xFFFFu) << 16);
		}
		if ((r[3] & 0xFFFFu) < 0xFFFFu) ++r[3];
	}
	/* Experimental TX deadline. dtm_hal rescheduleNextEvent.part.0 +0x70..0x86
	 * writes item+48 = start + tx_time + 1. Test whether this can remove the
	 * trailing BLE padding/CRC after the BR FHS; default 0 preserves native timing. */
	if (s_dtm_capture && s_dtm_raw_mode == 2 && (s_page_tx_now || s_page_force_x < 32)) {
		s_page_tx_now = false;
		const uint32_t item = SOC_DRAM_LOW | (*(volatile uint32_t *)0x600A18FCu & 0xFFFFFu);
		if (s_page_tx_end_us && s_page_tx_ctx && !(item & 3u) && item < SOC_DRAM_HIGH - 56)
			((volatile uint32_t *)item)[12] = *(volatile uint32_t *)((uint8_t *)s_page_tx_ctx + 24) + s_page_tx_end_us;
	}
	if (s_hop_on && s_hop_armed && !s_hop_rx_now && s_hop_ctx) {
		const uint32_t item = SOC_DRAM_LOW | (*(volatile uint32_t *)0x600A18FCu & 0xFFFFFu);
		if (!(item & 3u) && item < SOC_DRAM_HIGH - 56) {
			const uint32_t start = *(volatile uint32_t *)((uint8_t *)s_hop_ctx + 24);
			s_lead_seen = start - ((volatile uint32_t *)item)[11];
			if (s_tx_lead) ((volatile uint32_t *)item)[11] = start - s_tx_lead;
		}
	}
	if (s_hop_rx_now) {
		s_hop_rx_now = false;
		const uint32_t item = SOC_DRAM_LOW | (*(volatile uint32_t *)0x600A18FCu & 0xFFFFFu);
		if (!(item & 3u) && item < SOC_DRAM_HIGH - 56 && s_hop_ctx) {
			volatile uint8_t *b = (volatile uint8_t *)item;
			b[2] = (uint8_t)((b[2] & ~0x50u) | 0x40u);
			((volatile uint32_t *)item)[7] = 255;
			/* item+48 = start + s_hop_end (scan_restart +0x9c uses start + 1; DTM RX start + 1000) */
			((volatile uint32_t *)item)[12] = *(volatile uint32_t *)((uint8_t *)s_hop_ctx + 24) + s_hop_end;
			++s_hop_rx_events;
		} else {
			++s_hop_run_bad;
		}
	}
	orig_r_ble_lll_sched_run();
}

IRAM_ATTR void dtm_hal_rstLst(void *context, void *descriptor)
{
	orig_dtm_hal_rstLst(context, descriptor);
	if (s_dtm_capture && s_hop_on && s_hop_armed) dtm_hop_event(context, descriptor);
	if (s_dtm_capture && s_dtm_raw_mode) ((volatile uint32_t *)descriptor)[12] = s_dtm_raw_aa;
	if (s_dtm_capture && s_dtm_raw_mode == 2) {
		/* conn_reset_link_state +0x78..0x8c writes max TX octets(+MIC)
		 * in ls+0 bits20..27; CRC init is low24 at ls+36. Preserve
		 * pointers/flags. Whether a short cap truncates DTM is measured. */
		volatile uint32_t *ls = descriptor;
		const uint8_t cap = s_page_force_x < 32 ? s_page_tx_cap : (s_cap_override ? s_cap_now : s_dtm_tx_cap);
		s_cap_override = false;
		ls[0] = (ls[0] & ~0x0FF00000u) | ((uint32_t)cap << 20);
		ls[9] = (ls[9] & 0xFF000000u) | s_dtm_crc_init;
	}
	if (s_dtm_capture) {
		s_dtm_state = descriptor;
		for (unsigned i = 0; i < 16; ++i) s_dtm_words[i] = ((volatile uint32_t *)descriptor)[i];
		++s_dtm_resets;
	}
}
/* DTM rxProcess is inlined into recycleSchItem; hook its actual buffer
 * supplier instead. ble_lll.c.o get_rxed_buffer returns an RX descriptor,
 * DTM recycleSchItem +0xC2 reads descriptor+8 then status+12 before CRC check. */
IRAM_ATTR void *r_ble_lll_get_rxed_buffer(void *state, void *current)
{
	void *rx = orig_r_ble_lll_get_rxed_buffer(state, current);
	if (s_page_on && s_dtm_capture && state == s_dtm_state && rx) {
		const uint32_t off = ((volatile uint32_t *)rx)[2] & 0xFFFFFu;
		++s_page_rxed_calls;
		if (off && off < 0x7FFE0u) {
			const volatile uint32_t *d = (const volatile uint32_t *)(0x40800000u + off);
			const uint32_t stamp = d[4], word = d[7];
			if (word == s_dtm_raw_tail && stamp != s_page_rxed_last) {
				s_page_rxed_last = stamp;
				s_page_rxed_got = true;
				if (s_page_rxed_hits < 8) {
					s_page_rxed_log[s_page_rxed_hits][0] = r_ble_lll_timer_current_tick_get();
					s_page_rxed_log[s_page_rxed_hits][1] = stamp;
				}
				++s_page_rxed_hits;
			}
		}
	}
	if (s_dtm_capture && state == s_dtm_state && rx) {
		uint32_t offset = ((volatile uint32_t *)rx)[2] & 0xFFFFFu;
		if (offset) {
			s_dtm_status = *(volatile uint32_t *)(0x40800000u + offset + 12u);
			const volatile uint8_t *h = (const volatile uint8_t *)(0x40800000u + offset + 28u);
			s_dtm_header = h[0] | ((uint16_t)h[1] << 8);
			++s_dtm_rx;
		}
	}
	return rx;
}

#define H4_CMD 0x01
#define H4_ACL 0x02
#define H4_EVT 0x04

/* Peek/poke window: C6 peripheral space only (a bad RAM/ROM address would panic, and 3 panics roll back). */
#define PEEK_LO 0x60000000u
#define PEEK_HI 0x600FFFFCu

#define HOP_MAX_US 2000000u

typedef struct {
	uint8_t len;
	uint8_t data[255]; /* 1.4.246: full HCI parameter length (was 64) */
} lab_cmd_t;

static QueueHandle_t s_queue;
static volatile bool s_br_mode;
static volatile bool s_busy;
static bool s_wifi_was_started;
static bool s_quiet;
static bool s_quiet_restore_wifi;
static int64_t s_last_cmd_us;
static uint8_t s_tone_fn = FN_NONE;

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

/* Read-only diagnostic bounds: IDF esp32c6 soc.h SRAM limits. Avoid a
 * guessed pointer or stale/partial DMA pointer becoming an access fault. */
static bool lab_ram_span(uint32_t address, unsigned length)
{
	return !(address & 3u) && address >= SOC_DRAM_LOW && address < SOC_DRAM_HIGH &&
		length <= SOC_DRAM_HIGH - address;
}

static void send_cmd_complete_raw(uint16_t op, uint8_t status_only)
{
	uint8_t ev[7] = { H4_EVT, 0x0E, 4, 1, (uint8_t)op, (uint8_t)(op >> 8), status_only };
	slave_bt_send_to_host(ev, sizeof(ev));
}

/* Command Complete for 0xFFE0: status, LAB_VERSION, sub, data. */
static void reply(uint8_t sub, uint8_t status, const uint8_t *data, uint8_t n)
{
	uint8_t ev[6 + 3 + 240];
	if (n > 240) n = 240;
	ev[0] = H4_EVT;
	ev[1] = 0x0E;
	ev[2] = (uint8_t)(3 + 3 + n);
	ev[3] = 1;
	ev[4] = (uint8_t)RADIO_LAB_OPCODE;
	ev[5] = (uint8_t)(RADIO_LAB_OPCODE >> 8);
	ev[6] = status;
	ev[7] = LAB_VERSION;
	ev[8] = sub;
	if (n) memcpy(&ev[9], data, n);
	slave_bt_send_to_host(ev, (uint16_t)(9 + n));
}

/* Vendor event 0xFF: 'BRL1', sub, status, data. */
static void event(uint8_t sub, uint8_t status, const uint8_t *data, uint8_t n)
{
	uint8_t ev[3 + 6 + 240];
	if (n > 240) n = 240;
	ev[0] = H4_EVT;
	ev[1] = 0xFF;
	ev[2] = (uint8_t)(6 + n);
	memcpy(&ev[3], k_magic, 4);
	ev[7] = sub;
	ev[8] = status;
	if (n) memcpy(&ev[9], data, n);
	slave_bt_send_to_host(ev, (uint16_t)(9 + n));
}

/* esp_phy_ble_tx/rx take the BLE channel INDEX (measured 2026-11-09: index 19 -> 2444 MHz), not (MHz-2402)/2.
 * Data channels 0..10 = 2404..2424, 11..36 = 2428..2478; advertising 37 = 2402, 38 = 2426, 39 = 2480. -1 = odd MHz. */
static int ble_index(int mhz)
{
	if (mhz == 2402) return 37;
	if (mhz == 2426) return 38;
	if (mhz == 2480) return 39;
	if (mhz < 2404 || mhz > 2478 || (mhz & 1)) return -1;
	return mhz <= 2424 ? (mhz - 2404) / 2 : (mhz - 2428) / 2 + 11;
}

static int set_freq(uint8_t fn, int mhz)
{
	switch (fn) {
	case 0: return phy_force_freq_set(1, mhz, 0, 0);
	case 3: return bt_rx_force(1, mhz, 0, 0);
	default: return fn < N_FNS ? k_fns[fn](mhz, 0, 0, 0) : 0;
	}
}

static void rf_off(void)
{
	esp_phy_bt_tx_tone(0, 0, 0);
	esp_phy_test_start_stop(0);
	phy_force_freq_set(0, 0, 0, 0);
	s_tone_fn = FN_NONE;
}

static uint8_t enter_br(uint8_t *wifi_was_started)
{
	if (s_br_mode) {
		*wifi_was_started = s_wifi_was_started;
		return RL_OK;
	}
	if (fw_guard_in_trial()) return RL_ERR_TRIAL;
	s_wifi_was_started = esp_wifi_stop() == ESP_OK;
	esp_err_t err = esp_bt_controller_disable();
	ESP_LOGW(TAG, "enter BR: wifi_was_started=%d bt_disable=%s", s_wifi_was_started, esp_err_to_name(err));
	esp_wifi_power_domain_on();
	esp_phy_rftest_config(1);
	esp_phy_rftest_init();
	rf_off();
	s_br_mode = true;
	*wifi_was_started = s_wifi_was_started;
	return RL_OK;
}

static uint8_t exit_br(void)
{
	s_scan_profile = 0;
	s_dtm_capture = false;
	s_dtm_awake = false;
	s_dtm_native_clock = false;
	s_dtm_raw_mode = 0;
	s_page_force_x = 0xFF;
	s_page_xfix = 0xFF; s_page_act_i = 0xFF;
	s_page_kick = 0; s_page_r2_ls44 = 0; s_page_det_rxed = 0; s_page_rxed_got = false;
	s_page_r2skip = false; s_conn_prov = false; s_late_skip_us = 0; s_page_r2late = 0; s_itvl_adj = 0; s_r2_adj = false; s_page_shift = false; if (s_mod_tx) { *(volatile uint32_t *)MOD_REG = s_mod_orig; s_mod_tx = 0; }
	s_tx_lead = 0; s_rx_max = 0;
	s_page_tx_end_us = 0;
	s_page_tx_now = false;
	s_page_tx_ctx = NULL;
	s_hop_on = false;
	s_hop_rx = s_hop_rx_now = s_hop_armed = false;
	s_scan_aa_enabled = false; /* restore normal AA on the next scan start, including non-BR lab release */
	if (s_quiet) {
		esp_err_t err = s_quiet_restore_wifi ? esp_wifi_start() : ESP_OK;
		if (err != ESP_OK) return RL_ERR_INTERNAL;
		s_quiet = s_quiet_restore_wifi = false;
	}
	if (!s_br_mode) return RL_OK;
	rf_off();
	esp_phy_rftest_config(0);
	esp_err_t err = esp_bt_controller_enable(ESP_BT_MODE_BLE);
	esp_err_t werr = s_wifi_was_started ? esp_wifi_start() : ESP_OK;
	ESP_LOGW(TAG, "exit BR: bt_enable=%s wifi_start=%s", esp_err_to_name(err), esp_err_to_name(werr));
	s_br_mode = false;
	return err == ESP_OK && werr == ESP_OK ? RL_OK : RL_ERR_INTERNAL;
}

static void cmd_tone(const uint8_t *p, uint8_t n)
{
	if (n < 8 || (p[0] >= N_FNS && p[0] != FN_NONE)) { reply(RL_TONE, RL_ERR_PARAM, NULL, 0); return; }
	const uint8_t fn = p[0];
	const int mhz = rd16(p + 1);
	const uint8_t power = p[3];
	const uint32_t ms = rd32(p + 4);
	if (fn == FN_NONE && ble_index(mhz) < 0) { reply(RL_TONE, RL_ERR_PARAM, NULL, 0); return; }
	rf_off();
	esp_phy_bt_tx_tone(1, fn == FN_NONE ? (uint32_t)ble_index(mhz) : 37u, power);
	if (fn != FN_NONE) set_freq(fn, mhz);
	s_tone_fn = fn;
	if (!ms) { reply(RL_TONE, RL_OK, NULL, 0); return; }
	reply(RL_TONE, RL_STARTED, NULL, 0);
	vTaskDelay(pdMS_TO_TICKS(ms));
	rf_off();
	event(RL_TONE, RL_OK, NULL, 0);
}

static void cmd_hop(const uint8_t *p, uint8_t n)
{
	if (n < 9 || p[0] >= N_FNS) { reply(RL_HOP, RL_ERR_PARAM, NULL, 0); return; }
	const uint8_t fn = p[0];
	const int f1 = rd16(p + 1), f2 = rd16(p + 3);
	const uint32_t period = rd16(p + 5), count = rd16(p + 7);
	if (!period || !count || (uint64_t)period * count > HOP_MAX_US) { reply(RL_HOP, RL_ERR_PARAM, NULL, 0); return; }
	reply(RL_HOP, RL_STARTED, NULL, 0);
	vTaskDelay(pdMS_TO_TICKS(20)); /* let the reply leave before the busy loop */
	rf_off();
	esp_phy_bt_tx_tone(1, 0, 0);
	uint32_t mn = UINT32_MAX, mx = 0, late = 0;
	uint64_t sum = 0;
	const int64_t t0 = esp_timer_get_time();
	for (uint32_t i = 0; i < count; i++) {
		const int64_t due = t0 + (int64_t)i * period;
		while (esp_timer_get_time() < due) {
		}
		const int64_t a = esp_timer_get_time();
		if (a - due > 5) late++;
		set_freq(fn, (i & 1) ? f2 : f1);
		const uint32_t d = (uint32_t)(esp_timer_get_time() - a);
		sum += d;
		if (d < mn) mn = d;
		if (d > mx) mx = d;
	}
	rf_off();
	uint8_t out[10];
	wr16(out, (uint16_t)count);
	wr16(out + 2, (uint16_t)(mn > 0xFFFF ? 0xFFFF : mn));
	wr16(out + 4, (uint16_t)(mx > 0xFFFF ? 0xFFFF : mx));
	wr16(out + 6, (uint16_t)(sum / count));
	wr16(out + 8, (uint16_t)late);
	event(RL_HOP, RL_OK, out, sizeof(out));
}

/* esp_phy_ble_rx() is a receive loop (ble_rx: while (ble_rx_a_frame(...)) {}) that only ends when
 * esp_phy_test_start_stop(0) is called from another context; it then stores the counters read by
 * esp_phy_get_rx_result(). So it runs in a low-priority worker task. (1.4.190/191 called it inline and hung.) */
static volatile bool s_rx_done;
static uint32_t s_rx_args[2];

static void rx_worker(void *arg)
{
	(void)arg;
	esp_phy_ble_rx(s_rx_args[0], s_rx_args[1], PHY_BLE_RATE_1M);
	s_rx_done = true;
	vTaskDelete(NULL);
}

static void cmd_rx_count(const uint8_t *p, uint8_t n)
{
	if (n < 11 || (p[0] >= N_FNS && p[0] != FN_NONE)) { reply(RL_RX_COUNT, RL_ERR_PARAM, NULL, 0); return; }
	const uint8_t fn = p[0];
	const int mhz = rd16(p + 1);
	const uint32_t aa = rd32(p + 3), ms = rd32(p + 7);
	if (fn == FN_NONE && ble_index(mhz) < 0) { reply(RL_RX_COUNT, RL_ERR_PARAM, NULL, 0); return; }
	reply(RL_RX_COUNT, RL_STARTED, NULL, 0);
	rf_off();
	esp_phy_test_start_stop(3);
	s_rx_args[0] = fn == FN_NONE ? (uint32_t)ble_index(mhz) : 37u;
	s_rx_args[1] = aa;
	s_rx_done = false;
	if (xTaskCreate(rx_worker, "lab_rx", 4096, NULL, 1, NULL) != pdPASS) {
		event(RL_RX_COUNT, RL_ERR_INTERNAL, NULL, 0);
		return;
	}
	vTaskDelay(pdMS_TO_TICKS(30)); /* let ble_rx_init tune and arm the receiver, then override the frequency */
	if (fn != FN_NONE) set_freq(fn, mhz);
	vTaskDelay(pdMS_TO_TICKS(ms));
	const int rx_freq = phy_get_rx_freq(0, 0, 0, 0);
	esp_phy_test_start_stop(0); /* ends the receive loop */
	for (int i = 0; i < 100 && !s_rx_done; i++) vTaskDelay(pdMS_TO_TICKS(10));
	esp_phy_rx_result_t r;
	memset(&r, 0, sizeof(r));
	if (s_rx_done) esp_phy_get_rx_result(&r);
	rf_off();
	uint8_t out[14];
	wr32(out, r.phy_rx_total_count);
	wr32(out + 4, r.phy_rx_correct_count);
	out[8] = (uint8_t)r.phy_rx_rssi;
	wr32(out + 9, (uint32_t)rx_freq);
	out[13] = s_rx_done;
	event(RL_RX_COUNT, s_rx_done ? RL_OK : RL_ERR_INTERNAL, out, sizeof(out));
}

static void cmd_ble_tx(const uint8_t *p, uint8_t n)
{
	if (n < 12 || (p[0] >= N_FNS && p[0] != FN_NONE)) { reply(RL_BLE_TX, RL_ERR_PARAM, NULL, 0); return; }
	const uint8_t fn = p[0];
	const int mhz = rd16(p + 1);
	const uint32_t syncw = rd32(p + 3);
	const uint8_t len = p[7], type = p[8], power = p[9];
	const uint16_t num = rd16(p + 10);
	if (!num || (fn == FN_NONE && ((mhz - 2402) % 2 || mhz < 2402 || mhz > 2480))) { reply(RL_BLE_TX, RL_ERR_PARAM, NULL, 0); return; }
	reply(RL_BLE_TX, RL_STARTED, NULL, 0);
	rf_off();
	esp_phy_test_start_stop(3);
	esp_phy_ble_tx(power, fn == FN_NONE ? (uint32_t)ble_index(mhz) : 37u, len, (esp_phy_ble_type_t)type, syncw,
		       PHY_BLE_RATE_1M, num);
	if (fn != FN_NONE) set_freq(fn, mhz);
	/* No completion signal from the PHY: wait for the worst case (packet + 625 us gap). */
	vTaskDelay(pdMS_TO_TICKS(1 + (uint32_t)num * (80u + 8u * len + 700u) / 1000u));
	rf_off();
	event(RL_BLE_TX, RL_OK, NULL, 0);
}

/* Raw ID RX counter: read-only sampling of the current DMA candidate.
 * Source: current_rx_info_get maps ls+8 to descriptor-4; normal scan RX reads
 * data+16 timestamp and data+28 PDU. Expected word is supplied in RAM byte
 * order after hardware whitening, compared as all32bits (no tolerance).
 * Combined with configured lower32 AA this verifies the full test sync word.
 * Does not turn a partial/error buffer into a valid BLE packet. */
static volatile bool s_raw_running;
static uint16_t s_raw_ms;
static uint32_t s_raw_expected;
static uint8_t s_raw_policy;
static uint8_t s_raw_result[224];
static uint8_t s_raw_result_len;
/* rawmatch capture (G5 on-C6 decode): for the first RAW_CAP_MAX matching packets, wait until s_cap_delay_us after
 * the packet was first observed (so the DMA has written the whole packet), then copy s_cap_len bytes from the RX
 * buffer's first byte after the access address (data+28, the word rawmatch compares). */
#define RAW_CAP_MAX 4
#define RAW_CAP_BYTES 64
static uint8_t s_cap_len;
static uint16_t s_cap_delay_us;
static uint8_t s_cap_count;
static uint32_t s_cap_stamp[RAW_CAP_MAX];
static uint8_t s_cap[RAW_CAP_MAX][RAW_CAP_BYTES];
static void raw_match_worker(void *unused)
{
	(void)unused;
	uint32_t polls = 0, fresh = 0, matches = 0, different = 0, last_stamp = 0, last_word = 0;
	bool seen = false;
	uint32_t recent[64] = {0};
	unsigned recent_count = 0, recent_next = 0;
	uint32_t stamps[48];
	unsigned stamp_count = 0;
	uint32_t pending_stamp = 0;
	int64_t pending_since = 0;
	const int64_t start = esp_timer_get_time();
	int64_t next_yield = start + 100000;
	while ((s_scan_aa_enabled || s_dtm_raw_mode) && esp_timer_get_time() - start < (int64_t)s_raw_ms * 1000) {
		++polls;
		uint32_t ls = (uint32_t)(s_raw_policy >= 2 ? s_dtm_state : s_scan_state);
		if (lab_ram_span(ls, 120)) {
			uint32_t offset = ((volatile uint32_t *)ls)[2] & 0xFFFFFu;
			uint32_t desc = offset >= 4 ? (SOC_DRAM_LOW | offset) - 4u : 0;
			if (lab_ram_span(desc, 12)) {
				offset = ((volatile uint32_t *)desc)[2] & 0xFFFFFu;
				uint32_t data = offset ? SOC_DRAM_LOW | offset : 0;
				if (lab_ram_span(data, 32)) {
					const volatile uint32_t *d = (const volatile uint32_t *)data;
					uint32_t stamp = d[4], word = d[7], status = d[3];
					if (stamp == d[4] && word == d[7] &&
					    ((s_raw_policy & 1) || (status & 0xFFFFFFu) != 0xFFFFFFu)) {
						if (!seen) {
							last_stamp = stamp; seen = true; recent[0] = stamp;
							recent_count = recent_next = 1;
						} else if (stamp != last_stamp) {
							/* Read-only alternative: ID remainder is 32us at1M.
							 * Wait100us after observing its timestamp so data can
							 * settle even when completion status stays unwritten.
							 * Negative tail/AA controls must validate this policy. */
							if ((s_raw_policy & 1) && pending_stamp != stamp) {
								pending_stamp = stamp; pending_since = esp_timer_get_time();
							}
							if (!(s_raw_policy & 1) || esp_timer_get_time()-pending_since >= 100) {
								bool duplicate = false;
								last_stamp = stamp;
								for (unsigned j = 0; j < recent_count; ++j)
									if (recent[j] == stamp) duplicate = true;
								if (!duplicate) {
									recent[recent_next] = stamp; recent_next = (recent_next+1) & 63u;
									if (recent_count < 64) ++recent_count;
									last_word = word; ++fresh;
									if (stamp_count < 48) stamps[stamp_count++] = stamp;
									if (word == s_raw_expected) {
										++matches;
										if (s_page_on && s_page_det_rxed == 3) {
											s_page_poll_tick = r_ble_lll_timer_current_tick_get();
											s_page_poll_got = true; ++s_page_poll_hits;
										}
										if (s_cap_len && s_cap_count < RAW_CAP_MAX) {
											const int64_t seen_at = (s_raw_policy & 1) ? pending_since : esp_timer_get_time();
											while (esp_timer_get_time() - seen_at < s_cap_delay_us) {}
											const volatile uint8_t *src = (const volatile uint8_t *)data + 28;
											for (unsigned j = 0; j < s_cap_len; ++j) s_cap[s_cap_count][j] = src[j];
											s_cap_stamp[s_cap_count++] = stamp;
										}
									} else {
										++different;
									}
								}
							}
						}
					}
				}
			}
		}
		if (esp_timer_get_time() >= next_yield) {
			vTaskDelay(1); /* service SDIO/idle; ~1% intentional observation gaps */
			next_yield = esp_timer_get_time() + 100000;
		}
	}
	uint8_t *out = s_raw_result;
	wr32(out, polls); wr32(out+4, fresh); wr32(out+8, matches); wr32(out+12, different);
	wr32(out+16, last_stamp); wr32(out+20, last_word); wr32(out+24, s_raw_policy >= 2 ? s_dtm_raw_aa : s_scan_last_aa);
	wr32(out+28, (uint32_t)(esp_timer_get_time()-start));
	for (unsigned i = 0; i < stamp_count; ++i) wr32(out+32+4*i, stamps[i]);
	s_raw_result_len = 32+4*stamp_count;
	s_raw_running = false;
	event(RL_RAW_MATCH, RL_OK, out, s_raw_result_len);
	vTaskDelete(NULL);
}

static void handle(const uint8_t *p, uint8_t plen)
{
	/* p: parameters of 0xFFE0 = magic(4) sub(1) args */
	const uint8_t sub = p[4];
	const uint8_t *a = p + 5;
	const uint8_t n = (uint8_t)(plen - 5);
	uint8_t out[240];
	s_last_cmd_us = esp_timer_get_time();

	const bool needs_br = !(sub == RL_PING || sub == RL_ENTER_BR || sub == RL_EXIT_BR || sub == RL_REBOOT ||
				sub == RL_FORCE || sub == RL_CHANMAP || sub == RL_SCAN_AA || sub == RL_IRQ_STATS || sub == RL_SCAN_FLAGS || sub == RL_DTM_STATS || sub == RL_SCAN_RAW || sub == RL_RAW_MATCH || sub == RL_QUIET || sub == RL_DTM_RAW || sub == RL_DTM_HOP || sub == RL_RAW_DUMP || sub == RL_DTM_TRAIN || sub == RL_PAGE ||
				sub == RL_PEEK || sub == RL_POKE); /* 1.4.256: radio registers during DTM (window still enforced) */
	if (needs_br && !s_br_mode) { reply(sub, RL_ERR_DISALLOWED, NULL, 0); return; }

	switch (sub) {
	case RL_DTM_RAW: {
		/* 1.4.253: any BLE length byte (sync bits 40..47): IDs use cap0, page responses rxmax, the FHS page shift */
		if ((n != 9 && n != 14) || a[0] > 2) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		if (fw_guard_in_trial()) { reply(sub, RL_ERR_TRIAL, NULL, 0); break; }
		s_dtm_raw_mode = a[0]; s_dtm_raw_aa = rd32(a+1); s_dtm_raw_tail = rd32(a+5);
		if (!s_dtm_raw_mode) {
			s_page_force_x = 0xFF; s_page_tx_end_us = 0;
			s_page_tx_now = false; s_page_tx_ctx = NULL;
			s_page_xfix = 0xFF; s_page_act_i = 0xFF;
			s_page_kick = 0; s_page_r2_ls44 = 0; s_page_det_rxed = 0; s_page_rxed_got = false;
			s_page_r2skip = false; s_conn_prov = false; s_late_skip_us = 0; s_page_r2late = 0; s_itvl_adj = 0; s_r2_adj = false; s_page_shift = false; if (s_mod_tx) { *(volatile uint32_t *)MOD_REG = s_mod_orig; s_mod_tx = 0; }
		}
		if (!a[0]) s_hop_on = s_hop_rx = s_hop_rx_now = s_hop_armed = false;
		s_dtm_tx_cap = n == 14 ? a[9] : 255;
		s_dtm_crc_init = n == 14 ? rd32(a+10) & 0xFFFFFFu : 0x555555u;
		memcpy(out, a, n); reply(sub, RL_OK, out, n); break;
	}
	case RL_DTM_HOP: {
		/* n=3: 0xFE, TX lead u16 us (0 = native, else 40..600). */
		if (n == 2 && a[0] == 0xFD) {  /* RX max length for RX events (0 native) */
			s_rx_max = a[1];
			out[0] = s_rx_max; wr32(out + 1, s_rx_ls8_seen);
			reply(sub, RL_OK, out, 5); break;
		}
		if (n == 3 && a[0] == 0xFE) {
			const uint16_t lead = rd16(a + 1);
			if (lead && (lead < 40 || lead > 600)) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
			s_tx_lead = lead;
			wr16(out, s_tx_lead); wr32(out + 2, s_lead_seen);
			reply(sub, RL_OK, out, 6); break;
		}
		/* n=5: f1 f2 itvl16 on; n=13: +rx,early,ls44,end; n=15: +late_us16 (bounded experiment). */
		if (n == 5 || n == 13 || n == 15) {
			const bool rx = n >= 13 && a[5];
			const uint16_t late = n == 15 ? rd16(a + 13) : 0;
			if ((a[0] > 78 && a[0] != 0xFF) || (a[1] > 78 && a[1] != 0xFF) || a[4] > 1 ||
			    (rd16(a+2) && (rd16(a+2) < 625 || rd16(a+2) % 625)) ||
			    late > 250 ||
			    (rx && (rd16(a+2) != 625 || a[6] > 100 || rd16(a+11) < 1 || rd16(a+11) > 1000)))
				{ reply(sub, RL_ERR_PARAM, NULL, 0); break; }
			if (fw_guard_in_trial()) { reply(sub, RL_ERR_TRIAL, NULL, 0); break; }
			s_hop_on = false;
			s_hop_rx_now = false;
			s_hop_armed = false;
			s_hop_ls44_saved = false;
			s_hop_f[0] = a[0]; s_hop_f[1] = a[1]; s_hop_itvl_us = rd16(a+2);
			s_hop_rx = rx; s_hop_early = rx ? a[6] : 0;
			s_hop_late = rx ? late : 0;
			s_hop_ls44_value = rx ? rd32(a+7) : 0; s_hop_end = rx ? rd16(a+11) : 0;
			s_hop_events = s_hop_bad = s_hop_rx_events = s_hop_run_bad = 0;
			s_hop_dups = s_hop_jumps = 0; s_hop_last_k = 0xFFFFFFFFu;
			for (unsigned i = 0; i < 48; ++i) s_hop_start[i] = 0;
			s_hop_on = a[4];
			if (!a[4]) { s_tx_lead = 0; s_rx_max = 0; } /* dtmhop off clears the lead/rxmax experiments */
		} else if (n != 0) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		out[0] = s_hop_on; out[1] = s_hop_f[0]; out[2] = s_hop_f[1]; wr16(out+3, s_hop_itvl_us);
		wr32(out+5, s_hop_events); wr32(out+9, s_hop_bad);
		for (unsigned i = 0; i < 48; ++i) wr32(out+13+4*i, s_hop_start[i]);
		wr32(out+205, s_hop_rx_events); wr32(out+209, s_hop_run_bad);
		out[213] = s_hop_rx; out[214] = s_hop_early; wr32(out+215, s_hop_ls44_value); wr16(out+219, s_hop_end);
		wr16(out + 221, s_hop_late);
		wr16(out + 223, s_tx_lead); wr32(out + 225, s_lead_seen);
		wr32(out + 229, s_hop_dups); wr32(out + 233, s_hop_jumps);
		reply(sub, RL_OK, out, 237); break;
	}
	case RL_QUIET: {
		if (n != 1 || a[0] > 1) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		if (s_br_mode || fw_guard_in_trial()) { reply(sub, RL_ERR_DISALLOWED, NULL, 0); break; }
		if (a[0] && !s_quiet) {
			esp_err_t err = esp_wifi_stop();
			if (err != ESP_OK && err != ESP_ERR_WIFI_NOT_STARTED && err != ESP_ERR_WIFI_NOT_INIT) {
				reply(sub, RL_ERR_INTERNAL, NULL, 0); break;
			}
			s_quiet_restore_wifi = err == ESP_OK;
			s_quiet = true;
		} else if (!a[0] && s_quiet) {
			if (s_quiet_restore_wifi && esp_wifi_start() != ESP_OK) {
				reply(sub, RL_ERR_INTERNAL, NULL, 0); break;
			}
			s_quiet = s_quiet_restore_wifi = false;
		}
		out[0] = s_quiet; out[1] = s_quiet_restore_wifi;
		reply(sub, RL_OK, out, 2); break;
	}
	case RL_PING: {
		const esp_app_desc_t *d = esp_app_get_description();
		out[0] = LAB_VERSION;
		out[1] = s_br_mode;
		out[2] = fw_guard_in_trial();
		const size_t vl = strnlen(d->version, 32);
		memcpy(out + 3, d->version, vl);
		reply(sub, RL_OK, out, (uint8_t)(3 + vl));
		break;
	}
	case RL_ENTER_BR: {
		uint8_t w = 0;
		const uint8_t st = enter_br(&w);
		reply(sub, st, &w, 1);
		break;
	}
	case RL_EXIT_BR:
		reply(sub, exit_br(), NULL, 0);
		break;
	case RL_TONE: cmd_tone(a, n); break;
	case RL_STOP:
		rf_off();
		reply(sub, RL_OK, NULL, 0);
		break;
	case RL_HOP: cmd_hop(a, n); break;
	case RL_RX_COUNT: cmd_rx_count(a, n); break;
	case RL_BLE_TX: cmd_ble_tx(a, n); break;
	case RL_PEEK: {
		if (n < 5 || a[4] == 0 || a[4] > 60) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		const uint32_t addr = rd32(a);
		const uint32_t end = addr + 4u * (a[4] - 1u);
		if ((addr & 3u) || addr < PEEK_LO || end > PEEK_HI || end < addr) { reply(sub, RL_ERR_RANGE, NULL, 0); break; }
		for (unsigned i = 0; i < a[4]; i++) wr32(out + 4 * i, *(volatile uint32_t *)(addr + 4u * i));
		reply(sub, RL_OK, out, (uint8_t)(4 * a[4]));
		break;
	}
	case RL_POKE: {
		if (n < 8) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		const uint32_t addr = rd32(a);
		if ((addr & 3u) || addr < PEEK_LO || addr > PEEK_HI) { reply(sub, RL_ERR_RANGE, NULL, 0); break; }
		*(volatile uint32_t *)addr = rd32(a + 4);
		reply(sub, RL_OK, NULL, 0);
		break;
	}
	case RL_CALL: {
		if (n < 17 || a[0] >= N_FNS) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		const int rv = k_fns[a[0]]((int)rd32(a + 1), (int)rd32(a + 5), (int)rd32(a + 9), (int)rd32(a + 13));
		wr32(out, (uint32_t)rv);
		reply(sub, RL_OK, out, 4);
		break;
	}
	case RL_FORCE: {
		if (n < 3) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		const int rv = phy_force_freq_set(a[0] ? 1 : 0, rd16(a + 1), 0, 0);
		wr32(out, (uint32_t)rv);
		reply(sub, RL_OK, out, 4);
		break;
	}
	case RL_RAW_MATCH: {
		/* Zero-duration query retrieves the last completed result if its
		 * asynchronous SDIO event was lost. Never read a running worker. */
		if (n == 6 && !rd16(a)) {
			if (s_raw_running || !s_raw_result_len) reply(sub, RL_ERR_DISALLOWED, NULL, 0);
			else reply(sub, RL_OK, s_raw_result, s_raw_result_len);
			break;
		}
		if ((n != 6 && n != 7 && n != 10) || rd16(a) < 100 || rd16(a) > 4000 || (n >= 7 && a[6] > 3) ||
		    (n == 10 && (a[7] > RAW_CAP_BYTES || rd16(a+8) > 1000)))
			{ reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		uint8_t policy = n >= 7 ? a[6] : 0;
		if ((policy >= 2 ? !s_dtm_raw_mode : !s_scan_aa_enabled) || s_raw_running) { reply(sub, RL_ERR_DISALLOWED, NULL, 0); break; }
		s_raw_ms = rd16(a); s_raw_expected = rd32(a+2); s_raw_result_len = 0; s_raw_running = true;
		s_raw_policy = n >= 7 ? a[6] : 0;
		s_cap_len = n == 10 ? a[7] : 0; s_cap_delay_us = n == 10 ? rd16(a+8) : 0; s_cap_count = 0;
		if (xTaskCreate(raw_match_worker, "raw_match", 4096, NULL, configMAX_PRIORITIES-4, NULL) != pdPASS) {
			s_raw_running = false; reply(sub, RL_ERR_INTERNAL, NULL, 0); break;
		}
		reply(sub, RL_STARTED, NULL, 0);
		break;
	}
	case RL_DTM_TRAIN: {
		if (!n) {
			out[0] = s_train_n; wr16(out + 1, s_train_repeats);
			memcpy(out + 3, s_train_tx, 32); memcpy(out + 35, s_train_rx, 32);
			reply(sub, RL_OK, out, 67); break;
		}
		if (s_hop_on) { reply(sub, RL_ERR_BUSY, NULL, 0); break; }
		if (a[0] == 0 && n == 4 && (a[1] == 0 || a[1] == 16 || a[1] == 32) && rd16(a + 2)) {
			s_train_n = a[1]; s_train_repeats = rd16(a + 2); reply(sub, RL_OK, NULL, 0); break;
		}
		if (a[0] == 1 && n >= 3 && a[2] <= 16 && a[1] + a[2] <= 32 && n == 3 + 2 * a[2]) {
			bool ok = true;
			for (unsigned i = 0; i < 2u * a[2]; ++i) if (a[3 + i] > 78) ok = false;
			if (ok) {
				memcpy(s_train_tx + a[1], a + 3, a[2]); memcpy(s_train_rx + a[1], a + 3 + a[2], a[2]);
				reply(sub, RL_OK, NULL, 0); break;
			}
		}
		reply(sub, RL_ERR_PARAM, NULL, 0);
		break;
	}
	case RL_PAGE: {
		if (n == 1 && a[0] == 2) {
			wr32(out, s_page_resp1); wr32(out + 4, s_page_fhs_sent); wr32(out + 8, s_page_resp2);
			wr32(out + 12, s_page_resp2_miss); wr32(out + 16, s_page_rx_checks); wr32(out + 20, s_page_bad);
			out[24] = s_page_x; out[25] = s_page_state; out[26] = s_page_on;
			for (unsigned i = 0; i < 8; ++i) wr32(out + 27 + 4 * i, s_page_resp2_k[i]);
			out[59] = s_page_dbg_n;
			for (unsigned i = 0; i < 8; ++i)
				for (unsigned j = 0; j < 4; ++j) wr32(out + 60 + 16 * i + 4 * j, s_page_dbg[i][j]);
			/* 1.4.224: actual FHS / resp2-RX starts (u16 offsets from the ID stamp), then xfix */
			for (unsigned i = 0; i < 8; ++i) { wr16(out + 188 + 4 * i, s_page_act[i][0]); wr16(out + 190 + 4 * i, s_page_act[i][1]); }
			out[220] = s_page_xfix;
			wr32(out + 221, s_page_kicks); wr16(out + 225, s_page_kick); wr32(out + 227, s_page_r2_ls44);
			reply(sub, RL_OK, out, 231); break;
		}
		if (n == 1 && a[0] == 10) {  /* arming trace */
			out[0] = s_tr_row;
			for (unsigned i = 0; i < 3; ++i) for (unsigned j = 0; j < 3; ++j) for (unsigned w = 0; w < 6; ++w)
				wr32(out + 1 + 4 * (w + 6 * (j + 3 * i)), s_tr[i][j][w]);
			reply(sub, RL_OK, out, 217); break;
		}
		if (n == 1 && a[0] == 9) {  /* rxed-path detection log */
			out[0] = s_page_det_rxed; wr32(out + 1, s_page_rxed_calls); wr32(out + 5, s_page_rxed_hits);
			wr32(out + 73, s_page_poll_hits); wr32(out + 77, s_page_poll_used); wr32(out + 81, s_page_poll_stale);
			for (unsigned i = 0; i < 8; ++i) { wr32(out + 9 + 8 * i, s_page_rxed_log[i][0]); wr32(out + 13 + 8 * i, s_page_rxed_log[i][1]); }
			reply(sub, RL_OK, out, 85); break;
		}
		if (n == 24 && a[0] == 17) {  /* encryption: mode u8 (0 off, 1 RX+TX, 2 RX only), Kc' 16 (C byte order), central
		                                BD_ADDR 6 (index 0 = LSB) */
			memcpy(s_enc_kc, a + 2, 16); memcpy(s_enc_addr, a + 18, 6);
			s_enc_rx = a[1] != 0;
			s_enc_on = a[1] == 1;
			s_mask_reset = true; /* FIFO: recompute payload masks with the new TX encryption state */
			out[0] = s_enc_on; out[1] = s_enc_rx; reply(sub, RL_OK, out, 2); break;
		}
		if (n >= 5 && a[0] == 19) {  /* 1.4.244 FIFO push: tag u16 (retry dedup, 0 = none), type u8 (3 DM1, 4 DH1),
		                                LLID u8, data (DM1 <= 17, DH1 <= 27 bytes) */
			const uint16_t tag = rd16(a + 1);
			const uint8_t type = a[3], llid = a[4] & 3u;
			bool ok = true;
			if (!s_fifo_on || (type != BR_TYPE_DM1 && type != BR_TYPE_DH1) || !llid) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
			if (!(tag && tag == s_fifo_last_tag)) {
				ok = fifo_push(type, llid, a + 5, n - 5u);
				if (ok) s_fifo_last_tag = tag;
			}
			out[0] = ok; out[1] = (uint8_t)(FIFO_N - fifo_count()); wr16(out + 2, s_fifo_last_tag);
			reply(sub, RL_OK, out, 4); break;
		}
		if (n == 3 && a[0] == 22) {  /* 1.4.245 supervision timeout: slots u16 without any reply (0 = off) */
			s_conn_sup = rd16(a + 1);
			wr32(out, s_conn_sup); reply(sub, RL_OK, out, 4); break;
		}
		if (n == 3 && a[0] == 25 && rd16(a + 1) <= 300) {  /* 1.4.248 r2late u16 us (with r2skip) */
			s_page_r2late = rd16(a + 1); s_t3_n = 0; s_t3_i = 0xFF; s_itvl_adj = 0; s_r2_adj = false;
			for (unsigned i = 0; i < 8; ++i) s_conn_phase[i] = 0;
			s_reanchors = 0;
			wr16(out, s_page_r2late); reply(sub, RL_OK, out, 2); break;
		}
		if (n == 1 && a[0] == 27) {  /* 1.4.250 latency histogram (after TX, after RX) + jump log */
			for (unsigned r = 0; r < 2; ++r) for (unsigned i = 0; i < 16; ++i) wr32(out + 64 * r + 4 * i, s_lat_hist[r][i]);
			out[128] = s_jl_n; wr32(out + 209, s_late_skips);
			for (unsigned i = 0; i < 8; ++i) { wr16(out + 129 + 10 * i, (uint16_t)s_jl[i][0]); wr16(out + 131 + 10 * i, (uint16_t)s_jl[i][1]);
			                                   wr16(out + 133 + 10 * i, (uint16_t)s_jl[i][2]); wr32(out + 135 + 10 * i, s_jl[i][3]); }
			reply(sub, RL_OK, out, 213); break;
		}
		if (n == 3 && a[0] == 28 && rd16(a + 1) <= 1000) {  /* 1.4.251 late-hook skip threshold us (0 off) */
			s_late_skip_us = rd16(a + 1); s_late_skips = 0;
			wr16(out, s_late_skip_us); reply(sub, RL_OK, out, 2); break;
		}
		if (n == 2 && a[0] == 27) {  /* reset */
			memset((void *)s_lat_hist, 0, sizeof s_lat_hist); s_jl_n = 0;
			reply(sub, RL_OK, NULL, 0); break;
		}
		if (n == 1 && a[0] == 26) {  /* 1.4.248 long-FHS timing log */
			out[0] = s_t3_n;
			for (unsigned i = 0; i < 8; ++i) for (unsigned j = 0; j < 3; ++j) wr32(out + 1 + 12 * i + 4 * j, s_t3[i][j]);
			for (unsigned i = 0; i < 8; ++i) wr32(out + 97 + 4 * i, s_conn_phase[i]);
			wr32(out + 129, s_reanchors);
			reply(sub, RL_OK, out, 133); break;
		}
		if (n == 1 && a[0] == 30) {  /* 1.4.254 per-channel miss %: 79 by TX channel, 79 by reply channel (255 = no data) */
			for (unsigned c = 0; c < 79; ++c) {
				out[c] = s_ch_tx_n[c] ? (uint8_t)(100u * s_ch_tx_miss[c] / s_ch_tx_n[c]) : 255u;
				out[79 + c] = s_ch_rx_n[c] ? (uint8_t)(100u * s_ch_rx_miss[c] / s_ch_rx_n[c]) : 255u;
			}
			wr32(out + 158, s_rep_n); wr32(out + 162, s_rep_arqn1); wr32(out + 166, s_rep_flow0);
			for (unsigned i = 0; i < 16; ++i) wr32(out + 170 + 4 * i, s_rep_type[i]);
			reply(sub, RL_OK, out, 234); break;
		}
		if (n == 4 && a[0] == 33) {  /* 1.4.259 freq memory read: chan u8, type u8, sel u8 -> u32, + param u32 */
			wr32(out, freq_mem_read(a[1], a[2], a[3])); wr32(out + 4, get_freq_mem_param(2));
			reply(sub, RL_OK, out, 8); break;
		}
		if (n == 5 && a[0] == 34) {  /* 1.4.259 pll_dac_mem_update_new(u32) */
			pll_dac_mem_update_new(rd32(a + 1)); reply(sub, RL_OK, NULL, 0); break;
		}
		if (n == 5 && a[0] == 38) {  /* 1.4.263 TX-event modulation value u32 (0 = off, restores the original) */
			const uint32_t v = rd32(a + 1);
			if (v && !s_mod_tx) s_mod_orig = *(volatile uint32_t *)MOD_REG;
			if (!v && s_mod_tx) *(volatile uint32_t *)MOD_REG = s_mod_orig;
			s_mod_tx = v;
			wr32(out, s_mod_orig); reply(sub, RL_OK, out, 4); break;
		}
		if (n == 3 && a[0] == 39) {  /* 1.4.264 TX packet end for the RX restore, us after the TX start (300..600) */
			const uint16_t us = rd16(a + 1);
			if (us < 300 || us > 600) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
			s_mod_tx_us = us; reply(sub, RL_OK, NULL, 0); break;
		}
		if (n == 1 && a[0] == 39) {  /* query: on u8, value u32, orig u32, waits u32, max wait us u32, end us u16 */
			out[0] = s_mod_tx != 0; wr32(out + 1, s_mod_tx); wr32(out + 5, s_mod_orig); wr32(out + 9, s_mod_waits);
			wr32(out + 13, s_mod_wait_max); wr16(out + 17, s_mod_tx_us); reply(sub, RL_OK, out, 19); break;
		}
		if (n == 2 && a[0] == 32) {  /* 1.4.258 media fragments in DM1 u8 (0 = DH1) */
			s_stream_dm1 = a[1] != 0; out[0] = s_stream_dm1; reply(sub, RL_OK, out, 1); break;
		}
		if (n == 4 && a[0] == 36) {  /* 1.4.261 analog I2C read: block u8, host u8, reg u8 -> u8 */
			out[0] = a[2] & 0x80 ? esp_rom_regi2c_read(a[1], a[2] & 0x7F, a[3]) : rom_chip_i2c_readReg(a[1], a[2], a[3]);
			reply(sub, RL_OK, out, 1); break;
		}
		if (n == 5 && a[0] == 37) {  /* 1.4.261 analog I2C write: block, host, reg, value */
			if (a[2] & 0x80) esp_rom_regi2c_write(a[1], a[2] & 0x7F, a[3], a[4]);
			else rom_chip_i2c_writeReg(a[1], a[2], a[3], a[4]);
			reply(sub, RL_OK, NULL, 0); break;
		}
		if (n == 2 && a[0] == 35) {  /* 1.4.260 DH1 fragment length 1..27 (0 = 27) */
			if (a[1] > 27) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
			s_stream_frag = a[1]; out[0] = a[1]; reply(sub, RL_OK, out, 1); break;
		}
		if (n == 2 && a[0] == 31) {  /* 1.4.257 TX power dBm (3/6/9/12/15/18/20): BLE default + connections (DTM) */
			if (!cis_c6_knob_set(CIS_C6_KNOB_TX_DBM, a[1])) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
			out[0] = a[1]; reply(sub, RL_OK, out, 1); break;
		}
		if (n == 2 && a[0] == 30) {  /* reset */
			memset(s_ch_tx_n, 0, sizeof s_ch_tx_n); memset(s_ch_tx_miss, 0, sizeof s_ch_tx_miss);
			memset(s_ch_rx_n, 0, sizeof s_ch_rx_n); memset(s_ch_rx_miss, 0, sizeof s_ch_rx_miss);
			s_rep_n = s_rep_arqn1 = s_rep_flow0 = 0; memset(s_rep_type, 0, sizeof s_rep_type);
			reply(sub, RL_OK, NULL, 0); break;
		}
		if (n == 2 && a[0] == 29) {  /* 1.4.253 shifted FHS u8 (0 off, 1 on); set before mode 1 */
			s_page_shift = a[1] != 0; s_page_shift_sent = 0;
			out[0] = s_page_shift; reply(sub, RL_OK, out, 1); break;
		}
		if (n == 1 && a[0] == 29) {  /* query: on u8, shifted FHS sent u32 */
			out[0] = s_page_shift; wr32(out + 1, s_page_shift_sent); reply(sub, RL_OK, out, 5); break;
		}
		if (n == 2 && a[0] == 24) {  /* 1.4.247 r2skip u8 (0 off, 1 on) */
			s_page_r2skip = a[1] != 0; s_page_r2skips = 0; s_conn_prov_ends = 0;
			out[0] = s_page_r2skip; reply(sub, RL_OK, out, 1); break;
		}
		if (n == 1 && a[0] == 23) {  /* 1.4.245 end the connection at the next central slot (after an LMP detach) */
			s_conn_end_req = s_page_state == 4;
			out[0] = s_conn_end_req; reply(sub, RL_OK, out, 1); break;
		}
		if (n == 3 && a[0] == 20) {  /* 1.4.244 FIFO mode: on u8, SEQN of the first fragment u8 */
			fifo_reset(a[1] != 0, a[2]);
			out[0] = s_fifo_on; reply(sub, RL_OK, out, 1); break;
		}
		if (n == 9 && a[0] == 21) {  /* 1.4.244 A2DP stream test: on u8, media CID u16, frames per packet u8, packets u32
		                                (0 = until off) */
			static TaskHandle_t st;
			if (a[1] > 2 || (a[1] && (!s_fifo_on || !a[4] || a[4] > 15))) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
			s_stream_dcid = rd16(a + 2); s_stream_fpp = a[4]; s_stream_max = rd32(a + 5);
			if (a[1]) { s_stream_pkts = s_stream_frames = s_stream_full = 0; }
			if (!st) xTaskCreate(stream_task, "a2dp_stream", 3072, NULL, configMAX_PRIORITIES - 5, &st);
			s_stream_src = a[1];
			s_stream_on = a[1] != 0;
			out[0] = s_stream_on; reply(sub, RL_OK, out, 1); break;
		}
		if (((n >= 6 && a[0] == 16) || (n >= 7 && a[0] == 18)) && a[1] < LMP_Q) {
			/* 1.4.243: mode 18 = same as 16 with an explicit LLID byte before the data (1 L2CAP continuation,
			 * 2 L2CAP start, 3 LMP) so ACL/L2CAP fragments use the same queue, SEQN and encryption path. */
			const bool m18 = a[0] == 18;
			const uint8_t llid = m18 ? (a[6] & 3u) : 3u;
			const uint8_t *data = a + (m18 ? 7 : 6);  /* LMP queue: idx, start u16 (conn slot), repeat u8, seqn u8, PDU
		                                            bytes (1..17); n == 6 with repeat 0 clears the entry */
			lmp_q_t *q = &s_lmp_q[a[1]];
			const uint16_t start = rd16(a + 2); const uint8_t repeat = a[4], seqn = a[5] & 1u;
			const unsigned len = n - (m18 ? 7u : 6u);
			q->used = 0;
			if (!repeat) { reply(sub, RL_OK, NULL, 0); break; }
			if ((llid == 3 && len < 1) || len > 17 || !s_conn_slots || !llid) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
			static br_pkt_t lpkt;
			static uint8_t lair[BR_PACKET_MAX_BYTES];
			const uint32_t olap = s_conn_aa_lap; const uint8_t ouap = s_conn_aa_uap;
			bool ok = true;
			const bool enc = s_enc_on;
			uint32_t est = 0;
			if (enc) {
				/* fixed slots: well ahead of now and behind every pending entry (6 encodes take a few ms) */
				est = s_conn_n + 160u;
				for (unsigned qi = 0; qi < LMP_Q; ++qi)
					if (qi != a[1] && s_lmp_q[qi].used && (uint32_t)s_lmp_q[qi].start + s_lmp_q[qi].repeat + 2u > est)
						est = (uint32_t)s_lmp_q[qi].start + s_lmp_q[qi].repeat + 2u;
				if (repeat > 64) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
			}
			const unsigned variants = enc ? repeat : 64u;
			for (unsigned c = 0; c < variants && ok; ++c) {
				memset(&lpkt, 0, sizeof lpkt);
				lpkt.hdr.type = BR_TYPE_DM1; lpkt.hdr.lt_addr = 1; lpkt.hdr.flow = 1; lpkt.hdr.arqn = 1; lpkt.hdr.seqn = seqn;
				lpkt.llid = llid; lpkt.pflow = 1; lpkt.len = (uint16_t)len;
				memcpy(lpkt.payload, data, len);
				const uint32_t eclk = 4u * (est + c + 1u);
				static br_e0_t le0;
				if (enc) br_e0_init(&le0, s_enc_kc, s_enc_addr, eclk);
				const br_link_ctx_t ctx = { .lap = olap, .uap = ouap, .clk6 = (uint8_t)(enc ? ((eclk >> 1) & 63u) : c),
				                            .e0 = enc ? &le0 : NULL };
				size_t nbits = 0;
				if (br_packet_encode(&lpkt, &ctx, lair, sizeof lair, &nbits) != BR_OK || nbits <= 68 || nbits - 68 > 8 * LMP_PKT_BYTES) { ok = false; break; }
				memset(q->pkt[c], 0, LMP_PKT_BYTES);
				for (unsigned b = 0; b < nbits - 68; ++b)
					if (br_bit_get(lair, 68 + b)) q->pkt[c][b >> 3] |= (uint8_t)(1u << (b & 7));
				q->nbytes = (uint8_t)((nbits - 68 + 7) / 8);
			}
			if (!ok) { reply(sub, RL_ERR_INTERNAL, NULL, 0); break; }
			uint32_t st = start;
			if (enc) st = est;
			else if (start == 0xFFFFu) {
				/* 1.4.241: ASAP. Encoding 64 variants takes ~0.5 s, so the host cannot know the slot in advance:
				 * start 8 slots from now, after every other queued entry that is still pending. */
				st = s_conn_n + 8u;
				for (unsigned qi = 0; qi < LMP_Q; ++qi)
					if (qi != a[1] && s_lmp_q[qi].used && (uint32_t)s_lmp_q[qi].start + s_lmp_q[qi].repeat + 2u > st)
						st = (uint32_t)s_lmp_q[qi].start + s_lmp_q[qi].repeat + 2u;
			}
			q->start = (uint16_t)st; q->repeat = repeat; q->enc = enc; q->used = 1;
			out[0] = q->nbytes; memcpy(out + 1, q->pkt[enc ? 0 : 8], LMP_PKT_BYTES); wr16(out + 1 + LMP_PKT_BYTES, q->start);
			reply(sub, RL_OK, out, 3 + LMP_PKT_BYTES); break;
		}
		if (n == 1 && a[0] == 13) {  /* connection counters (1.4.234 layout) */
			out[0] = s_conn_armed; out[1] = (s_page_state == 4 && s_conn_prov) ? 5 : s_page_state; wr32(out + 2, s_conn_n); wr32(out + 6, s_conn_slots);
			wr32(out + 10, s_conn_entries); wr32(out + 14, s_conn_tx); wr32(out + 18, s_conn_rx);
			wr32(out + 22, s_conn_underrun); out[26] = s_conn_log_n; out[27] = s_conn_ready;
			for (unsigned i = 0; i < 16; ++i) wr16(out + 28 + 2 * i, s_conn_rx_first[i]);
			out[60] = s_conn_rx_first_n;
			wr32(out + 61, s_conn_hit_saved); wr32(out + 65, s_conn_hit_now);
			wr32(out + 69, s_conn_hit_rxed); wr32(out + 73, s_conn_drained);
			wr32(out + 77, s_conn_nulls); wr32(out + 81, s_conn_others);
			wr32(out + 85, s_lmp_sent); wr32(out + 89, s_conn_log_count);
			/* 1.4.244 FIFO/ARQ counters */
			const uint32_t f[17] = { s_fifo_head, s_fifo_tail, s_fifo_tx, s_fifo_retx, s_fifo_acked, s_fifo_nomask,
			                         s_rx_nak, s_rx_ack, s_rx_hecfail, s_rx_verified, s_rx_verify_fail, s_rx_dup,
			                         s_rx_noreply, s_mask_us_max, s_mask_n, s_stream_pkts, s_stream_full };
			for (unsigned i = 0; i < 17; ++i) wr32(out + 93 + 4 * i, f[i]);
			out[161] = s_fifo_on; out[162] = s_tx_seqn; out[163] = s_enc_on | (s_enc_rx << 1); out[164] = s_stream_on;
			/* 1.4.245 */
			wr32(out + 165, s_conn_sup_ends); wr32(out + 169, s_conn_host_ends); wr32(out + 173, s_page_xf_agree);
			wr32(out + 177, s_page_xf_differ); wr32(out + 181, s_conn_sup); wr32(out + 185, s_stream_frames);
			wr32(out + 189, s_stream_skips);
			/* 1.4.246 host SBC ring */
			wr32(out + 193, s_sbc_w - s_sbc_r); wr32(out + 197, s_sbc_drops); wr32(out + 201, s_sbc_in);
			/* 1.4.247 r2skip */
			wr32(out + 205, s_page_r2skips); wr32(out + 209, s_conn_prov_ends); out[213] = s_page_r2skip;
			reply(sub, RL_OK, out, 214); break;
		}
		if (n == 2 && a[0] == 15 && a[1] < 4) {  /* buffer trace, 8 slots per page */
			for (unsigned i = 0; i < 8; ++i) { wr32(out + 8 * i, s_conn_buf_trace[8 * a[1] + i][0]); wr32(out + 8 * i + 4, s_conn_buf_trace[8 * a[1] + i][1]); }
			reply(sub, RL_OK, out, 64); break;
		}
		if ((n == 2 || n == 5) && a[0] == 14) {  /* log entry: n=2 ring position u8 (old); n=5 absolute index u32 */
			const uint32_t idx = n == 5 ? rd32(a + 1) : a[1];
			const uint32_t cnt = s_conn_log_count;
			if (n == 5 ? (idx >= cnt || cnt - idx > CONN_LOG_N) : (a[1] >= s_conn_log_n)) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
			const unsigned e = idx % CONN_LOG_N;
			wr32(out, s_conn_log_slot[e]); memcpy(out + 4, s_conn_log[e], CONN_LOG_BYTES);
			reply(sub, RL_OK, out, 4 + CONN_LOG_BYTES); break;
		}
		if (s_hop_on) { reply(sub, RL_ERR_BUSY, NULL, 0); break; }
		if ((n == 7 || n == 10) && a[0] == 12) {  /* arm connection: own LAP u24, UAP u8, slots u16 (0 off)
		                                            [, conn rxmax u8, conn ls44 u16] (1.4.234) */
			const uint32_t olap = a[1] | (a[2] << 8) | ((uint32_t)a[3] << 16);
			const uint8_t ouap = a[4];
			const uint16_t slots16 = rd16(a + 5);
			/* 1.4.245: 65535 = no slot limit (the link ends by supervision timeout or `page connend`) */
			const uint32_t slots = slots16 == 0xFFFFu ? 0xFFFFFFFFu : slots16;
			s_conn_armed = false; s_conn_ready = false;
			if (!slots) { reply(sub, RL_OK, NULL, 0); break; }
			static br_pkt_t cpkt;
			static uint8_t cair[BR_PACKET_MAX_BYTES];
			bool ok = true;
			for (unsigned c = 0; c < 64 && ok; ++c) {
				memset(&cpkt, 0, sizeof cpkt);
				cpkt.hdr.type = BR_TYPE_POLL; cpkt.hdr.lt_addr = 1; cpkt.hdr.flow = 1; cpkt.hdr.arqn = 1;
				const br_link_ctx_t ctx = { .lap = olap, .uap = ouap, .clk6 = (uint8_t)c };
				size_t nbits = 0;
				if (br_packet_encode(&cpkt, &ctx, cair, sizeof cair, &nbits) != BR_OK || nbits != 126) { ok = false; break; }
				if (c == 0) {
					uint32_t aa = 0, tail = 0;
					for (unsigned b = 0; b < 32; ++b) { aa |= (uint32_t)br_bit_get(cair, 4 + b) << b; tail |= (uint32_t)br_bit_get(cair, 36 + b) << b; }
					s_conn_aa = aa; s_conn_tail = tail; s_conn_len = (uint8_t)(tail >> 8);
				}
				memset(s_conn_poll[c], 0, CONN_POLL_BYTES);
				for (unsigned b = 0; b < 126 - 68; ++b)
					if (br_bit_get(cair, 68 + b)) s_conn_poll[c][b >> 3] |= (uint8_t)(1u << (b & 7));
			}
			for (unsigned c = 0; c < 64 && ok; ++c)
				for (unsigned v = 0; v < 8 && ok; ++v) {
					memset(&cpkt, 0, sizeof cpkt);
					cpkt.hdr.type = BR_TYPE_NULL; cpkt.hdr.lt_addr = 1;
					cpkt.hdr.flow = v & 1; cpkt.hdr.arqn = (v >> 1) & 1; cpkt.hdr.seqn = (v >> 2) & 1;
					const br_link_ctx_t ctx = { .lap = olap, .uap = ouap, .clk6 = (uint8_t)c };
					size_t nbits = 0;
					if (br_packet_encode(&cpkt, &ctx, cair, sizeof cair, &nbits) != BR_OK || nbits != 126) { ok = false; break; }
					uint64_t h = 0;
					for (unsigned b = 0; b < 54; ++b) h |= (uint64_t)br_bit_get(cair, 72 + b) << b;
					s_conn_null_hdr[c][v] = h;
					s_conn_null_mv[c][v] = conn_maj18(h);
				}
			if (!ok || s_conn_len < 40 || s_conn_len > 55) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
			fifo_reset(false, 1);
			fifo_tables(ouap, cair);
			s_conn_a28 = br_hop_address(ouap, olap);
			s_conn_aa_lap = olap; s_conn_aa_uap = ouap;
			for (unsigned qi = 0; qi < LMP_Q; ++qi) s_lmp_q[qi].used = 0;
			s_lmp_sent = 0; s_enc_on = false; s_enc_rx = false;
			s_conn_slots = slots;
			s_conn_rxmax = n == 10 ? a[7] : 0;
			s_conn_ls44 = n == 10 ? rd16(a + 8) : 0;
			conn_fill_from(0);
			s_conn_entries = s_conn_rx = s_conn_tx = s_conn_underrun = 0; s_conn_rx_first_n = 0; s_conn_log_n = 0;
			s_conn_log_count = 0;
			s_conn_hit_saved = s_conn_hit_now = s_conn_now_last = 0;
			s_conn_hit_rxed = s_conn_drained = s_conn_rxed_last = 0; s_conn_nulls = s_conn_others = 0;
			s_conn_refill = false; s_conn_ready = true;
			s_conn_armed = true;
			if (!s_conn_task) xTaskCreate(conn_fill_task, "conn_fill", 3072, NULL, configMAX_PRIORITIES - 3, &s_conn_task);
			wr32(out, s_conn_aa); wr32(out + 4, s_conn_tail); out[8] = s_conn_len;
			memcpy(out + 9, s_conn_f_tx, 8); memcpy(out + 17, s_conn_f_rx, 8); memcpy(out + 25, s_conn_poll[8], CONN_POLL_BYTES);
			reply(sub, RL_OK, out, 33); break;
		}
		if (n == 5 && a[0] == 11) {  /* detection compare mask (0 = all bits) */
			s_page_mask = rd32(a + 1) ? rd32(a + 1) : 0xFFFFFFFFu;
			wr32(out, s_page_mask); reply(sub, RL_OK, out, 4); break;
		}
		if (n == 2 && a[0] == 8 && a[1] <= 3) {  /* detection: 0 ls+8 at TX hook, 1 rxed hook, 2 RX-time buffer, 3 rawmatch worker */
			s_page_poll_got = false; s_page_poll_hits = s_page_poll_used = s_page_poll_stale = 0;
			s_page_det_rxed = a[1]; out[0] = a[1]; reply(sub, RL_OK, out, 1); break;
		}
		if (n == 3 && a[0] == 6) {  /* kick period in pairs, 0 = off */
			s_page_kick = rd16(a + 1); s_page_kicks = 0;
			wr16(out, s_page_kick); reply(sub, RL_OK, out, 2); break;
		}
		if (n == 5 && a[0] == 7 && rd32(a + 1) <= 2000) {  /* resp2 RX ls44 raw, 0 = same as dtmhop */
			s_page_r2_ls44 = rd32(a + 1);
			wr32(out, s_page_r2_ls44); reply(sub, RL_OK, out, 4); break;
		}
		if (n == 2 && a[0] == 5 && (a[1] < 32 || a[1] == 0xFF)) {
			s_page_xfix = a[1];
			out[0] = s_page_xfix;
			reply(sub, RL_OK, out, 1); break;
		}
		if (n == 3 && a[0] == 4 && rd16(a + 1) <= 625 && s_page_on) {
			s_page_tx_end_us = rd16(a + 1);
			reply(sub, RL_OK, NULL, 0); break;
		}
		if ((n == 2 || n == 4) && a[0] == 3 && a[1] < 32 && s_page_on && s_dtm_raw_mode == 2 &&
		    (n == 2 || rd16(a + 2) <= 625)) {
			s_page_force_x = a[1];
			s_page_tx_end_us = n == 4 ? rd16(a + 2) : 0;
			out[0] = s_page_tx_cap;
			reply(sub, RL_OK, out, 1); break;
		}
		if (n == 1 && a[0] == 0) {
			if (s_page_state == 4) { s_dtm_raw_aa = s_conn_save_aa; s_dtm_raw_tail = s_conn_save_tail; }
			s_page_force_x = 0xFF;
			s_page_tx_end_us = 0; s_page_tx_now = false; s_page_tx_ctx = NULL;
			s_page_on = false; s_page_state = 0; s_page_last_stamp = 0;
			s_page_resp1 = s_page_fhs_sent = s_page_resp2 = s_page_resp2_miss = s_page_rx_checks = s_page_bad = 0;
			for (unsigned i = 0; i < 8; ++i) s_page_resp2_k[i] = 0;
			memset((void *)s_page_dbg, 0, sizeof s_page_dbg); s_page_dbg_n = 0; s_page_dbg_pending = false;
			memset((void *)s_page_act, 0xFF, sizeof s_page_act); s_page_act_i = 0xFF; s_page_xfix = 0xFF;
			s_page_kick = 0; s_page_kicks = 0; s_page_r2_ls44 = 0; s_page_mask = 0xFFFFFFFFu;
			s_conn_armed = false;
			s_page_det_rxed = 0; s_page_rxed_got = false; s_page_rxed_calls = s_page_rxed_hits = s_page_rxed_last = 0;
			memset((void *)s_page_rxed_log, 0, sizeof s_page_rxed_log);
			memset((void *)s_tr, 0, sizeof s_tr); s_tr_row = 0; s_tr_stage = 0xFF; s_tr_pending = false;
			reply(sub, RL_OK, NULL, 0); break;
		}
		if (n != 18 || a[0] != 1) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		const uint32_t tlap = a[1] | (a[2] << 8) | ((uint32_t)a[3] << 16), olap = a[5] | (a[6] << 8) | ((uint32_t)a[7] << 16);
		const uint8_t tuap = a[4], ouap = a[8];
		/* The DAC tail occupies the BLE header: its second byte is the BLE payload length.
		 * Measured 2026-11-09 (A2DP_PROGRESS.md): Bose LEN=55 with cap40 aborts after
		 * the header (~77 us); cap55 sends the full payload (~540 us incl. ramp).
		 * Require room for the 40 payload octets carrying the FHS, and bound the
		 * extra tail to the longest measured packet that still fits this slot. */
		const uint8_t tx_len = (uint8_t)(s_dtm_raw_tail >> 8);
		/* 1.4.247: 56..80 only with r2skip (the frame overlaps the resp2 slot; 80 ends ~740 us, before the next TX) */
		if (!s_page_shift && (tx_len < 40 || tx_len > (s_page_r2skip ? 80 : 55))) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		static br_pkt_t pkt;
		static uint8_t air[BR_PACKET_MAX_BYTES];
		br_fhs_t fh = { .parity = br_fhs_parity_for_lap(olap), .lap = olap, .eir = 0, .sr = 1, .uap = ouap,
		                .nap = rd16(a + 9), .cod = a[11] | (a[12] << 8) | ((uint32_t)a[13] << 16), .lt_addr = 1,
		                .clk27_2 = rd32(a + 14) & 0x3FFFFFFu, .page_scan_mode = 0 };
		const uint32_t a28 = br_hop_address(tuap, tlap);
		bool ok = true;
		for (uint32_t x = 0; x < 32 && ok; ++x) {
			memset(&pkt, 0, sizeof pkt);
			pkt.hdr.type = BR_TYPE_FHS; pkt.hdr.flow = 1; pkt.len = BR_FHS_BYTES;
			br_fhs_pack(&fh, pkt.payload);
			const br_link_ctx_t ctx = { .lap = tlap, .uap = tuap, .clk6 = (uint8_t)(((x + 1) & 31u) | 0x20u) };
			size_t nbits = 0;
			if (br_packet_encode(&pkt, &ctx, air, sizeof air, &nbits) != BR_OK || nbits != 366) { ok = false; break; }
			/* sanity: air bits 36..67 must be the sync tail the DTM body[0..3] already carries */
			uint32_t tail = 0;
			for (unsigned b = 0; b < 32; ++b) tail |= (uint32_t)br_bit_get(air, 36 + b) << b;
			if (tail != s_dtm_raw_tail) { ok = false; break; }
			memset(s_page_fhs[x], 0, PAGE_FHS_BYTES);
			for (unsigned b = 0; b < 366 - 68; ++b)
				if (br_bit_get(air, 68 + b)) s_page_fhs[x][b >> 3] |= (uint8_t)(1u << (b & 7));
			memset(s_page_fhs_full[x], 0, PAGE_SHIFT_LEN);
			for (unsigned b = 0; b < 366; ++b)
				if (br_bit_get(air, b)) s_page_fhs_full[x][b >> 3] |= (uint8_t)(1u << (b & 7));
			s_page_fhs_f[x] = (uint8_t)br_hop_slave_page_response(a28, x << 12, (x << 12) | 4u, 1);
			s_page_resp2_f[x] = (uint8_t)br_hop_slave_page_response(a28, x << 12, (x << 12) | 6u, 1);
		}
		if (!ok) { reply(sub, RL_ERR_INTERNAL, NULL, 0); break; }
		s_page_state = 0; s_page_last_stamp = 0;
		s_page_tx_cap = s_page_shift ? PAGE_SHIFT_LEN : tx_len;
		s_page_force_x = 0xFF;
		s_page_tx_end_us = 0;
		s_page_on = true;
		memcpy(out, s_page_fhs_f, 32); memcpy(out + 32, s_page_resp2_f, 32);
		memcpy(out + 64, s_page_fhs[0], PAGE_FHS_BYTES);
		out[64 + PAGE_FHS_BYTES] = s_page_tx_cap;
		reply(sub, RL_OK, out, 65 + PAGE_FHS_BYTES);
		break;
	}
	case RL_RAW_DUMP: {
		if (s_raw_running || n > 1 || (n == 1 && a[0] >= s_cap_count)) { reply(sub, RL_ERR_DISALLOWED, NULL, 0); break; }
		if (!n) { out[0] = s_cap_count; reply(sub, RL_OK, out, 1); break; }
		wr32(out, s_cap_stamp[a[0]]); out[4] = s_cap_len;
		memcpy(out + 5, s_cap[a[0]], s_cap_len);
		reply(sub, RL_OK, out, (uint8_t)(5 + s_cap_len));
		break;
	}
	case RL_SCAN_RAW: {
		if (n || !s_scan_aa_enabled || !lab_ram_span((uint32_t)s_scan_state, 120)) {
			reply(sub, RL_ERR_DISALLOWED, NULL, 0); break;
		}
		/* get_rxed_buffer reads ls+92 as CPU list head. current_rx_info_get
		 * maps ls+8 low20 to RAM then subtracts4 to get current DMA header.
		 * Inspect candidates even if get_rxed_buffer returned no packet;
		 * never mark them done, advance the ring or change CRC handling. */
		const volatile uint32_t *state = (const volatile uint32_t *)s_scan_state;
		const uint32_t current = state[2] & 0xFFFFFu;
		const uint32_t heads[2] = { state[23], current >= 4 ? (SOC_DRAM_LOW | current) - 4u : 0 };
		memset(out, 0, 92);
		wr32(out, (uint32_t)state); wr32(out + 4, state[2]); wr32(out + 8, state[23]);
		for (unsigned i = 0; i < 2; ++i) {
			uint8_t *entry = out + 12 + 20 * i;
			wr32(entry, heads[i]);
			if (!lab_ram_span(heads[i], 12)) continue;
			const uint32_t offset = ((volatile uint32_t *)heads[i])[2] & 0xFFFFFu;
			wr16(entry + 18, 1);
			const uint32_t data = offset ? SOC_DRAM_LOW | offset : 0;
			wr32(entry + 4, data);
			if (!lab_ram_span(data, 32)) continue;
			const volatile uint8_t *bytes = (const volatile uint8_t *)data;
			wr32(entry + 8, *(const volatile uint32_t *)(bytes + 12));
			wr32(entry + 12, *(const volatile uint32_t *)(bytes + 24));
			wr16(entry + 16, bytes[28] | ((uint16_t)bytes[29] << 8));
			wr16(entry + 18, 3);
			/* Fixed SRAM sample, NOT a trusted packet-length copy. Tests
			 * must prove which bytes actually belong to the received frame. */
			if (lab_ram_span(data, 44)) {
				for (unsigned j = 0; j < 16; ++j) out[52 + 16*i + j] = bytes[28+j];
				wr16(entry + 18, 7);
			}
		}
		wr32(out + 84, state[0]); wr32(out + 88, state[5]);
		reply(sub, RL_OK, out, 92);
		break;
	}
	case RL_DTM_STATS: {
		if (n != 1 || a[0] > 6) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		if (a[0] == 6) {
			s_dtm_native_clock = true; s_dtm_awake = true;
			out[0] = 1; reply(sub, RL_OK, out, 1); break;
		}
		if (a[0] == 4 || a[0] == 5) {
			s_dtm_native_clock = false;
			s_dtm_awake = a[0] == 4;
			out[0] = s_dtm_awake;
			reply(sub, RL_OK, out, 1); break;
		}
		if (a[0] == 3) {
			/* Known register reads: LL clock in cis_c6_radio.c;
			 * 18fc/1900/1904 in dtm/scheduler code; IRQ words in PHY ISR. */
			static const uint32_t addresses[7] = {
				0x600A18FCu, 0x600A1900u, 0x600A1904u,
				0x600A1304u, 0x600A130Cu, 0x600A1314u, 0x600A131Cu,
			};
			wr32(out, s_dtm_sched_calls);
			wr32(out + 4, s_dtm_irqs);
			wr32(out + 8, *(volatile uint32_t *)0x600A1924u);
			wr32(out + 12, s_dtm_sched_address);
			wr32(out + 16, (uint32_t)s_dtm_state);
			for (unsigned i = 0; i < 7; ++i) wr32(out + 20 + 4 * i, *(volatile uint32_t *)addresses[i]);
			for (unsigned i = 0; i < 16; ++i) wr32(out + 48 + 4 * i, s_dtm_sched_words[i]);
			wr32(out + 112, s_dtm_awake);
			wr32(out + 116, s_dtm_sleep_skipped);
			reply(sub, RL_OK, out, 120);
			break;
		}
		if (a[0] != 1) s_dtm_capture = false;
		if (a[0] == 0) {
			s_dtm_sleep_skipped = 0;
			s_dtm_sched_calls = s_dtm_irqs = s_dtm_sched_address = 0;
			for (unsigned i = 0; i < 16; ++i) s_dtm_sched_words[i] = 0;
			s_dtm_state = NULL;
			s_dtm_resets = s_dtm_rx = s_dtm_status = 0;
			s_dtm_header = 0;
			for (unsigned i = 0; i < 16; ++i) s_dtm_words[i] = 0;
			s_dtm_capture = true;
		}
		wr32(out, s_dtm_resets);
		wr32(out + 4, s_dtm_rx);
		wr32(out + 8, s_dtm_status);
		wr16(out + 12, s_dtm_header);
		for (unsigned i = 0; i < 16; ++i) wr32(out + 14 + 4 * i, s_dtm_words[i]);
		reply(sub, RL_OK, out, 78);
		break;
	}
	case RL_SCAN_FLAGS: {
		if (n != 1 || a[0] > 5) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		if (a[0] != 2) s_scan_profile = a[0];
		out[0] = s_scan_profile;
		wr32(out + 1, s_scan_word20_before);
		wr32(out + 5, s_scan_word20_after);
		wr32(out + 9, s_scan_word0_before);
		wr32(out + 13, s_scan_word0_after);
		wr32(out + 17, s_scan_word36_before);
		wr32(out + 21, s_scan_word36_after);
		reply(sub, RL_OK, out, 25);
		break;
	}
	case RL_IRQ_STATS: {
		if (n != 1 || a[0] > 2) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		if (a[0] == 2) { /* reset with scanning stopped */
			s_irq_count = 0;
			for (unsigned bank = 0; bank < 2; ++bank) {
				s_irq_last[bank] = 0;
				for (unsigned bit = 0; bit < 32; ++bit) s_irq_bits[bank][bit] = 0;
			}
			reply(sub, RL_OK, NULL, 0);
		} else {
			out[0] = a[0];
			wr32(out + 1, s_irq_count);
			wr32(out + 5, s_irq_last[a[0]]);
			for (unsigned bit = 0; bit < 32; ++bit) wr32(out + 9 + bit * 4, s_irq_bits[a[0]][bit]);
			reply(sub, RL_OK, out, 137);
		}
		break;
	}
	case RL_SCAN_AA: {
		/* mode 0 restores defaults, 1 sets AA, 2 queries. Stop scan first. */
		if (n != 5 || a[0] > 2) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		if (a[0] != 2) {
			s_scan_aa_enabled = false;
			if (a[0] == 1) { s_scan_aa = rd32(a + 1); s_scan_aa_enabled = true; }
		}
		out[0] = s_scan_aa_enabled;
		wr32(out + 1, s_scan_aa);
		wr32(out + 5, s_scan_reset_count);
		wr32(out + 9, s_scan_applied_count);
		wr32(out + 13, s_scan_last_aa);
		wr32(out + 17, s_scan_rx_count);
		wr32(out + 21, s_scan_rx_buffer_count);
		wr32(out + 25, s_scan_rx_status);
		wr16(out + 29, s_scan_rx_header);
		reply(sub, RL_OK, out, 31);
		break;
	}
	case RL_CHANMAP: {
		if (n < 3) { reply(sub, RL_ERR_PARAM, NULL, 0); break; }
		s_remap_value = -1; /* dump the original table through the hook (verify_hooks: orig_* only inside hooks) */
		for (int i = 0; i < 40; i++) out[i] = r_ble_phy_chan_to_freq((uint8_t)i);
		s_remap_chan = a[0];
		s_remap_value = (int16_t)rd16(a + 1);
		reply(sub, RL_OK, out, 40);
		break;
	}
	case RL_RXFREQ:
		wr32(out, (uint32_t)phy_get_rx_freq(0, 0, 0, 0));
		reply(sub, RL_OK, out, 4);
		break;
	case RL_REBOOT:
		reply(sub, RL_OK, NULL, 0);
		vTaskDelay(pdMS_TO_TICKS(100));
		esp_restart();
		break;
	default:
		reply(sub, RL_ERR_PARAM, NULL, 0);
		break;
	}
}

static void lab_task(void *arg)
{
	(void)arg;
	lab_cmd_t c;
	for (;;) {
		if (xQueueReceive(s_queue, &c, pdMS_TO_TICKS(1000)) == pdTRUE) {
			s_busy = true;
			handle(c.data, c.len);
			s_busy = false;
		} else if ((s_br_mode || s_quiet) && esp_timer_get_time() - s_last_cmd_us > (int64_t)LAB_IDLE_EXIT_S * 1000000) {
			ESP_LOGW(TAG, "no lab command for %d s: leaving BR mode", LAB_IDLE_EXIT_S);
			exit_br();
		}
	}
}

void radio_lab_init(void)
{
	if (s_queue) return;
	s_queue = xQueueCreate(4, sizeof(lab_cmd_t));
	/* Below the BLE LL task priority in normal mode; HOP's busy loop runs only in BR mode (controller off). */
	xTaskCreate(lab_task, "radio_lab", 4096, NULL, configMAX_PRIORITIES - 3, NULL);
	ESP_LOGI(TAG, "radio lab v%d ready (HCI 0x%04X)", LAB_VERSION, RADIO_LAB_OPCODE);
}

bool radio_lab_br_mode(void) { return s_br_mode; }

bool radio_lab_h2c(const uint8_t *h4, uint16_t len)
{
	if (len < 1 || !s_queue) return false;
	const bool is_lab = h4[0] == H4_CMD && len >= 9 && len == 4u + h4[3] && rd16(&h4[1]) == RADIO_LAB_OPCODE &&
			    memcmp(&h4[4], k_magic, 4) == 0;
	if (is_lab && h4[8] == RL_PAGE && h4[3] >= 8 && h4[9] == 24) {
		/* 1.4.246 SBC frame push, no reply: magic(4) sub mode(24) n_frames frame_len frames... */
		const unsigned nf = h4[10], fl = h4[11];
		if (fl && fl <= SBC_FRAME_MAX && 12u + nf * fl <= len) {
			s_sbc_flen = (uint8_t)fl;
			for (unsigned i = 0; i < nf; ++i) {
				if (s_sbc_w - s_sbc_r >= SBC_RING_N) { ++s_sbc_drops; continue; }
				memcpy(s_sbc_ring[s_sbc_w % SBC_RING_N], h4 + 12 + i * fl, fl);
				s_sbc_len[s_sbc_w % SBC_RING_N] = (uint8_t)fl;
				s_sbc_w = s_sbc_w + 1u;
				++s_sbc_in;
			}
		}
		s_last_cmd_us = esp_timer_get_time();
		return true;
	}
	if (is_lab) {
		lab_cmd_t c;
		c.len = h4[3] > sizeof(c.data) ? sizeof(c.data) : h4[3];
		memcpy(c.data, &h4[4], c.len);
		if (s_busy && h4[8] != RL_STOP) {
			uint8_t ev[10] = { H4_EVT, 0x0E, 6, 1, (uint8_t)RADIO_LAB_OPCODE, (uint8_t)(RADIO_LAB_OPCODE >> 8),
					   RL_ERR_BUSY, LAB_VERSION, h4[8], 0 };
			slave_bt_send_to_host(ev, 9);
			return true;
		}
		if (xQueueSend(s_queue, &c, 0) != pdTRUE) {
			send_cmd_complete_raw(RADIO_LAB_OPCODE, RL_ERR_BUSY);
		}
		return true;
	}
	if (!s_br_mode) return false;
	/* BR mode: the BLE controller is off. Refuse commands, drop everything else. */
	if (h4[0] == H4_CMD && len >= 4) send_cmd_complete_raw(rd16(&h4[1]), RL_ERR_DISALLOWED);
	return true;
}
