/*
 * Tab5 native A2DP: radio lab (A2DP_NATIVE_BUILD_PLAN.md, tasks T0.3, T1.1-T1.4).
 *
 * Vendor HCI command 0xFFE0 (OGF 0x3F, OCF 0x3E0) with the magic "BRL1" followed by a subcommand byte. The lab can
 * take the radio away from Wi-Fi and the BLE controller (BR mode), drive it through the PHY RF-test API and the
 * internal frequency-override functions, and return measurements over HCI - the SDIO link stays up throughout.
 *
 * Replies: an HCI Command Complete for 0xFFE0 with return parameters
 *     status, LAB_VERSION, subcommand, data...
 * Long tests (TONE with a duration, HOP, RX_COUNT, BLE_TX) first answer status RL_STARTED, then send a vendor event
 *     0xFF: 'B' 'R' 'L' '1' subcommand status data...
 * Multi-byte fields are little endian. See radio_lab.c for each subcommand's parameters.
 *
 * Safety:
 *  - BR mode is refused while the image is on fw_guard trial (it needs BLE up to confirm itself).
 *  - In BR mode every other HCI command from the host gets Command Complete "Command Disallowed" (0x0C) and ACL is
 *    dropped, so nothing reaches the disabled controller.
 *  - BR mode ends by itself after LAB_IDLE_EXIT_S seconds without a lab command.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#define RADIO_LAB_OPCODE 0xFFE0
#define LAB_VERSION 1
#define LAB_IDLE_EXIT_S 120

enum {
	RL_OK = 0x00,
	RL_STARTED = 0x01,
	RL_ERR_PARAM = 0x12,     /* HCI "Invalid HCI Command Parameters" */
	RL_ERR_DISALLOWED = 0x0C,/* HCI "Command Disallowed" */
	RL_ERR_TRIAL = 0xE0,     /* image on fw_guard trial: BR mode refused */
	RL_ERR_BUSY = 0xE1,      /* a long test is running */
	RL_ERR_RANGE = 0xE2,     /* address outside the allowed peek/poke window */
	RL_ERR_INTERNAL = 0xE3,
};

enum {
	RL_PING = 0x00,
	RL_ENTER_BR = 0x01,
	RL_EXIT_BR = 0x02,
	RL_TONE = 0x03,
	RL_STOP = 0x04,
	RL_HOP = 0x05,
	RL_RX_COUNT = 0x06,
	RL_PEEK = 0x07,
	RL_POKE = 0x08,
	RL_CALL = 0x09,
	RL_RXFREQ = 0x0A,
	RL_BLE_TX = 0x0B,
	RL_FORCE = 0x0C,   /* allowed outside BR mode: phy_force_freq_set(en, mhz) under the running BLE controller */
	RL_CHANMAP = 0x0D, /* allowed outside BR mode: read the controller's channel->frequency table, remap one channel */
	RL_SCAN_AA = 0x0E, /* mode u8 + AA u32: 0 default, 1 override, 2 query; scan stopped when changing */
	RL_REBOOT = 0x0F,
	RL_RAW_MATCH = 0x14, /* ms u16, expected DMA u32; unique timestamp/full-word counts event */
	RL_QUIET = 0x15, /* bool: stop Wi-Fi while keeping BLE controller; exit/release restores Wi-Fi */
	RL_DTM_TRAIN = 0x19, /* G5 inquiry train for dtmhop rx: mode 0 = config n u8 (0 off,16,32), repeats u16;
	                        mode 1 = load offset u8, count u8 (<=16), tx[count], rx[count] (MHz-2402); n=0 query */
	RL_PAGE = 0x1A, /* T4.2 page reaction: mode 0 off+clear; 1 = target LAP u24, UAP u8, own LAP u24, UAP u8, NAP u16,
	                   CoD u24, CLK27_2 u32 (builds 32 FHS); 2 = query counters (+1.4.224 actual FHS/resp2 starts, xfix);
	                   3 = forced test X; 4 = TX end us; 5 = fixed reaction X u8 (0xFF off); 6 = kick period u16 pairs (emulated reaction, 0 off);
	                   7 = resp2 RX ls44 u32 (0 = dtmhop value);
	                   8 = detection path u8 (0 ls+8 buffer at the TX hook, 1 rxed-buffer hook, 2 buffer saved at the RX hook, 3 rawmatch worker flag;
	                   needs a running `lab rawmatch` window); 10 trace; 11 = detection compare mask u32 (0 = all);
	                   12 = arm connection: own LAP u24, UAP u8, slots u16 [, conn rxmax u8, conn ls44 u16] (1.4.233/234);
	                   13 = connection counters; 14 = connection packet log entry (index u8);
	                   16 = LMP queue: idx u8, start slot u16 (65535 ASAP), repeat u8, seqn u8, PDU (1..17 bytes) (1.4.239/241);
	                   17 = E0 encryption: on u8, Kc' 16, central BD_ADDR 6 (1.4.242);
	                   18 = like 16 with LLID u8 before the data (1 L2CAP cont., 2 L2CAP start, 3 LMP) (1.4.243); 17 = encryption mode 0 off / 1 RX+TX / 2 RX only (1.4.244); 19 = ACL FIFO push (tag, type, LLID, data), 20 = FIFO mode on/off + first SEQN, 21 = A2DP stream test (built-in SBC beep) (1.4.244, ARQ both ways); 9 = rxed log query; 10 = arming trace query (1.4.227);
	                   24 = r2skip u8: enter the link without resp2, FHS length byte 56..80 allowed, provisional link falls back
	                   to paging after 12 silent central slots (1.4.247); 25 = r2late u16 us: RX after a long FHS late, first
	                   central TX early by the same amount (1.4.248); 26 = long-FHS timing log + central-slot phase histogram
	                   (1.4.248/249); 27 = diagnostics query (hook latency, event jumps, late skips), n=2 resets (1.4.250);
	                   28 = lateskip u16 us: a central TX whose hook runs later than this after the previous start is armed one
	                   central slot later instead of sliding into the peripheral's slot (1.4.251, 0 = off). Needs dtmraw 2 +
	                   dtmtrain + dtmhop rx */
	RL_RAW_DUMP = 0x18, /* n=0: count u8; n=1 index u8: timestamp u32, length u8, bytes after the AA (rawmatch capture) */
	RL_DTM_HOP = 0x17, /* G4: f1 u8, f2 u8 (MHz-2402, 0xFF keep), interval us u16 (0 keep), on u8 [, rx u8, early us u8,
	                      window us u16: TX f1 / RX f2 alternating at 625 us]; n=0 query;
	                      n=3: 0xFE, TX lead u16 us (1.4.228; 0 native, 40..600: item+44 = start - lead for TX events) */
	RL_DTM_RAW = 0x16, /* mode0off/1customAA/2customAA+TXtail, AA u32, tail u32; stop DTM before change */
	RL_SCAN_RAW = 0x13, /* read-only scan RX DMA candidate status/header, including unfinished buffers */
	RL_DTM_STATS = 0x12, /* 0 clear+enable capture, 1 query, 2 disable; DTM/scan stopped to change */
	RL_SCAN_FLAGS = 0x11, /* 0/1 configure DTM word+20 bit27, 2 query; scan stopped to change */
	RL_IRQ_STATS = 0x10, /* bank 0/1 query ISR bit counters; 2 reset while scan stopped */
};

/* Starts the lab task. Call once from app_main after Bluetooth is initialised. */
void radio_lab_init(void);

/* From the SDIO receive path, before the CIS engine: true = the lab consumed the packet (h4[0] = H4 type). */
bool radio_lab_h2c(const uint8_t *h4, uint16_t len);

/* true while the lab owns the radio. */
bool radio_lab_br_mode(void);
