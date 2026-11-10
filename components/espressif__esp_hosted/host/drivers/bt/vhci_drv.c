// Copyright 2015-2024 Espressif Systems (Shanghai) PTE LTD
/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */

#include <stdint.h>
#include <string.h>

#include "esp_hosted_transport.h"
#include "os_wrapper.h"
#include "transport_drv.h"

#include "hci_drv.h"
#include "esp_hosted_cyberdeck.h"

#if H_BT_HOST_ESP_NIMBLE
#include "host/ble_hs_mbuf.h"
#include "os/os_mbuf.h"
#include "nimble/transport.h"
#include "nimble/transport/hci_h4.h"
#include "nimble/hci_common.h"
#endif

#if H_BT_HOST_ESP_BLUEDROID
#include "esp_hosted_bt.h"
#endif

#include "esp_hosted_log.h"
static const char TAG[] = "vhci_drv";

/* Phosphor HCI router: the C6 controller serves one BLE host at a time. NimBLE (Meshtastic, workout sync) uses the
 * stock VHCI path below; the LE Audio host (p4_le_audio) uses the raw H4 channel, which also carries HCI ISO (0x05)
 * packets that the NimBLE path drops. The owner decides where received packets go and which side may transmit; the
 * application switches it only after the previous host has stopped (see main/bt/bt_owner.cpp). */
static volatile esp_hosted_cyberdeck_hci_owner_t s_owner = ESP_HOSTED_HCI_OWNER_NONE;
static esp_hosted_cyberdeck_hci_rx_cb_t s_raw_rx_cb = NULL;
static volatile uint32_t s_dropped_rx = 0, s_dropped_tx = 0;

void esp_hosted_cyberdeck_set_hci_owner(esp_hosted_cyberdeck_hci_owner_t owner)
{
	s_owner = owner;
	ESP_LOGI(TAG, "HCI owner: %s", owner == ESP_HOSTED_HCI_OWNER_RAW ? "raw (LE Audio)" :
		 owner == ESP_HOSTED_HCI_OWNER_NIMBLE ? "NimBLE" : "none");
}

esp_hosted_cyberdeck_hci_owner_t esp_hosted_cyberdeck_get_hci_owner(void)
{
	return s_owner;
}

void esp_hosted_cyberdeck_hci_drops(uint32_t *rx, uint32_t *tx)
{
	if (rx) *rx = s_dropped_rx;
	if (tx) *tx = s_dropped_tx;
}

void esp_hosted_cyberdeck_set_hci_rx_cb(esp_hosted_cyberdeck_hci_rx_cb_t cb)
{
	s_raw_rx_cb = cb;
}

esp_hosted_cyberdeck_hci_rx_cb_t esp_hosted_cyberdeck_get_hci_rx_cb(void)
{
	return s_raw_rx_cb;
}

int esp_hosted_cyberdeck_hci_tx(const uint8_t *data, uint16_t len)
{
	if (!data || !len) {
		return ESP_FAIL;
	}
	if (s_owner != ESP_HOSTED_HCI_OWNER_RAW) {
		s_dropped_tx++;
		return ESP_FAIL;
	}
	/* The copy that lives while queued goes to PSRAM: the SDIO write task copies it into the transport buffer
	 * anyway (H_BUFF_NO_ZEROCOPY), and an LE Audio stream is ~100-200 packets/s. */
	uint8_t *ptr = MEM_ALLOC_PREFER_PSRAM(len);
	if (!ptr) {
		return ESP_FAIL;
	}
	memcpy(ptr, data, len);
	return esp_hosted_tx(ESP_HCI_IF, 0, ptr, len, H_BUFF_NO_ZEROCOPY, H_DEFLT_FREE_FUNC);
}

/* Raw owner: every packet type, including ISO, to the LE Audio host (in the SDIO receive thread). */
static int hci_rx_raw(interface_buffer_handle_t *buf_handle)
{
	esp_hosted_cyberdeck_hci_rx_cb_t cb = s_raw_rx_cb;
	if (cb && buf_handle && buf_handle->payload && buf_handle->payload_len) {
		cb(buf_handle->payload, buf_handle->payload_len);
	}
	return ESP_OK;
}

#if H_BT_HOST_ESP_NIMBLE
#define BLE_HCI_EVENT_HDR_LEN               (2)
#define BLE_HCI_CMD_HDR_LEN                 (3)
#endif

void hci_drv_init(void)
{
	// do nothing for VHCI: underlying transport should be ready
}

void hci_drv_show_configuration(void)
{
	ESP_LOGI(TAG, "Host BT Support: Enabled");
	ESP_LOGI(TAG, "\tBT Transport Type: VHCI");
}

#if H_BT_HOST_ESP_NIMBLE
/**
 * HCI_H4_xxx is the first byte of the received data
 */
int hci_rx_handler(interface_buffer_handle_t *buf_handle)
{
	if (s_owner == ESP_HOSTED_HCI_OWNER_RAW) {
		return hci_rx_raw(buf_handle);
	}
	if (s_owner != ESP_HOSTED_HCI_OWNER_NIMBLE) {
		s_dropped_rx++;
		return ESP_OK;
	}
	uint8_t * data = buf_handle->payload;
	uint32_t len_total_read = buf_handle->payload_len;

	int rc;

	if (data[0] == HCI_H4_EVT) {
		uint8_t *evbuf;
		int totlen;

		totlen = BLE_HCI_EVENT_HDR_LEN + data[2];
		if (totlen > UINT8_MAX + BLE_HCI_EVENT_HDR_LEN) {
			ESP_LOGE(TAG, "Rx: len[%d] > max INT [%d], drop",
					totlen, UINT8_MAX + BLE_HCI_EVENT_HDR_LEN);
			return ESP_FAIL;
		}

		if (totlen > MYNEWT_VAL(BLE_TRANSPORT_EVT_SIZE)) {
			ESP_LOGE(TAG, "Rx: len[%d] > max BLE [%d], drop",
					totlen, MYNEWT_VAL(BLE_TRANSPORT_EVT_SIZE));
			return ESP_FAIL;
		}

		if (data[1] == BLE_HCI_EVCODE_HW_ERROR) {
			ESP_LOGE(TAG, "Rx: HW_ERROR");
			return ESP_FAIL;
		}

		/* Allocate LE Advertising Report Event from lo pool only */
		if ((data[1] == BLE_HCI_EVCODE_LE_META) &&
			(data[3] == BLE_HCI_LE_SUBEV_ADV_RPT || data[3] == BLE_HCI_LE_SUBEV_EXT_ADV_RPT)) {
			evbuf = ble_transport_alloc_evt(1);
			/* Skip advertising report if we're out of memory */
			if (!evbuf) {
				ESP_LOGW(TAG, "Rx: Drop ADV Report Event: NimBLE OOM (not fatal)");
				return ESP_FAIL;
			}
		} else {
			evbuf = ble_transport_alloc_evt(0);
			if (!evbuf) {
				ESP_LOGE(TAG, "Rx: failed transport_alloc_evt(0)");
				return ESP_FAIL;
			}
		}

		memset(evbuf, 0, sizeof * evbuf);
		memcpy(evbuf, &data[1], totlen);

		rc = ble_transport_to_hs_evt(evbuf);
		if (rc) {
			ESP_LOGE(TAG, "Rx: transport_to_hs_evt failed");
			return ESP_FAIL;
		}
	} else if (data[0] == HCI_H4_ACL) {
		struct os_mbuf *m = NULL;

		m = ble_transport_alloc_acl_from_ll();
		if (!m) {
			ESP_LOGE(TAG, "Rx: alloc_acl_from_ll failed");
			return ESP_FAIL;
		}

		if ((rc = os_mbuf_append(m, &data[1], len_total_read - 1)) != 0) {
			ESP_LOGE(TAG, "Rx: failed os_mbuf_append; rc = %d", rc);
			os_mbuf_free_chain(m);
			return ESP_FAIL;
		}

		ble_transport_to_hs_acl(m);
	}
	return ESP_OK;
}

/**
 * ESP NimBLE expects these interfaces for Tx
 *
 * For doing non-zero copy:
 * - transport expects the HCI_H4_xxx type to be the first byte of the
 *   data stream
 *
 * For doing zero copy:
 * - fill in esp_paylod_header and payload data
 * - HCI_H4_xxx type should be set in esp_payload_header.hci_pkt_type
 */

#if H_BT_ENABLE_LL_INIT
void ble_transport_ll_init(void)
{
	/* Phosphor: the application brings the transport up before nimble_port_init (shared with Wi-Fi and the LE
	 * Audio host); a transport that is down here must not abort the firmware. */
	if (transport_drv_reconfigure() != ESP_OK) {
		ESP_LOGE(TAG, "NimBLE start: transport to the co-processor is down");
	}
}

/* Called by nimble_port_deinit (IDF 5.5). The transport stays up for Wi-Fi and the LE Audio host. */
void ble_transport_ll_deinit(void)
{
}
#endif

int ble_transport_to_ll_acl_impl(struct os_mbuf *om)
{
	// TODO: zerocopy version

	// calculate data length from the incoming data
	int data_len = OS_MBUF_PKTLEN(om) + 1;

	uint8_t * data = NULL;
	int res;

	if (s_owner != ESP_HOSTED_HCI_OWNER_NIMBLE) {
		s_dropped_tx++;
		res = ESP_FAIL;
		goto exit;
	}

	data = MEM_ALLOC(data_len);
	if (!data) {
		ESP_LOGE(TAG, "Tx %s: malloc failed", __func__);
		res = ESP_FAIL;
		goto exit;
	}

	data[0] = HCI_H4_ACL;
	res = ble_hs_mbuf_to_flat(om, &data[1], OS_MBUF_PKTLEN(om), NULL);
	if (res) {
		ESP_LOGE(TAG, "Tx: Error copying HCI_H4_ACL data %d", res);
		res = ESP_FAIL;
		goto exit;
	}

	res = esp_hosted_tx(ESP_HCI_IF, 0, data, data_len, H_BUFF_NO_ZEROCOPY, H_DEFLT_FREE_FUNC);

 exit:
	os_mbuf_free_chain(om);

	return res;
}

int ble_transport_to_ll_cmd_impl(void *buf)
{
	// TODO: zerocopy version

	// calculate data length from the incoming data
	int buf_len = 3 + ((uint8_t *)buf)[2] + 1;

	uint8_t * data = NULL;
	int res;

	if (s_owner != ESP_HOSTED_HCI_OWNER_NIMBLE) {
		s_dropped_tx++;
		res = ESP_FAIL;
		goto exit;
	}

	data = MEM_ALLOC(buf_len);
	if (!data) {
		ESP_LOGE(TAG, "Tx %s: malloc failed", __func__);
		res =  ESP_FAIL;
		goto exit;
	}

	data[0] = HCI_H4_CMD;
	memcpy(&data[1], buf, buf_len - 1);

	res = esp_hosted_tx(ESP_HCI_IF, 0, data, buf_len, H_BUFF_NO_ZEROCOPY, H_DEFLT_FREE_FUNC);

 exit:
	ble_transport_free(buf);

	return res;
}
#endif // H_BT_HOST_ESP_NIMBLE

#if H_BT_HOST_ESP_BLUEDROID
static esp_bluedroid_hci_driver_callbacks_t s_callback = { 0 };

int hci_rx_handler(interface_buffer_handle_t *buf_handle)
{
	uint8_t * data = buf_handle->payload;
	uint32_t len_total_read = buf_handle->payload_len;

	if (s_callback.notify_host_recv) {
		s_callback.notify_host_recv(data, len_total_read);
	}

	return ESP_FAIL;
}

void hosted_hci_bluedroid_open(void)
{
	ESP_ERROR_CHECK(transport_drv_reconfigure());
}

void hosted_hci_bluedroid_close(void)
{
}

esp_err_t hosted_hci_bluedroid_register_host_callback(const esp_bluedroid_hci_driver_callbacks_t *callback)
{
	s_callback.notify_host_send_available = callback->notify_host_send_available;
	s_callback.notify_host_recv = callback->notify_host_recv;

	return ESP_OK;
}

void hosted_hci_bluedroid_send(uint8_t *data, uint16_t len)
{
	int res;
	uint8_t * ptr = NULL;

	ptr = MEM_ALLOC(len);
	if (!ptr) {
		ESP_LOGE(TAG, "%s: malloc failed", __func__);
		return;
	}
	memcpy(ptr, data, len);

	res = esp_hosted_tx(ESP_HCI_IF, 0, ptr, len, H_BUFF_NO_ZEROCOPY, H_DEFLT_FREE_FUNC);

	if (res) {
		ESP_LOGE(TAG, "%s: Tx failed", __func__);
	}
}

bool hosted_hci_bluedroid_check_send_available(void)
{
	return true;
}

#endif // H_BT_HOST_ESP_BLUEDROID
