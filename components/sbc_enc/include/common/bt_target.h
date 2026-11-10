/* Shim for the vendored Bluedroid SBC encoder (ESP-IDF 5.5.5 components/bt/host/bluedroid/external/sbc/encoder,
 * Apache-2.0): the configuration Bluedroid builds it with on ESP32 (bt_target.h), nothing else. */
#pragma once
#include <stdint.h>
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif
#define SBC_ENC_INCLUDED TRUE
#define SBC_NO_PCM_CPY_OPTION FALSE
#define SBC_FOR_EMBEDDED_LINUX TRUE
#define BT_BLE_DYNAMIC_ENV_MEMORY FALSE
#include <stdbool.h>
#define APPL_TRACE_EVENT(...) ((void)0)
