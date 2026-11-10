#pragma once
// Which BLE host owns the ESP32-C6 controller.
//
// The C6 runs one controller, and both BLE hosts on the P4 reset it and expect to own it: NimBLE (Meshtastic radios,
// workout stopwatch sync) and the LE Audio host (earbuds, components/p4_le_audio). The esp_hosted HCI router
// (components/espressif__esp_hosted/host/drivers/bt/vhci_drv.c) sends received packets to one of them and drops the
// other's transmissions. acquire() stops the current owner through its release hook, then switches the router.
//
// acquire() blocks for up to a few seconds (the release hooks close links over the air): call it from a task, never
// from the LVGL thread or an ISR.

#include "esp_err.h"

namespace bt_owner {

enum class Owner { None, NimBLE, LeAudio, Lab };  // Lab: radio lab (native A2DP), raw HCI channel

// Stops the host that owns the controller. Runs in the caller's task; must return only once that host sends nothing.
using ReleaseHook = void (*)();
// True while the owner is in the middle of something the user would notice losing (a connection, a sync, a stream).
using BusyHook = bool (*)();

void set_hooks(Owner owner, ReleaseHook release, BusyHook busy);

// Hands the controller to `want`. ESP_OK also when it already owns it. `why` is logged.
esp_err_t acquire(Owner want, const char* why);
// Gives the controller up if `owner` holds it (owner None afterwards).
void release(Owner owner);

Owner current();
// The current owner reports itself busy.
bool owner_busy();
const char* name(Owner owner);

}  // namespace bt_owner
