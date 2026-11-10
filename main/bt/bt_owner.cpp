#include "bt/bt_owner.h"

#include <atomic>

#include "esp_hosted_cyberdeck.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

namespace bt_owner {
namespace {

constexpr const char* TAG = "bt_owner";

struct Hooks { ReleaseHook release = nullptr; BusyHook busy = nullptr; };
Hooks hooks[4];
std::atomic<Owner> owner{Owner::None};
SemaphoreHandle_t lock = nullptr;
portMUX_TYPE init_mux = portMUX_INITIALIZER_UNLOCKED;

SemaphoreHandle_t get_lock() {
    portENTER_CRITICAL(&init_mux);
    if (!lock) lock = xSemaphoreCreateRecursiveMutex();
    portEXIT_CRITICAL(&init_mux);
    return lock;
}

esp_hosted_cyberdeck_hci_owner_t router_owner(Owner o) {
    switch (o) {
        case Owner::NimBLE: return ESP_HOSTED_HCI_OWNER_NIMBLE;
        case Owner::LeAudio:
        case Owner::Lab: return ESP_HOSTED_HCI_OWNER_RAW;
        default: return ESP_HOSTED_HCI_OWNER_NONE;
    }
}

void stop_current() {
    const Owner old = owner.load();
    if (old == Owner::None) return;
    ESP_LOGI(TAG, "Releasing the controller from %s", name(old));
    if (ReleaseHook h = hooks[static_cast<int>(old)].release) h();
    owner = Owner::None;
    esp_hosted_cyberdeck_set_hci_owner(ESP_HOSTED_HCI_OWNER_NONE);
}

}  // namespace

void set_hooks(Owner o, ReleaseHook release, BusyHook busy) {
    if (o == Owner::None) return;
    hooks[static_cast<int>(o)] = Hooks{release, busy};
}

esp_err_t acquire(Owner want, const char* why) {
    SemaphoreHandle_t l = get_lock();
    if (!l) return ESP_ERR_NO_MEM;
    xSemaphoreTakeRecursive(l, portMAX_DELAY);
    if (owner.load() != want) {
        stop_current();
        if (want != Owner::None) {
            ESP_LOGI(TAG, "Controller to %s (%s)", name(want), why ? why : "");
            esp_hosted_cyberdeck_set_hci_owner(router_owner(want));
            owner = want;
        }
    }
    xSemaphoreGiveRecursive(l);
    return ESP_OK;
}

void release(Owner o) {
    SemaphoreHandle_t l = get_lock();
    if (!l) return;
    xSemaphoreTakeRecursive(l, portMAX_DELAY);
    if (owner.load() == o) stop_current();
    xSemaphoreGiveRecursive(l);
}

Owner current() { return owner.load(); }

bool owner_busy() {
    const Owner o = owner.load();
    if (o == Owner::None) return false;
    BusyHook h = hooks[static_cast<int>(o)].busy;
    return h && h();
}

const char* name(Owner o) {
    switch (o) {
        case Owner::NimBLE: return "NimBLE";
        case Owner::LeAudio: return "LE Audio";
        case Owner::Lab: return "radio lab";
        default: return "nobody";
    }
}

}  // namespace bt_owner
