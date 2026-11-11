#include <cstdio>
#include <cstring>

#include "bsp/m5stack_tab5.h"
#include "bt/a2dp_native.h"
#include "driver/usb_serial_jtag.h"
#include "esp_hosted.h"
#include "esp_hosted_cyberdeck.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "ui.h"

static void help() {
    std::puts("\nTab5 native Bluetooth Classic / A2DP demo\n"
              "Put headphones in pairing mode, then: a2dp find, a2dp list, a2dp pair <n | address>\n"
              "(or a2dp pair: pair the first audio device found)\n"
              "After streaming starts: a2dp tone 440 | a2dp tone off | a2dp status | a2dp stop\n"
              "Saved headphones: a2dp list | a2dp connect [n] | a2dp forget <n> | Boot reconnect: a2dp auto 1\n"
              "Diagnostics: a2dp diag | a2dp chans | BR modulation: a2dp brmod <hex|0>\n"
              "Stop the link before resetting or flashing. Type help to repeat.");
}

extern "C" void app_main() {
    // Preserve the original firmware's NVS (including a2dpn peer/link key).
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(bsp_i2c_init());
    QueueHandle_t commands = xQueueCreate(8, sizeof(demo_ui::Command));
    ESP_ERROR_CHECK(commands ? ESP_OK : ESP_ERR_NO_MEM);
    demo_ui::start(commands);
    ESP_ERROR_CHECK(bsp_feature_enable(BSP_FEATURE_WIFI, true));
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_err_t radio_error = esp_hosted_init();
    if (radio_error == ESP_OK) radio_error = esp_hosted_cyberdeck_connect(30000);

    usb_serial_jtag_driver_config_t usb = {};
    usb.rx_buffer_size = 1024;
    usb.tx_buffer_size = 1024;
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&usb));
    a2dp_native::init();
    demo_ui::transport(radio_error == ESP_OK, radio_error == ESP_OK ? "Radio ready" : esp_err_to_name(radio_error));
    help();

    char line[192];
    size_t used = 0;
    bool overflow = false;
    while (true) {
        demo_ui::Command command{};
        if (xQueueReceive(commands, &command, 0) == pdTRUE) a2dp_native::command(command.text);
        char ch;
        if (usb_serial_jtag_read_bytes(&ch, 1, pdMS_TO_TICKS(50)) <= 0) continue;
        if (ch == '\r' || ch == '\n') {
            if (overflow) std::puts("Command too long; discarded.");
            else if (used) {
                line[used] = '\0';
                if (!std::strncmp(line, "a2dp", 4) && (line[4] == ' ' || line[4] == '\0'))
                    a2dp_native::command(line);
                else help();
            }
            used = 0;
            overflow = false;
        } else if (ch == '\b' || ch == 127) {
            if (used) --used;
        } else if (ch >= 32 && ch < 127 && !overflow) {
            if (used + 1 < sizeof(line)) line[used++] = ch;
            else overflow = true;
        }
    }
}
