idf_component_register(
    SRCS "main.cpp" "ui.cpp" "bt/a2dp_native.cpp" "bt/radio_lab.cpp" "bt/bt_owner.cpp"
    INCLUDE_DIRS "."
    REQUIRES lvgl esp_lvgl_port esp_wifi esp_wifi_remote m5stack_tab5 espressif__esp_hosted br_baseband sbc_enc
             nvs_flash esp_timer esp_driver_usb_serial_jtag)
