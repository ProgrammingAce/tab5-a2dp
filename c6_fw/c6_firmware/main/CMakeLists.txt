if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/common")
    set(common_dir "${CMAKE_CURRENT_SOURCE_DIR}/common")
else()
    set(common_dir "../../common")
endif()

set(COMPONENT_SRCS "slave_control.c" "${common_dir}/proto/esp_hosted_rpc.pb-c.c" "protocomm_pserial.c" "app_main.c" "slave_bt.c" "mempool.c" "stats.c"  "mempool_ll.c" "fw_guard.c" "fw_guard_policy.c" "radio_lab.c")
set(COMPONENT_ADD_INCLUDEDIRS "." "${common_dir}" "${common_dir}/log" "${common_dir}/proto" "${common_dir}/rpc" "${common_dir}/transport")

# Select BT UART code based on IDF Target
if(CONFIG_IDF_TARGET_ESP32)
    list(APPEND COMPONENT_SRCS slave_bt_uart_esp32.c)
elseif(CONFIG_IDF_TARGET_ESP32C3 OR CONFIG_IDF_TARGET_ESP32S3)
    list(APPEND COMPONENT_SRCS slave_bt_uart_esp32c3_s3.c)
else()
    list(APPEND COMPONENT_SRCS slave_bt_uart_esp32xx.c)
endif()

if(CONFIG_ESP_SDIO_HOST_INTERFACE)
    list(APPEND COMPONENT_SRCS sdio_slave_api.c)
elseif(CONFIG_ESP_SPI_HOST_INTERFACE)
    list(APPEND COMPONENT_SRCS spi_slave_api.c)
elseif(CONFIG_ESP_SPI_HD_MODE)
    list(APPEND COMPONENT_SRCS spi_hd_slave_api.c)
else(CONFIG_ESP_UART_HOST_INTERFACE)
    list(APPEND COMPONENT_SRCS uart_slave_api.c)
endif()

# CIS engine compiled from its single source, <repo>/cis_ll (no copy), plus the C6 adapters.
set(cis_ll_dir "${CMAKE_CURRENT_SOURCE_DIR}/../../cis_ll")
if(CONFIG_BT_ENABLED AND CONFIG_IDF_TARGET_ESP32C6)
    list(APPEND COMPONENT_SRCS "${cis_ll_dir}/cis_engine.c" "${cis_ll_dir}/cis_proto.c" "${cis_ll_dir}/cis_crypto.c"
        "cis_c6_core.c" "cis_c6_radio.c" "cis_c6_llcp.c" "cis_c6_crash.c" "cis_c6_hang.c")
    list(APPEND COMPONENT_ADD_INCLUDEDIRS "${cis_ll_dir}")
endif()

# Classic BR baseband library (pure C99) from the enclosing tab5 repo: <tab5>/components/br_baseband (no copy).
# Used by the radio lab's page test to build FHS packets on the C6. Only the packet/hop parts are needed.
set(br_dir "${CMAKE_CURRENT_SOURCE_DIR}/../../../components/br_baseband")
if(EXISTS "${br_dir}/src/br_packet.c")
    foreach(f br_bits br_access_code br_crc br_whiten br_fec br_header br_packet br_hop br_e0 br_fast)
        list(APPEND COMPONENT_SRCS "${br_dir}/src/${f}.c")
    endforeach()
    list(APPEND COMPONENT_ADD_INCLUDEDIRS "${br_dir}/include")
else()
    message(FATAL_ERROR "br_baseband not found at ${br_dir} (c6_fw must sit inside the tab5 repo)")
endif()

register_component()

# 1.4.244: per-slot E0 masks and the TX hook's payload build run at slot rate; IDF builds -Os by default
set_source_files_properties("${br_dir}/src/br_fast.c" PROPERTIES COMPILE_OPTIONS "-O2")

# Add directory of protocomm_priv.h to include paths
idf_component_get_property(protocomm_dir protocomm COMPONENT_DIR)
target_include_directories(${COMPONENT_LIB} PRIVATE "${protocomm_dir}/src/common")
