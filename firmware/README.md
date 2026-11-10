# Prebuilt firmware

| File | What it is | Flash |
| --- | --- | --- |
| `network_adapter.bin` | Custom C6 application image **1.4.252** | C6 installer (below) |
| `p4/bootloader.bin` | P4 bootloader | `0x2000` |
| `p4/partition-table.bin` | Partition table (`partitions.csv`) | `0x8000` |
| `p4/ota_data_initial.bin` | OTA data (boots `ota_0`) | `0xf000` |
| `p4/tab5_a2dp_demo.bin` | P4 demo application | `0x20000` |
| `p4/flash_args` | The four P4 files above for `esptool write_flash "@flash_args"` | |
| `p4/tab5_a2dp_demo_merged.bin` | Same P4 build as one image; erases the NVS bond | `0x0` |

All SHA-256 sums are in `SHA256SUMS`; `provenance.json` records the sources and
ESP-IDF version. P4 flashing commands are in the [main README](../README.md#flash-the-prebuilt-firmware).

## ESP32-C6 image

`network_adapter.bin` is the custom **1.4.252** C6 application image used by
this POC: the exact image installed and confirmed on the development Tab5. It is
an application image, not a merged full-flash image and not P4 firmware.
1.4.247-1.4.251 add long-FHS paging (`page r2skip`, `page r2late`), an
FHS-anchored connection slot grid, link diagnostics (`page t3`, `page diag`) and
the late-hook central slot skip (`page lateskip`); 1.4.252 stores each SBC
frame's length so the host can change the bitpool mid-stream. The P4 demo
enables all of them.

From this directory, verify it with:

```sh
shasum -a 256 -c SHA256SUMS
```

The C6 image must be installed and confirmed before running the P4 demo. Use a
compatible ESP-Hosted 1.4 C6 installer or provision the C6 over its UART
interface. The demo itself does not implement C6 OTA.

A stock ESP-Hosted 2.x C6 requires a separate migration procedure; a 1.4 OTA
host cannot activate a 2.x update. For a fresh board, use a compatible C6
installer or C6 UART recovery with the bootloader, partition table and
application produced by the C6 build. Do not write this application binary alone
to flash offset zero. The board's C6 UART pads and partition layout must be
handled by that installer. C6 provisioning is a prerequisite for running the
demo.

## Rebuild the C6 source

Activate ESP-IDF 5.5.5. From the project root:

```sh
cd c6_fw/c6_firmware
sh test/run_host_tests.sh
sh ../cis_ll/test/run.sh
idf.py -DIDF_TARGET=esp32c6 -DSDKCONFIG_DEFAULTS=sdkconfig.release build
python3 cmake/verify_hooks.py \
  --elf build/network_adapter.elf --map build/network_adapter.map \
  --hooks cmake/ble_hooks.txt \
  --orig-lib "$IDF_PATH/components/bt/controller/lib_esp32c6/esp32c6-bt-lib/esp32c6/libble_app.a"
```

The hook checker must finish with `RESULT: PASS` before an image is installed.
`sdkconfig.release` preserves the source snapshot's known configuration;
generated `sdkconfig` and build output are ignored. Rebuilding may change image
hashes due to build metadata. Replacing the shipped binary requires updating its
checksum and validating it on hardware. Installation must be an explicit user
action.

The retained C6 firmware has a trial/rollback guard. A newly installed image
must be confirmed through a compatible installer and healthy host traffic; do
not assume an unconfirmed image will stay installed.
