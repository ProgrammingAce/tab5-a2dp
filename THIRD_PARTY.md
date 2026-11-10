# Source provenance and third-party notices

This folder is a source snapshot for an independent Tab5 A2DP demonstration.
Source revisions and the carried C6 binary hash are in `firmware/provenance.json`.
No git history, credentials, bonds, RF captures, or build artifacts are needed.

- `components/espressif__esp_hosted`: Espressif ESP-Hosted 1.4.0, Apache-2.0,
  locally patched. See its `LICENSE` and `PATCHES.md`.
- `components/sbc_enc`: SBC encoder from ESP-IDF 5.5.5 / Bluedroid,
  Apache-2.0. Original copyright/license headers are retained; see its README.
- `c6_fw`: source from the Tab5 fork of Ernest Domaradzki's
  esp32-p4-c6-le-audio, including MIT project code and Espressif Apache-2.0
  ESP-Hosted sources. `c6_fw/LICENSE` and `c6_fw/NOTICE` are retained verbatim.
  The upstream NOTICE describes the larger upstream distribution; some listed
  optional components are not included in this smaller snapshot.
- Embedded protobuf-c sources retain their BSD license files and headers.
- The C6 application binary incorporates ESP-IDF controller and PHY libraries.
  Their upstream notices and terms are supplied with ESP-IDF 5.5.5, including
  `components/bt/controller/lib_esp32c6`.
- M5Stack Tab5 BSP, Wi-Fi Remote and transitive dependencies are resolved from
  the ESP Component Registry and retain their own licenses.

The extracted application and Classic implementation retain their existing
headers. No blanket project license is newly granted by this extraction.
