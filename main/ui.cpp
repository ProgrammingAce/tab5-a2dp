#include "ui.h"
#include <cstdio>
#include <cstring>
#include "bsp/m5stack_tab5.h"
#include "bt/a2dp_native.h"
#include "esp_log.h"
#include "lvgl.h"

namespace demo_ui {
namespace {
QueueHandle_t commands;
lv_obj_t *state_label, *peer_label, *detail_label, *tone_label, *device_list;
lv_obj_t *connect_btn, *scan_btn, *stop_btn, *tone_btn;
bool radio_ready = false;
char radio_message[96] = "Starting the radio...";
char list_signature[1024] = "";
char row_cmd[a2dp_native::kMaxSaved + a2dp_native::kMaxFound][40];  // console command per list row
constexpr uint32_t bg = 0x0b1220, panel = 0x162235, ink = 0xeaf2fb, muted = 0x99adc5, accent = 0x50dfc3;

void send(const char* text) {
    Command cmd{};
    std::snprintf(cmd.text, sizeof cmd.text, "%s", text);
    if (xQueueSend(commands, &cmd, 0) != pdTRUE) ESP_LOGW("demo_ui", "Command queue full");
}
void click(lv_event_t* e) {
    const char* action = static_cast<const char*>(lv_event_get_user_data(e));
    if (!std::strcmp(action, "tone")) send(a2dp_native::status().tone_hz ? "a2dp tone off" : "a2dp tone 440");
    else if (!std::strcmp(action, "stop")) { send("a2dp tone off"); send("a2dp stop"); }
    else send(action);
    ESP_LOGI("demo_ui", "Touch action: %s", action);
}
// A found device pairs (a2dp pair <address>), a saved one connects (a2dp connect <n>).
void choose(lv_event_t* e) { send(row_cmd[reinterpret_cast<intptr_t>(lv_event_get_user_data(e))]); }
lv_obj_t* label(lv_obj_t* parent, const char* text, int x, int y, int width, const lv_font_t* font, uint32_t color = ink) {
    auto* l = lv_label_create(parent);
    lv_label_set_text(l, text);
    lv_obj_set_pos(l, x, y);
    lv_obj_set_width(l, width);
    lv_obj_set_style_text_font(l, font, 0);
    lv_obj_set_style_text_color(l, lv_color_hex(color), 0);
    return l;
}
lv_obj_t* card(lv_obj_t* root, int x, int y, int w, int h) {
    auto* c = lv_obj_create(root);
    lv_obj_set_pos(c, x, y); lv_obj_set_size(c, w, h);
    lv_obj_set_style_bg_color(c, lv_color_hex(panel), 0);
    lv_obj_set_style_border_width(c, 0, 0);
    lv_obj_set_style_radius(c, 20, 0);
    lv_obj_set_style_pad_all(c, 24, 0);
    lv_obj_remove_flag(c, LV_OBJ_FLAG_SCROLLABLE);
    return c;
}
lv_obj_t* button(lv_obj_t* parent, const char* title, const char* action, int x, int y, int w, bool primary = false) {
    auto* b = lv_button_create(parent);
    lv_obj_set_pos(b, x, y); lv_obj_set_size(b, w, 64);
    lv_obj_set_style_radius(b, 12, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_bg_color(b, lv_color_hex(primary ? accent : 0x2a3d56), 0);
    auto* t = lv_label_create(b); lv_label_set_text(t, title); lv_obj_center(t);
    lv_obj_set_style_text_font(t, &lv_font_montserrat_24, 0);
    lv_obj_set_style_text_color(t, lv_color_hex(primary ? bg : ink), 0);
    lv_obj_add_event_cb(b, click, LV_EVENT_CLICKED, const_cast<char*>(action));
    return b;
}
void enable(lv_obj_t* obj, bool on) {
    if (on) lv_obj_remove_state(obj, LV_STATE_DISABLED); else lv_obj_add_state(obj, LV_STATE_DISABLED);
    lv_obj_set_style_opa(obj, on ? LV_OPA_COVER : LV_OPA_40, 0);
}
void update(lv_timer_t*) {
    const auto st = a2dp_native::status();
    lv_label_set_text(state_label, !radio_ready ? "RADIO STARTUP" : st.streaming ? "CONNECTED / STREAMING" : st.connected ? "CONNECTED / IDLE" : st.running ? "CONNECTING / SEARCHING" : "READY");
    lv_obj_set_style_text_color(state_label, lv_color_hex(st.connected ? accent : ink), 0);
    const char* name = st.saved_count && st.saved[0].name[0] ? st.saved[0].name : st.have_peer ? st.peer : "No headphones saved";
    lv_label_set_text_fmt(peer_label, "Headphones\n%s\n%s", name,
                          st.have_key ? "Paired (default for Connect)" : "Find devices, then tap yours to pair");
    lv_label_set_text(detail_label, radio_ready ? (st.text[0] ? st.text : "Choose a device or connect your saved headphones.") : radio_message);
    lv_label_set_text(tone_label, st.tone_hz && st.streaming ? "440 Hz tone is playing" : "Tone is off");
    lv_label_set_text(lv_obj_get_child(tone_btn, 0), st.tone_hz ? "Stop tone" : "Play 440 Hz tone");
    enable(connect_btn, radio_ready && st.have_peer && !st.running);
    enable(scan_btn, radio_ready && !st.running);
    enable(stop_btn, radio_ready && st.running);
    // An idle link suspends its stream after 3 s without audio; the tone starts it again.
    enable(tone_btn, radio_ready && st.connected);

    // Rebuild the list when the found/saved sets or the busy state change.
    char signature[sizeof list_signature] = "";
    for (int i = 0; i < st.found_count; ++i) std::strcat(signature, st.found[i].addr);
    std::strcat(signature, "|");
    for (int i = 0; i < st.saved_count; ++i) { std::strcat(signature, st.saved[i].addr); std::strcat(signature, st.saved[i].name); }
    std::strcat(signature, st.running ? (st.searching ? "search" : "busy") : "idle");
    if (!std::strcmp(signature, list_signature)) return;
    std::snprintf(list_signature, sizeof list_signature, "%s", signature);
    lv_obj_clean(device_list);
    if (!st.found_count && !st.saved_count) {
        label(device_list, "No devices yet.\nPut headphones in pairing mode,\nthen tap Find devices.", 0, 8, 382, &lv_font_montserrat_24, muted);
        return;
    }
    auto row = [&](int idx, const char* top, const char* bottom, bool on) {
        auto* b = lv_button_create(device_list);
        lv_obj_set_size(b, LV_PCT(100), 70);
        lv_obj_set_style_bg_color(b, lv_color_hex(0x2a3d56), 0);
        auto* l = lv_label_create(b);
        lv_label_set_text_fmt(l, "%s\n%s", top, bottom);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_18, 0); lv_obj_center(l);
        enable(b, on);
        lv_obj_add_event_cb(b, choose, LV_EVENT_CLICKED, reinterpret_cast<void*>(static_cast<intptr_t>(idx)));
    };
    // Found while searching: tap to pair (also while the search still runs: it pairs after the current window).
    for (int i = 0; i < st.found_count; ++i) {
        const auto& d = st.found[i];
        const int k = a2dp_native::kMaxSaved + i;
        std::snprintf(row_cmd[k], sizeof row_cmd[k], "a2dp pair %s", d.addr);
        char bottom[64];
        std::snprintf(bottom, sizeof bottom, "%s%s - tap to pair", a2dp_native::device_kind(d.cod), d.saved ? " (saved)" : "");
        row(k, d.addr, bottom, !st.running || st.searching);
    }
    // Saved (paired) headphones, most recently used first: tap to connect.
    for (int i = 0; i < st.saved_count; ++i) {
        const auto& d = st.saved[i];
        std::snprintf(row_cmd[i], sizeof row_cmd[i], "a2dp connect %d", i);
        char bottom[64];
        std::snprintf(bottom, sizeof bottom, "%s - saved, tap to connect", d.addr);
        row(i, d.name[0] ? d.name : a2dp_native::device_kind(d.cod), bottom, !st.running);
    }
}
} // namespace

void start(QueueHandle_t queue) {
    commands = queue;
    bsp_display_cfg_t cfg{};
    cfg.lvgl_port_cfg = ESP_LVGL_PORT_INIT_CONFIG();
    cfg.lvgl_port_cfg.task_affinity = 1;
    cfg.lvgl_port_cfg.task_priority = 5;
    cfg.lvgl_port_cfg.task_stack = 8192;
    cfg.buffer_size = 720 * 40;
    cfg.double_buffer = false;
    cfg.flags.buff_spiram = true;
    cfg.flags.buff_dma = false;
    cfg.flags.sw_rotate = true;
    auto* display = bsp_display_start_with_config(&cfg);
    ESP_ERROR_CHECK(display ? ESP_OK : ESP_FAIL);
    ESP_ERROR_CHECK(bsp_display_lock(portMAX_DELAY) ? ESP_OK : ESP_FAIL);
    bsp_display_rotate(display, LV_DISPLAY_ROTATION_90);
    auto* root = lv_screen_active();
    lv_obj_set_style_bg_color(root, lv_color_hex(bg), 0);
    lv_obj_remove_flag(root, LV_OBJ_FLAG_SCROLLABLE);
    label(root, "Bluetooth Classic", 32, 26, 900, &lv_font_montserrat_40);
    label(root, "Tab5 native A2DP demo", 34, 84, 1000, &lv_font_montserrat_24, muted);
    auto* connection = card(root, 32, 140, 720, 436);
    state_label = label(connection, "STARTING", 0, 0, 672, &lv_font_montserrat_28, accent);
    peer_label = label(connection, "", 0, 55, 672, &lv_font_montserrat_28);
    detail_label = label(connection, radio_message, 0, 176, 672, &lv_font_montserrat_24, muted);
    connect_btn = button(connection, "Connect", "a2dp connect", 0, 270, 328, true);
    stop_btn = button(connection, "Disconnect", "stop", 344, 270, 328);
    auto* nearby = card(root, 776, 140, 472, 436);
    label(nearby, "Devices", 0, 0, 424, &lv_font_montserrat_28);
    scan_btn = button(nearby, "Find devices", "a2dp find", 0, 53, 424, true);
    device_list = lv_obj_create(nearby);
    lv_obj_set_pos(device_list, 0, 137); lv_obj_set_size(device_list, 424, 244);
    lv_obj_set_style_bg_opa(device_list, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(device_list, 0, 0); lv_obj_set_style_pad_all(device_list, 0, 0);
    lv_obj_set_flex_flow(device_list, LV_FLEX_FLOW_COLUMN);
    auto* audio = card(root, 32, 600, 1216, 96);
    tone_label = label(audio, "Tone is off", 0, 9, 600, &lv_font_montserrat_28);
    tone_btn = button(audio, "Play 440 Hz tone", "tone", 824, -8, 344, true);
    lv_timer_create(update, 250, nullptr);
    update(nullptr);
    bsp_display_unlock();
    ESP_ERROR_CHECK(bsp_display_backlight_on());
    ESP_ERROR_CHECK(bsp_display_brightness_set(75));
    ESP_LOGI("demo_ui", "Display ready: %ld x %ld; touch initialized", (long)lv_display_get_horizontal_resolution(display), (long)lv_display_get_vertical_resolution(display));
}
void transport(bool ready, const char* message) {
    if (!bsp_display_lock(1000)) return;
    radio_ready = ready;
    std::snprintf(radio_message, sizeof radio_message, "%s", message);
    update(nullptr);
    bsp_display_unlock();
}
} // namespace demo_ui
