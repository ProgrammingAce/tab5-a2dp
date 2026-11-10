#pragma once
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
namespace demo_ui {
struct Command { char text[64]; };
void start(QueueHandle_t queue);
void transport(bool ready, const char* message);
}
