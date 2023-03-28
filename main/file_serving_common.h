/*
 * SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
/* HTTP File Server Example, common declarations

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#pragma once

#include "sdkconfig.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t mount_storage(const char *base_path);

esp_err_t start_file_server(const char *base_path);

void ota_main();
void simple_ota_task(void *pvParameter);
static esp_err_t ensure_transWARP_to_be_on_second_ota_partition();

//#define WARP_MORE_HARDWARE_BIN "warpAC011K_firmware_2_0_12_64033399_merged.bin"
//#define OTA_URL "http://192.168.188.79:8000/" WARP_MORE_HARDWARE_BIN
char OTA_URL[256] = "http://192.168.188.79:8000/warpAC011K_firmware_2_0_12_64033399_merged.bin";

#ifdef __cplusplus
}
#endif
