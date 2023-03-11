#include <string.h>
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "freertos/event_groups.h"
#include "esp_system.h"


#include <stdio.h>
#include "esp_http_server.h"
#include "esp_vfs_fat.h"
#include <dirent.h>

#include "esp_http_client.h"

// File system details
#define MOUNT_POINT "/fat"

// Web server details
#define WEB_PORT 80

#include "file_serving_common.h"

static EventGroupHandle_t wifi_event_group;
const int CONNECTED_BIT = BIT0;


/*******************************************************
 *                Variable Definitions
 *******************************************************/
static const char *TAG = "transWARP";
static esp_netif_t *netif_sta = NULL;


void task1_handler(void *arg) {
    while (1) {
        ESP_ERROR_CHECK( esp_wifi_connect() );
        vTaskDelay(33 * 1000 / portTICK_PERIOD_MS);
    }
    vTaskDelete(NULL);
}

void task2_handler(void *arg) {
    while (1) {
        //ESP_LOGI(TAG, "Tas2 tick");
        vTaskDelay(55 * 1000 / portTICK_PERIOD_MS);
    }
    vTaskDelete(NULL);
}

esp_err_t app_tasks_start(void) {
    static bool is_app_tasks_started = false;

    if (!is_app_tasks_started) {
        xTaskCreate(task1_handler, "task1", 3072, NULL, 5, NULL);
        xTaskCreate(task2_handler, "task2", 3072, NULL, 5, NULL);
        is_app_tasks_started = true;
    }
    return ESP_OK;
}

void ip_event_handler(void *arg, esp_event_base_t event_base,
                      int32_t event_id, void *event_data)
{
    ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
    ESP_LOGI(TAG, "<IP_EVENT_STA_GOT_IP>IP:" IPSTR, IP2STR(&event->ip_info.ip));

    app_tasks_start();
}


static void event_handler(void* arg, esp_event_base_t event_base,
								int32_t event_id, void* event_data)
{
	if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
		ESP_LOGI(TAG, "WIFI_EVENT_STA_DISCONNECTED");
		esp_wifi_connect();
		xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
	} else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
		ESP_LOGI(TAG, "IP_EVENT_STA_GOT_IP");
		xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
	}
}

static void initialise_wifi(void) {
	esp_log_level_set("wifi", ESP_LOG_WARN);
	static bool initialized = false;
	if (initialized) {
		return;
	}
	ESP_ERROR_CHECK(esp_netif_init());
	wifi_event_group = xEventGroupCreate();
	esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();
	assert(ap_netif);
	esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
	assert(sta_netif);
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
	ESP_ERROR_CHECK( esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &event_handler, NULL) );
	ESP_ERROR_CHECK( esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL) );

    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_FLASH));
	//ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );

    ESP_ERROR_CHECK( esp_wifi_set_ps(WIFI_PS_NONE));
	ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
	ESP_ERROR_CHECK( esp_wifi_start() );

	initialized = true;
}

static bool wifi_apsta(int timeout_ms) {
	wifi_config_t ap_config = { 0 };
	strcpy((char *)ap_config.ap.ssid,TAG);
	strcpy((char *)ap_config.ap.password, "");
	ap_config.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;
	ap_config.ap.ssid_len = strlen(TAG);
	ap_config.ap.max_connection = 4;
	ap_config.ap.channel = 0;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;

    ESP_LOGI(TAG, "Looking for WiFi config");
	wifi_config_t sta_config = { 0 };
    int ret = esp_wifi_get_config(ESP_IF_WIFI_STA, &sta_config);
    if (ret != ESP_OK)
    {
        ESP_LOGW(TAG, "Wifi configuration not found in NVS flash partition.");    
    }
    else if (strlen((char*)sta_config.sta.ssid) == 0)
    {
        ESP_LOGW(TAG, "Wifi configuration empty in NVS flash partition.");    
    }
    else
    {
        ESP_LOGI(TAG, "Found Wifi configuration in NVS flash.");
        ESP_LOGI(TAG, "SSID: %s" ,sta_config.sta.ssid);
        ESP_LOGI(TAG, "Pass: %s" ,sta_config.sta.password);
    }

	ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_APSTA) );
	ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_AP, &ap_config) );
	ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &sta_config) );
	ESP_ERROR_CHECK( esp_wifi_start() );
	ESP_LOGI(TAG, "WIFI_MODE_AP started. SSID:%s with no password.", TAG);

	ESP_ERROR_CHECK( esp_wifi_connect() );
	int bits = xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
								   pdFALSE, pdTRUE, timeout_ms / portTICK_PERIOD_MS);
	ESP_LOGI(TAG, "bits=%x", bits);
	if (bits) {
		ESP_LOGI(TAG, "WIFI_MODE_STA connected.");
	} else {
		ESP_LOGI(TAG, "WIFI_MODE_STA can't connect.");
	}
	return (bits & CONNECTED_BIT) != 0;
}


/********************************************************************************
 * http put something
 * */

// HTTP web server details
#define WEB_SERVER "http://example.com/upload.php"
#define WEB_PORT 80
#define WEB_PATH "/upload"

#define FILE_NAME "example.txt"


// Initialize the SD card and mount the FAT file system
static esp_err_t initialize_filesystem(void) {
    /* sdmmc_host_t host = SDMMC_HOST_DEFAULT(); */
    /* sdmmc_slot_config_t slot_config = SDMMC_SLOT_CONFIG_DEFAULT(); */

    /* esp_vfs_fat_sdmmc_mount_config_t mount_config = { */
    /*     .format_if_mount_failed = true, */
    /*     .max_files = 5 */
    /* }; */

    /* sdmmc_card_t *card; */
    /* esp_err_t ret = esp_vfs_fat_sdmmc_mount(MOUNT_POINT, &host, &slot_config, &mount_config, &card); */

    const esp_vfs_fat_mount_config_t mount_config = {
        .max_files = 4,
        .format_if_mount_failed = false,
        .allocation_unit_size = CONFIG_WL_SECTOR_SIZE
    };

    // Mount a FAT partition on the SPI flash memory
    esp_err_t ret = esp_vfs_fat_spiflash_mount_ro(MOUNT_POINT, "storage", &mount_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount FAT file system: %s", esp_err_to_name(ret));
        return ret;
    }
    else {
        ESP_LOGI(TAG, "Mounted FAT file system: %s", MOUNT_POINT);
    }

    return ESP_OK;
}

// Read the contents of the file and upload it to the web server
static esp_err_t upload_file(void) {
    // Open the file for reading
    char path[32];
    sprintf(path, "%s/%s", MOUNT_POINT, FILE_NAME);
    FILE* f = fopen(path, "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open file for reading");
        return ESP_FAIL;
    }

    // Get the file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Allocate a buffer for the file contents
    char* file_contents = (char*) malloc(file_size);
    if (file_contents == NULL) {
        ESP_LOGE(TAG, "Failed to allocate buffer for file contents");
        fclose(f);
        return ESP_FAIL;
    }

    // Read the file contents into the buffer
    size_t bytes_read = fread(file_contents, 1, file_size, f);
    fclose(f);
    if (bytes_read != file_size) {
        ESP_LOGE(TAG, "Failed to read entire file");
        free(file_contents);
        return ESP_FAIL;
    }

    // Initialize the HTTP client configuration
    esp_http_client_config_t config = {
        .url = WEB_SERVER WEB_PATH,
        .port = WEB_PORT,
        .method = HTTP_METHOD_PUT,
        .buffer_size = file_size,
        //.upload_data = file_contents,
        //.upload_len = file_size
    };

    // Initialize the HTTP client
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        free(file_contents);
        return ESP_FAIL;
    }

    // Perform the HTTP request
    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to perform HTTP request: %s", esp_err_to_name(err));
    }

    // Clean up
    esp_http_client_cleanup(client);
    free(file_contents);

    return err;
}

/* void app_main() */
/* { */
/* // Initialize the file system */
/* esp_err_t ret = initialize_filesystem(); */
/* if (ret != ESP_OK) { */
/*     return; */
/* } */

/* // Upload the file */
/* ret = upload_file(); */
/* if (ret != ESP_OK) { */
/*     return; */
/* } */

/* ESP_LOGI(TAG, "File upload complete"); */

/* } */

/******************************
 *
 This code initializes the SD card and mounts the FAT file system on startup. It then opens the specified file for reading, reads its contents into a buffer, and uploads the buffer to the specified HTTP web server using the PUT method.

 Note that you will need to replace the placeholder values for `WEB_SERVER`, `WEB_PORT`, `WEB_PATH`, `MOUNT_POINT`, and `FILE_NAME` with the appropriate values for your application. Additionally, you will need to ensure that you have the necessary components and libraries installed in your ESP-IDF environment to use HTTP client functionality.
 */


void app_main(void)
{
  /* Needed here otherwise an ESP_ERR_NVS_NOT_INITIALIZED occur
  * at Wifi init
  */
  ESP_ERROR_CHECK(nvs_flash_init());

  ESP_ERROR_CHECK(esp_event_loop_create_default());

  //vTaskDelay(3 * 1000 / portTICK_PERIOD_MS);

  ESP_LOGI(TAG, "Initialize WiFi");    
  initialise_wifi();

        ESP_LOGI(TAG, "Start APSTA Mode");
        wifi_apsta(10*1000);

  // Initialize the file system
  ESP_LOGI(TAG, "Initialize the FAT file system");
  esp_err_t ret = initialize_filesystem();
  if (ret != ESP_OK) {
      return;
  }

  /* Start the file server */
  ESP_LOGI(TAG, "Initialize the file server");
  ESP_ERROR_CHECK(start_file_server(MOUNT_POINT));

  ESP_LOGI(TAG, "Ready");



  /* memcpy((uint8_t *) &cfg.router.ssid, CONFIG_MESH_ROUTER_SSID, strlen(CONFIG_MESH_ROUTER_SSID)); */
  /* memcpy((uint8_t *) &cfg.router.password, CONFIG_MESH_ROUTER_PASSWD, strlen(CONFIG_MESH_ROUTER_PASSWD)); */
  /* cfg.mesh_ap.max_connection = CONFIG_MESH_AP_CONNECTIONS; */
  /* cfg.mesh_ap.nonmesh_max_connection = CONFIG_MESH_NON_MESH_AP_CONNECTIONS; */
  /* memcpy((uint8_t *) &cfg.mesh_ap.password, CONFIG_MESH_AP_PASSWD, strlen(CONFIG_MESH_AP_PASSWD)); */
  /* //ESP_ERROR_CHECK(esp_mesh_set_config(&cfg)); */


  //app_tasks_start();
}
