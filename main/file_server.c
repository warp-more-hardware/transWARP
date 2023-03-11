/*
 * SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
/* HTTP File Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#include "esp_err.h"
#include "esp_log.h"

#include "esp_vfs.h"
#include "esp_spiffs.h"
#include "esp_http_server.h"

/* Max length a file path can have on storage */
#define FILE_PATH_MAX (ESP_VFS_PATH_MAX + CONFIG_SPIFFS_OBJ_NAME_LEN)

/* Max size of an individual file. Make sure this
 * value is same as that set in upload_script.html */
#define MAX_FILE_SIZE   (200*1024) // 200 KB
#define MAX_FILE_SIZE_STR "200KB"

#define WARP_MORE_HARDWARE_BIN "warpAC011K_firmware_2_0_12_64033399_merged.bin"

/* Scratch buffer size */
#define SCRATCH_BUFSIZE  8192

struct file_server_data {
    /* Base path of file storage */
    char base_path[ESP_VFS_PATH_MAX + 1];

    /* Scratch buffer for temporary storage during file transfer */
    char scratch[SCRATCH_BUFSIZE];
};

static const char *TAG = "file_server";

/* Handler to redirect incoming GET request for /index.html to /
 * This can be overridden by uploading file with same name */
static esp_err_t index_html_get_handler(httpd_req_t *req)
{
    httpd_resp_set_status(req, "307 Temporary Redirect");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);  // Response body can be empty
    return ESP_OK;
}

/* Send HTTP response with a run-time generated html consisting of
 * a list of all files and folders under the requested path.
 * In case of SPIFFS this returns empty list when path is any
 * string other than '/', since SPIFFS doesn't support directories */
static esp_err_t http_resp_dir_html(httpd_req_t *req, const char *dirpath)
{
    char entrypath[FILE_PATH_MAX];
    char entrysize[16];
    const char *entrytype;

    struct dirent *entry;
    struct stat entry_stat;

    DIR *dir = opendir(dirpath);
    const size_t dirpath_len = strlen(dirpath);

    /* Retrieve the base path of file storage to construct the full path */
    strlcpy(entrypath, dirpath, sizeof(entrypath));

    if (!dir) {
        ESP_LOGE(TAG, "Failed to stat dir : %s", dirpath);
        /* Respond with 404 Not Found */
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Directory does not exist");
        return ESP_FAIL;
    }

    /* Send HTML file header */
    httpd_resp_sendstr_chunk(req, 
            "<!DOCTYPE html>"
            "<html>"
            "<head>"
                "<title>Download EN+ Firmware Backup</title>"
                "<style>"
                    "body {"
                        "font-family: Arial, sans-serif;"
                        "background-color: #f2f2f2;"
                        "padding: 20px;"
                    "}   h1 {"
                    "text-align: center;"
                    "color: #333;"
                "}"
                "p {"
                    "font-size: 18px;"
                    "line-height: 1.5;"
                    "color: #555;"
                "}"
                "table {"
                    "border-collapse: collapse;"
                    "width: 100%;"
                    "margin-top: 20px;"
                    "margin-bottom: 20px;"
                "}"
                "th, td {"
                    "text-align: left;"
                    "padding: 8px;"
                    "border: 1px solid #ddd;"
                "}"
                "th {"
                    "background-color: #f2f2f2;"
                    "color: #333;"
                "}"
                "tr:nth-child(even) {"
                    "background-color: #f9f9f9;"
                "}"
                "a {"
                    "color: #008CBA;"
                    "text-decoration: none;"
                "}"
                "a:hover {"
                    "color: #005580;"
                "}"
            "</style>"
            "</head>"
            "<body>"
                "<h1>Download Your Firmware Backup</h1>"
                "<p>Please download a <a href='/AC011K_ENplus_flash_backup.bin'>backup</a> "
                "of the firmware you're about to replace with the warp-more-hardware firmware.</p>"
                "<table class='fixed'>"
                    "<thead>"
                        "<tr>"
                            "<th>Name</th>"
                            "<th>Type</th>"
                            "<th>Size</th>"
                        "</tr>"
                    "</thead>"
                    "<tbody>"
    );

    /* Iterate over all files / folders and fetch their names and sizes */
    while ((entry = readdir(dir)) != NULL) {
        entrytype = (entry->d_type == DT_DIR ? "directory" : "file");

        strlcpy(entrypath + dirpath_len, entry->d_name, sizeof(entrypath) - dirpath_len);
        if (stat(entrypath, &entry_stat) == -1) {
            ESP_LOGE(TAG, "Failed to stat %s : %s", entrytype, entry->d_name);
            continue;
        }
        sprintf(entrysize, "%ld", entry_stat.st_size);
        ESP_LOGI(TAG, "Found %s : %s (%s bytes)", entrytype, entry->d_name, entrysize);

        /* Send chunk of HTML file containing table entries with file name and size */
        httpd_resp_sendstr_chunk(req, "<tr><td><a href=\"");
        httpd_resp_sendstr_chunk(req, req->uri);
        httpd_resp_sendstr_chunk(req, entry->d_name);
        if (entry->d_type == DT_DIR) {
            httpd_resp_sendstr_chunk(req, "/");
        }
        httpd_resp_sendstr_chunk(req, "\">");
        httpd_resp_sendstr_chunk(req, entry->d_name);
        httpd_resp_sendstr_chunk(req, "</a></td><td>");
        httpd_resp_sendstr_chunk(req, entrytype);
        httpd_resp_sendstr_chunk(req, "</td><td>");
        httpd_resp_sendstr_chunk(req, entrysize);
        httpd_resp_sendstr_chunk(req, "</td></tr>\n");
    }
    closedir(dir);

    /* Finish the file list table */
    httpd_resp_sendstr_chunk(req, "</tbody></table>");

    /* Send remaining chunk of HTML file to complete it */
    httpd_resp_sendstr_chunk(req, "</body></html>");

    /* Send empty chunk to signal HTTP response completion */
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

/* Copies the full path into destination buffer and returns
 * pointer to path (skipping the preceding base path) */
static const char* get_path_from_uri(char *dest, const char *base_path, const char *uri, size_t destsize)
{
    const size_t base_pathlen = strlen(base_path);
    size_t pathlen = strlen(uri);

    const char *quest = strchr(uri, '?');
    if (quest) {
        pathlen = MIN(pathlen, quest - uri);
    }
    const char *hash = strchr(uri, '#');
    if (hash) {
        pathlen = MIN(pathlen, hash - uri);
    }

    if (base_pathlen + pathlen + 1 > destsize) {
        /* Full path string won't fit into destination buffer */
        return NULL;
    }

    /* Construct full path (base + path) */
    strcpy(dest, base_path);
    strlcpy(dest + base_pathlen, uri, pathlen + 1);

    /* Return pointer to path, skipping the base */
    return dest + base_pathlen;
}


#include "esp_partition.h"
#include "esp_ota_ops.h"
#include "esp_flash.h"
#include "esp_system.h"


/* Handler to download the whole flash (less the partition this prog is running from, but instead the other app partition twice) */
static esp_err_t download_flash_backup(httpd_req_t *req)
{
    esp_err_t err = ESP_FAIL;
    size_t index = 0;

    httpd_resp_set_type(req, "application/octet-stream");

    // Get the transWARPpartition that the currently running program was started from
    const esp_partition_t *transWARPpartition = esp_ota_get_running_partition();
    if (transWARPpartition == NULL) {
        ESP_LOGE(TAG, "Error getting running transWARPpartition");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Running from transWARPpartition: label=%s, type=0x%x, subtype=0x%x, offset=0x%x, size=0x%x",
            transWARPpartition->label, transWARPpartition->type, transWARPpartition->subtype, transWARPpartition->address, transWARPpartition->size);

    /* Iterating over partitions */
    ESP_LOGI(TAG, "Serving the Backup");
    ESP_LOGI(TAG, "----------------Iterate through partitions---------------");
    esp_partition_iterator_t it;
    it = esp_partition_find(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, NULL);

    // Allocate a buffer to hold a chunk of data
    char *chunk_buffer = malloc(1024);

    // Loop through all partitions
    // serve them
    // if the label of the RUN partition is found skip it.
    // serve the other app partition twice
    for (; it != NULL; it = esp_partition_next(it)) {
        const esp_partition_t *part = esp_partition_get(it);
        if (part->type == transWARPpartition->type) {
            if (part->label == transWARPpartition->label) {
                // we do not want to backup ourself
                
                ESP_LOGW(TAG, "\tpartition type: 0x%x, subtype: 0x%x, offset: 0x%x, size: 0x%x, label: %s"
                        " (skip serving the transWARP partition)",
                        part->type, part->subtype, part->address, part->size, part->label);
                index = index + part->size;
                continue;
            } else {
                ESP_LOGI(TAG, "\tpartition type: 0x%x, subtype: 0x%x, offset: 0x%x, size: 0x%x, label: %s"
                        " (double serving the EN+ app partition)",
                        part->type, part->subtype, part->address, part->size, part->label);
                for (int i=part->address; i < (part->address + part->size); i += 1024) {
                    // Read the chunk at the current offset
                    esp_err_t err = esp_flash_read(NULL, chunk_buffer, i, 1024);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "Error reading flash: %d", err);
                        break;
                    }

                    if (httpd_resp_send_chunk(req, chunk_buffer, 1024) != ESP_OK) {
                        ESP_LOGE(TAG, "File sending failed!");
                        /* Abort sending file */
                        httpd_resp_sendstr_chunk(req, NULL);
                        /* Respond with 500 Internal Server Error */
                        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
                        return ESP_FAIL;
                    }
                }
            }
        }
        ESP_LOGI(TAG, "\tpartition type: 0x%x, subtype: 0x%x, offset: 0x%x, size: 0x%x, label: %s",
                part->type, part->subtype, part->address, part->size, part->label);

        // Read the flash in chunks of 1024 bytes
        for (; index < (part->address + part->size); index += 1024) {
            // Read the chunk at the current offset
            esp_err_t err = esp_flash_read(NULL, chunk_buffer, index, 1024);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Error reading flash: %d", err);
                break;
            }

            if (httpd_resp_send_chunk(req, chunk_buffer, 1024) != ESP_OK) {
                ESP_LOGE(TAG, "File sending failed!");
                /* Abort sending file */
                httpd_resp_sendstr_chunk(req, NULL);
                /* Respond with 500 Internal Server Error */
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
                return ESP_FAIL;
            }
        }
    }
    // Release the partition iterator to release memory allocated for it
    esp_partition_iterator_release(it);

    ESP_LOGI(TAG, "Backup served");

    // Free the chunk buffer
    free(chunk_buffer);

    /* /1* Retrieve the pointer to scratch buffer for temporary storage *1/ */
    /* char *chunk = ((struct file_server_data *)req->user_ctx)->scratch; */
    /* size_t chunksize; */
    /* do { */
    /*     /1* Read file in chunks into the scratch buffer *1/ */
    /*     chunksize = fread(chunk, 1, SCRATCH_BUFSIZE, fd); */

    /*     if (chunksize > 0) { */
    /*         /1* Send the buffer contents as HTTP response chunk *1/ */
    /*         if (httpd_resp_send_chunk(req, chunk, chunksize) != ESP_OK) { */
    /*             fclose(fd); */
    /*             ESP_LOGE(TAG, "File sending failed!"); */
    /*             /1* Abort sending file *1/ */
    /*             httpd_resp_sendstr_chunk(req, NULL); */
    /*             /1* Respond with 500 Internal Server Error *1/ */
    /*             httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file"); */
    /*            return ESP_FAIL; */
    /*        } */
    /*     } */

    /*     /1* Keep looping till the whole file is sent *1/ */
    /* } while (chunksize != 0); */

    /* Close file after sending complete */
    //fclose(fd);

    /* Respond with an empty chunk to signal HTTP response completion */
#ifdef CONFIG_EXAMPLE_HTTPD_CONN_CLOSE_HEADER
    httpd_resp_set_hdr(req, "Connection", "close");
#endif
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* Handler to download a file kept on the server */
static esp_err_t download_get_handler(httpd_req_t *req)
{
    char filepath[FILE_PATH_MAX];
    FILE *fd = NULL;
    struct stat file_stat;

    const char *filename = get_path_from_uri(filepath, ((struct file_server_data *)req->user_ctx)->base_path,
                                             req->uri, sizeof(filepath));
    if (!filename) {
        ESP_LOGE(TAG, "Filename is too long");
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Filename too long");
        return ESP_FAIL;
    }

    /* If name has trailing '/', respond with directory contents */
    if (filename[strlen(filename) - 1] == '/') {
        return http_resp_dir_html(req, filepath);
    }

    if (stat(filepath, &file_stat) == -1) {
        /* If file not present on SPIFFS check if URI
         * corresponds to one of the hardcoded paths */
        if (strcmp(filename, "/index.html") == 0) {
            return index_html_get_handler(req);
        }
        ESP_LOGE(TAG, "Failed to stat file : %s", filepath);
        /* Respond with 404 Not Found */
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File does not exist");
        return ESP_FAIL;
    }

    fd = fopen(filepath, "r");
    if (!fd) {
        ESP_LOGE(TAG, "Failed to read existing file : %s", filepath);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read existing file");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Sending file : %s (%ld bytes)...", filename, file_stat.st_size);
    httpd_resp_set_type(req, "application/octet-stream");

    /* Retrieve the pointer to scratch buffer for temporary storage */
    char *chunk = ((struct file_server_data *)req->user_ctx)->scratch;
    size_t chunksize;
    do {
        /* Read file in chunks into the scratch buffer */
        chunksize = fread(chunk, 1, SCRATCH_BUFSIZE, fd);

        if (chunksize > 0) {
            /* Send the buffer contents as HTTP response chunk */
            if (httpd_resp_send_chunk(req, chunk, chunksize) != ESP_OK) {
                fclose(fd);
                ESP_LOGE(TAG, "File sending failed!");
                /* Abort sending file */
                httpd_resp_sendstr_chunk(req, NULL);
                /* Respond with 500 Internal Server Error */
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
               return ESP_FAIL;
           }
        }

        /* Keep looping till the whole file is sent */
    } while (chunksize != 0);

    /* Close file after sending complete */
    fclose(fd);
    ESP_LOGI(TAG, "File sending complete");

    /* Respond with an empty chunk to signal HTTP response completion */
#ifdef CONFIG_EXAMPLE_HTTPD_CONN_CLOSE_HEADER
    httpd_resp_set_hdr(req, "Connection", "close");
#endif
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* Handler to upload a file onto the server */
static esp_err_t upload_post_handler(httpd_req_t *req)
{
    /* /1* File cannot be larger than a limit *1/ */
    /* if (req->content_len > MAX_FILE_SIZE) { */
    /*     ESP_LOGE(TAG, "File too large : %d bytes", req->content_len); */
    /*     /1* Respond with 400 Bad Request *1/ */
    /*     httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, */
    /*                         "File size must be less than " */
    /*                         MAX_FILE_SIZE_STR "!"); */
    /*     /1* Return failure to close underlying connection else the */
    /*      * incoming file content will keep the socket busy *1/ */
    /*     return ESP_FAIL; */
    /* } */

    ESP_LOGI(TAG, "Receiving firmware ...");

    /* Retrieve the pointer to scratch buffer for temporary storage */
    char *buf = ((struct file_server_data *)req->user_ctx)->scratch;
    int received;

    // Get the size of the flash
    uint32_t flash_size;
    esp_err_t err = esp_flash_get_size(NULL, &flash_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error detecting flash size.");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Error detecting flash size.");
        return err;
    }

    if (req->content_len != flash_size) {
        ESP_LOGE(TAG, "The firmware file size is wrong! File size: %d, flash size: %d", req->content_len, flash_size);
        //httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "The firmware file size is wrong!");
        //return ESP_ERR_INVALID_SIZE;
    }

    bool write_protected;
    err = esp_flash_get_chip_write_protect(NULL, &write_protected);
    if (err == ESP_OK) {
        if (write_protected) {
            ESP_LOGI(TAG, "Flash is write protected, unlocking it...");
            ESP_ERROR_CHECK(esp_flash_set_chip_write_protect(NULL, false));
        } else {
            ESP_LOGI(TAG, "Flash is writeable");
        }
    } else {
        ESP_LOGE(TAG, "Failed to esp_flash_get_chip_write_protect");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Error detecting flash write protection.");
        return err;
    }

    esp_flash_t flash_cfg = {0};
    const esp_flash_region_t *prot_regions;
    uint32_t num_prot_regions;

    esp_flash_init(&flash_cfg);

    // Get the protectable regions
    err = esp_flash_get_protectable_regions(&flash_cfg, &prot_regions, &num_prot_regions);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "Failed to get protectable regions: %s\n", esp_err_to_name(err));
        return err;
    }

    // Iterate through the protectable regions
    for (int i = 0; i < num_prot_regions; i++) {
        // Get the protection status of the region
        bool prot;
        err = esp_flash_get_protected_region(NULL, &prot_regions[i], &prot);
        if (err != ESP_OK) {
            ESP_LOGI(TAG, "Failed to get protected region: %s\n", esp_err_to_name(err));
            return err;
        }

        // Print the protection status of the region
        if (prot) {
            ESP_LOGI(TAG, "Region 0x%x - 0x%x is protected\n", prot_regions[i].offset, prot_regions[i].size);
        } else {
            ESP_LOGI(TAG, "Region 0x%x - 0x%x is not protected\n", prot_regions[i].offset, prot_regions[i].size);
        }
    }

    // Unprotect the entire flash
    esp_flash_region_t region;
    region.offset = 0x1000;
    region.size = flash_size - 0x1000;
    esp_flash_set_protected_region(NULL, &region, false);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to unprotect flash");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to unprotect flash");
        return err;
    }

    /* // Erase the entire flash */
    /* err = esp_flash_erase_chip(NULL); */
    /* if (err != ESP_OK) { */
    /*     ESP_LOGE(TAG, "Failed to erase flash"); */
    /*     httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to erase flash"); */
    /*     return err; */
    /* } */

    // Erase the entire flash
    err = esp_flash_erase_region(NULL, 0x1000, flash_size - 0x1000);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to erase flash");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to erase flash");
        return err;
    }

    /* Content length of the request gives the size of the file being uploaded */
    int remaining = req->content_len;
    int address = 0;

    while (remaining > 0) {

        ESP_LOGI(TAG, "Remaining size : %d", remaining);
        /* Receive the file part by part into a buffer */
        if ((received = httpd_req_recv(req, buf, MIN(remaining, SCRATCH_BUFSIZE))) <= 0) {
            if (received == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry if timeout occurred */
                continue;
            }

            /* // In case of unrecoverable error, */
            /* // close and delete the unfinished file */
            /* fclose(fd); */
            /* unlink(filepath); */

            ESP_LOGE(TAG, "File reception failed!");
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to receive file");
            return ESP_FAIL;
        }

        ESP_LOGI(TAG, "would write at %x, %d bytes", address, received);
        /* /1* Write buffer content to flash *1/ */
        /* esp_err_t err = esp_flash_write(NULL, buf, address, received); */
        /* if (err != ESP_OK) { */
        /*     ESP_LOGE(TAG, "Failed to write flash"); */
        /*     httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to write flash"); */
        /*     return err; */
        /* } */

        /* Keep track of remaining size of the file left to be uploaded */
        address += received;
        remaining -= received;
    }

    ESP_LOGI(TAG, "File reception complete");

    /* Redirect onto root to see the updated file list */
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/");
#ifdef CONFIG_EXAMPLE_HTTPD_CONN_CLOSE_HEADER
    httpd_resp_set_hdr(req, "Connection", "close");
#endif
    httpd_resp_sendstr(req, "File uploaded successfully");


    // esp.reboot;

    return ESP_OK;
}

/* Function to start the file server */
esp_err_t start_file_server(const char *base_path)
{
    static struct file_server_data *server_data = NULL;

    if (server_data) {
        ESP_LOGE(TAG, "File server already started");
        return ESP_ERR_INVALID_STATE;
    }

    /* Allocate memory for server data */
    server_data = calloc(1, sizeof(struct file_server_data));
    if (!server_data) {
        ESP_LOGE(TAG, "Failed to allocate memory for server data");
        return ESP_ERR_NO_MEM;
    }
    strlcpy(server_data->base_path, base_path,
            sizeof(server_data->base_path));

    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    /* Use the URI wildcard matching function in order to
     * allow the same handler to respond to multiple different
     * target URIs which match the wildcard scheme */
    config.uri_match_fn = httpd_uri_match_wildcard;

    ESP_LOGI(TAG, "Starting HTTP Server on port: %d", config.server_port);
    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start file server!");
        return ESP_FAIL;
    }

    /* URI handler for getting a flash backup */
    httpd_uri_t flash_backup_download = {
        .uri       = "/AC011K_ENplus_flash_backup.bin",
        .method    = HTTP_GET,
        .handler   = download_flash_backup,
        .user_ctx  = server_data    // Pass server data as context
    };
    httpd_register_uri_handler(server, &flash_backup_download);

    /* URI handler for uploading files to server */
    httpd_uri_t file_upload = {
        .uri       = "/" WARP_MORE_HARDWARE_BIN,   // Match all URIs of type /upload/path/to/file
        .method    = HTTP_POST,
        .handler   = upload_post_handler,
        .user_ctx  = server_data    // Pass server data as context
    };
    httpd_register_uri_handler(server, &file_upload);

    /* URI handler for getting files */
    httpd_uri_t file_download = {
        .uri       = "/*",  // Match all URIs of type /path/to/file
        .method    = HTTP_GET,
        .handler   = download_get_handler,
        .user_ctx  = server_data    // Pass server data as context
    };
    httpd_register_uri_handler(server, &file_download);

    return ESP_OK;
}
