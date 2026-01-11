// Global AdBlocker declarations
//
// s60sc 2022

#pragma once
#include "globals.h"

#if CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32S2
#error "App not compatible with this ESP model"
#endif

#define ALLOW_SPACES false // set true to allow whitespace in configs.txt key values

// web server ports
#define HTTP_PORT 80 // app access
#define HTTPS_PORT 443 // secure app access


/*********************** Fixed defines leave as is ***********************/ 
/** Do not change anything below here unless you know what you are doing **/

#define STATIC_IP_OCTAL "168" // dev only
#define DEBUG_MEM false // leave as false
#define FLUSH_DELAY 0 // for debugging crashes
#define DBG_ON false // esp debug output
#define DBG_LVL ESP_LOG_ERROR // level if DBG_ON true: ESP_LOG_ERROR, ESP_LOG_WARN, ESP_LOG_INFO, ESP_LOG_DEBUG, ESP_LOG_VERBOSE
#define DOT_MAX 50
#define HOSTNAME_GRP 0
#define USE_IP6 false

#define APP_NAME "ESP32_AdBlocker" // max 15 chars
#define APP_VER "3.0"

#define HTTP_CLIENTS 2 // http, ws
#define MAX_STREAMS 0
#define INDEX_PAGE_PATH DATA_DIR "/AdBlocker" HTML_EXT
#define FILE_NAME_LEN 64
#define IN_FILE_NAME_LEN 128
#define JSON_BUFF_LEN (1024 * 4) // set big enough to hold json string
#define MAX_CONFIGS 60 // > number of entries in configs.txt
#define GITHUB_PATH "/s60sc/ESP32_AdBlocker/main"
#define CUSTOM_FILE_PATH DATA_DIR "/custom" TEXT_EXT

#define STORAGE LittleFS // One of LittleFS or SD_MMC
#define RAMSIZE (1024 * 8) 
#define CHUNKSIZE (1024 * 4)
#define MIN_RAM 8 // min object size stored in ram instead of PSRAM default is 4096
#define MAX_RAM 4096 // max object size stored in ram instead of PSRAM default is 4096
#define TLS_HEAP (64 * 1024) // min free heap for TLS session
#define WARN_HEAP (32 * 1024) // low free heap warning
#define WARN_ALLOC (16 * 1024) // low free max allocatable free heap block
#define MAX_ALERT 1024

#define INCLUDE_FTP_HFS false // ftp.cpp (file upload)
#define INCLUDE_SMTP false    // smtp.cpp (email)
#define INCLUDE_MQTT false    // mqtt.cpp
#define INCLUDE_TGRAM false   // telegram.cpp
#define INCLUDE_CERTS false   // certificates.cpp (https and server certificate checking)
#define INCLUDE_WEBDAV true   // webDav.cpp (WebDAV protocol)

// to determine if newer data files need to be loaded
#define CFG_VER 3

#ifdef CONFIG_IDF_TARGET_ESP32S3 
#define SERVER_STACK_SIZE (1024 * 8)
#define DS18B20_STACK_SIZE (1024 * 2)
#define STICK_STACK_SIZE (1024 * 4)
#else
#define SERVER_STACK_SIZE (1024 * 4)
#define DS18B20_STACK_SIZE (1024)
#define STICK_STACK_SIZE (1024 * 2)
#endif
#define BATT_STACK_SIZE (1024 * 2)
#define EMAIL_STACK_SIZE (1024 * 6)
#define FS_STACK_SIZE (1024 * 4)
#define LOG_STACK_SIZE (1024 * 3)
#define MQTT_STACK_SIZE (1024 * 4)
#define PING_STACK_SIZE (1024 * 5)
#define SERVO_STACK_SIZE (1024)
#define SUSTAIN_STACK_SIZE (1024 * 4)
#define TGRAM_STACK_SIZE (1024 * 6)
#define TELEM_STACK_SIZE (1024 * 4)
#define UART_STACK_SIZE (1024 * 2)

// task priorities
#define HTTP_PRI 5
#define TGRAM_PRI 1
#define EMAIL_PRI 1
#define FTP_PRI 1
#define LOG_PRI 1
#define UART_PRI 1
#define BATT_PRI 1

/******************** Function declarations *******************/

// global app specific functions

void appSetup();
IPAddress resolveDomain(const char* host);

/******************** Global app declarations *******************/

extern const char* appConfig;
