// Global AdBlocker declarations
//
// s60sc 2022

#pragma once
#include "globals.h"

#define ALLOW_SPACES false // set true to allow whitespace in configs.txt key values

// web server ports
#define WEB_PORT 80 // app control
#define OTA_PORT (WEB_PORT + 1) // OTA update


/*********************** Fixed defines leave as is ***********************/ 
/** Do not change anything below here unless you know what you are doing **/

//#define DEV_ONLY // leave commented out
#define STATIC_IP_OCTAL "168" // dev only
#define CHECK_MEM false // leave as false
#define FLUSH_DELAY 200 // for debugging crashes
 
#define APP_NAME "ESP32_AdBlocker" // max 15 chars
#define APP_VER "2.1"

#define MAX_CLIENTS 2 // allowing too many concurrent web clients can cause errors
#define INDEX_PAGE_PATH DATA_DIR "/AdBlocker" HTML_EXT
#define FILE_NAME_LEN 128
#define JSON_BUFF_LEN (1024 * 4) 
#define MAX_CONFIGS 50 // > number of entries in configs.txt
#define GITHUB_URL "https://raw.githubusercontent.com/s60sc/ESP32_AdBlocker/master"

#define STORAGE LittleFS // One of LittleFS or SD_MMC
#define RAMSIZE (1024 * 8) 
#define CHUNKSIZE (1024 * 4)
#define RAM_LOG_LEN 5000 // size of ram stored system message log in bytes
//#define INCLUDE_FTP 
//#define INCLUDE_SMTP
//#define INCLUDE_SD
//#define INCLUDE_MQTT

#define IS_IO_EXTENDER false // must be false except for IO_Extender
#define EXTPIN 100

// to determine if newer data files need to be loaded
#define HTM_VER "1"
#define JS_VER "0"
#define CFG_VER "1"


/******************** Function declarations *******************/

// global app specific functions

void appSetup();

/******************** Global app declarations *******************/
