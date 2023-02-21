// Global AdBlocker declarations
//
// s60sc 2022

#pragma once
#include "globals.h"

/********************* fixed defines leave as is *******************/ 
/** Do not change anything below here unless you know what you are doing **/

//#define DEV_ONLY // leave commented out
#define STATIC_IP_OCTAL "168" // dev only
#define CHECK_MEM false // leave as false
#define FLUSH_DELAY 0 // for debugging crashes
 
#define APP_NAME "ESP32_AdBlocker" // max 15 chars
#define APP_VER "2.0"

#define MAX_CLIENTS 2 // allowing too many concurrent web clients can cause errors
#define DATA_DIR "/data"
#define HTML_EXT ".htm"
#define TEXT_EXT ".txt"
#define JS_EXT ".js"
#define CSS_EXT ".css"
#define ICO_EXT ".ico"
#define SVG_EXT ".svg"
#define INDEX_PAGE_PATH DATA_DIR "/AdBlocker" HTML_EXT
#define CONFIG_FILE_PATH DATA_DIR "/configs" TEXT_EXT
#define LOG_FILE_PATH DATA_DIR "/log" TEXT_EXT
#define OTA_FILE_PATH DATA_DIR "/OTA" HTML_EXT 
#define FILE_NAME_LEN 128
#define ONEMEG (1024 * 1024)
#define MAX_PWD_LEN 64
#define JSON_BUFF_LEN (1024 * 4) 
#define MAX_CONFIGS 50 // > number of entries in configs.txt
#define GITHUB_URL "https://raw.githubusercontent.com/s60sc/ESP32_AdBlocker/master"

#define FILLSTAR "****************************************************************"
#define DELIM '~'
#define STORAGE LittleFS // use of SPIFFS, LIttleFS or SD_MMC
#define RAMSIZE (1024 * 8) 
#define CHUNKSIZE (1024 * 4)
//#define INCLUDE_FTP 
//#define INCLUDE_SMTP
//#define INCLUDE_SD

#define IS_IO_EXTENDER true // must be true for IO_Extender
#define EXTPIN 100

/******************** Function declarations *******************/

// global app specific functions
void appSetup();

/******************** Global app declarations *******************/
