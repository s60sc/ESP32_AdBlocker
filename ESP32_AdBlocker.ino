 /*
   ESP32_AdBlocker acts as a DNS Sinkhole by returning 0.0.0.0 for any domain names in its blocked list, 
   else forwards to an external DNS server to resolve IP addresses. This prevents content being retrieved 
   from or sent to blocked domains. Searches generally take <200us.

   To use ESP32_AdBlocker, enter its IP address in place of the DNS server IPs in your router/devices.
   Currently it does have an IPv6 address and some devices use IPv6 by default, so disable IPv6 DNS on 
   your device / router to force it to use IPv4 DNS.

   Blocklist files can downloaded from hosting sites and should either be in HOSTS format 
   or Adblock format (only domain name entries processed)

   arduino-esp32 library DNSServer.cpp modified as custom AdBlockerDNSServer.cpp so that DNSServer::processNextRequest()
   calls checkBlocklist() in ESP32_AdBlocker to check if domain blocked, which returns the relevant IP. 
   Based on idea from https://github.com/rubfi/esphole

   Compile with partition scheme 'No OTA (2M APP/2M SPIFFS)'

   s60sc 2021
*/

#include <WiFi.h>
#include <FS.h>
#include "SPIFFS.h"
#include <SD_MMC.h>
#include <string>
#include <algorithm>
#include <bits/stdc++.h>
//#include <unordered_map>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ESPAsyncWebServer.h>
#include <Preferences.h>

#include "AdBlockerDNSServer.h" // customised
#include "AdBlockerWebPage.h"

static const bool USESPIFFS = true; // set to false to store blocklist on SD card
static const char* WIFISSID = ""; // router ssid
static const char* WIFIPASS = ""; // router password
#define TIMEZONE "GMT+0BST-1,M3.5.0/01:00:00,M10.5.0/02:00:00" // local timezone string (https://sites.google.com/a/usapiens.com/opnode/time-zones)

static const IPAddress ADBLOCKER(192, 168, 1, 128); // static IP for ESP32_AdBlocker DNS Server
static const IPAddress RESOLVER(1, 1, 1, 1); // use whatever is fastest external DNS server
static const IPAddress GATEWAY(192, 168, 1, 1); // router
static const IPAddress SUBNET(255, 255, 255, 0);

static const size_t MIN_MEMORY = 20000; // minimum amount of memory to keep free
static const size_t MAX_LINELEN = 200; // max length of line processed in downloaded blocklists
static const uint8_t UPDATE_HOUR = 4; // do daily blocklist update at 4am
static const size_t MAX_DOMAINS = 65535; // maximum number of domains, >64K crashes esp32 

static AsyncWebServer webServer(80);
static DNSServer dnsServer;
static const byte DNS_PORT = 53;
static TaskHandle_t dnsTaskHandle = NULL;

//std::unordered_set <std::string> blockSet ; // holds hashed list of blocked domains in memory [too much memory overhead]
std::vector<std::string> blockVec; // holds sorted list of blocked domains in memory
static uint8_t* downloadBuff; // temporary store for ptocessing downloaded blocklist file
static char whichStorage[10];
static fs::FS useFH = SPIFFS;
static const char* BLOCKLISTFILE = {"/BlockedList"};
static const size_t jsonLen = 200;
static char jsonData[jsonLen];
static uint32_t blockCnt, allowCnt = 0;
static char fileURL[jsonLen];
static Preferences preferences;
enum prefType {SET, GET, CLEAR};

static float inline inKB(size_t inVal) {
  return (float)(inVal / 1024.0);
}

void setup() {  
  printf("Sketch size %0.1fKB, PSRAM %s available\n", inKB(ESP.getSketchSize()), (psramFound()) ? "IS" : "NOT");
  startWifi();
  getNTP();
  startWebServer();

  if (!mountFS()) {
    puts("Aborting as no filesystem available");
    return;
  }
  storedURL(GET);
  if (!strlen(fileURL)) {
    if (USESPIFFS) {
      puts("Formatting SPIFFS ...");
      SPIFFS.format(); // spiffs can fail to store large files if not freshly formatted
    } else useFH.remove(BLOCKLISTFILE);
    if (useFH.exists(BLOCKLISTFILE)) {
      printf("Aborting, need to manually delete %s\n", BLOCKLISTFILE);
      return;
    } else {
      puts("Enter blocklist URL on web page ...");
      while (true) delay(1000); // wait for restart
    }
  }
  bool haveBlocklist = useFH.exists(BLOCKLISTFILE);
  if (!haveBlocklist) {
    puts("No blocklist stored, need to download ...");
    if (downloadFile()) haveBlocklist = createBlocklist();
  } else haveBlocklist = loadBlocklist();

  if (haveBlocklist) {
    // DNS server startup
    dnsServer.setErrorReplyCode(DNSReplyCode::ServerFailure);
    if (dnsServer.start(DNS_PORT, "*", WiFi.localIP())) {
      printf("\nDNS Server started on %s:%d\n", WiFi.localIP().toString().c_str(), DNS_PORT);
      delay(100);
      xTaskCreate(&dnsTask, "dnsTask", 4096, NULL, 2, &dnsTaskHandle);
    } else {
      puts("Aborting as DNS Server not running");
      return;
    }
  } else {
    puts("Aborting as no resources available");
    return;
  }
  printf("Free DRAM: %0.1fKB, Free PSRAM: %0.1fKB\n*** Ready...\n\n", inKB(ESP.getFreeHeap()), inKB(ESP.getFreePsram()));
}

void loop() {
  checkAlarm();
  delay(100000);
}

static void startWifi() {
  WiFi.mode(WIFI_AP_STA);
  printf("Connect to SSID: %s\n", WIFISSID);
  WiFi.config(ADBLOCKER, GATEWAY, SUBNET, RESOLVER);
  WiFi.begin(WIFISSID, WIFIPASS);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    printf(".");
  }
  puts("");
}

static void dnsTask(void* parameter) {
  // higher priority than loop()
  while (true) dnsServer.processNextRequest();
  vTaskDelete(NULL);
}

IPAddress checkBlocklist(const char* domainName) {
  // called from ESP32_DNSServer
  IPAddress ip = IPAddress(0, 0, 0, 0); // IP to return for blocked domain
  if (strlen(domainName)) {
    uint64_t uselapsed = micros();
    // search for domain in blocklist
    //bool blocked = (blockSet.find(std::string(domainName)) == blockSet.end()) ? false : true;
    bool blocked = binary_search(blockVec.begin(), blockVec.end(), std::string(domainName));
    uint64_t checkTime = micros() - uselapsed;

    uint32_t mselapsed = millis();
    // if not blocked, get IP address for domain from external DNS
    if (!blocked)  WiFi.hostByName(domainName, ip);
    uint32_t resolveTime = millis() - mselapsed;

    printf("%s %s in %lluus", (blocked) ? "*Blocked*" : "Allowed", domainName, checkTime);
    if (!blocked) printf(", resolved to %s in %ums\n", ip.toString().c_str(), resolveTime);
    else puts("");

    if (blocked) blockCnt++;
    else allowCnt++;
  }
  return ip;
}

static bool loadBlocklist() {
  // load blocklist file into memory from storage
  size_t remaining = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  printf("Loading blocklist %s\n", fileURL);
  uint32_t loadTime = millis();
  if (psramFound()) heap_caps_malloc_extmem_enable(5); // force vector into psram
  blockVec.reserve((psramFound()) ? MAX_DOMAINS : 1000);
  if (psramFound()) heap_caps_malloc_extmem_enable(100000);
  
  File file = useFH.open(BLOCKLISTFILE, FILE_READ);
  if (file) {
    printf("File size %0.1fKB on %s loading into %0.1fKB %s memory ...\n", inKB(file.size()),
      whichStorage, inKB(remaining), (psramFound()) ? "PSRAM" : "DRAM");
    char domainLine[MAX_LINELEN + 1];
    int itemsLoaded = 0;
    if (psramFound()) heap_caps_malloc_extmem_enable(5); // force vector into psram

    while (file.available()) {
      size_t lineLen = file.readBytesUntil('\n', domainLine, MAX_LINELEN);
      if (lineLen) {
        domainLine[lineLen] = 0;
        //blockSet.insert(std::string(domainLine));
        blockVec.push_back(std::string(domainLine));
        itemsLoaded++;
        if (itemsLoaded%500 == 0) { // check memory too often triggers watchdog
          remaining = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
          if (remaining < (MIN_MEMORY)) {
            printf("Blocklist truncated to avoid memory overflow, %u bytes remaining\n", remaining);
            break;
          }
        }
        if (itemsLoaded >= MAX_DOMAINS ) {
          // max 64K vectors else esp32 crashes
          printf("Blocklist truncated as maximum number of domains loaded - %u\n", MAX_DOMAINS);
          break;
        }
      }
    }
    file.close();
    //for (int i=0; i < blockVec.size(); i++) printf("%s\n", blockVec.at(i).c_str());

    if (psramFound()) heap_caps_malloc_extmem_enable(100000);
    if (!itemsLoaded) {
      puts("Aborting as empty blocklist read ..."); // SPIFFS issue
      storedURL(CLEAR);
      delay(100);
      ESP.restart();
    }
    printf("Loaded %u domains from blocklist file in %.01f secs\n", itemsLoaded, (float)((millis() - loadTime) / 1000.0));
    return true;
  }
  puts(" - not found");
  return false;
}

static bool sortBlocklist() {
  // read downloaded blocklist from storage, sort in alpha order to allow binary search, rewrite to storage
  free(downloadBuff);
  delay(100);
  if (loadBlocklist()) {
    puts("Sorting blocklist alphabetically ...");
    uint32_t sortTime = millis();
    sort(blockVec.begin(), blockVec.end());
    printf("Sorted blocklist after %0.1f secs, saving to file ...\n", (float)((millis() - sortTime) / 1000.0));
    sortTime = millis();
    std::string previous = "";
    int duplicate = 0;
    
    // rewrite file with sorted domains
    useFH.remove(BLOCKLISTFILE);
    File file = useFH.open(BLOCKLISTFILE, FILE_WRITE);
    if (file) {
      for (auto domain : blockVec) {
        if (domain.compare(previous) != 0) {
          // store unduplicated domain
          file.write((uint8_t*)domain.c_str(), strlen(domain.c_str()));
          file.write((uint8_t*)"\n", 1);
          previous.assign(domain);
        } else duplicate++;
      }
      file.close();
      printf("Saved into file removing %u duplicates after %0.1f secs, restarting ...\n", duplicate, (float)((millis() - sortTime) / 1000.0));
      delay(100);
      ESP.restart(); // quicker to restart than clear vector
      return true;
    } else puts ("Failed to write to blocklist file");
  }
  return false;
}

static size_t inline extractDomains() {
  // extract domain names from downloaded blocklist
  size_t downloadBuffPtr = 0;
  char *saveLine, *saveItem = NULL;
  char* tokenLine = strtok_r((char*)downloadBuff, "\n", &saveLine);
  char* tokenItem;

  // for each line
  while (tokenLine != NULL) {
    if (strncmp(tokenLine, "127.0.0.1", 9) == 0 || strncmp(tokenLine, "0.0.0.0", 7) == 0) {
      // HOSTS file format matched, extract domain name
      tokenItem = strtok_r(tokenLine, " \t", &saveItem); // skip over first token
      if (tokenItem != NULL) tokenItem = strtok_r(NULL, " \t", &saveItem); // domain in second token
    } else if (strncmp(tokenLine, "||", 2) == 0)
      tokenItem = strtok_r(tokenLine, "|^", &saveItem); // Adblock format - domain in first token
    else tokenItem = NULL; // no match
    if (tokenItem != NULL) {
      // write processed line back to buffer
      size_t itemLen = strlen(tokenItem);
      int wwwOffset = (strncmp(tokenItem, "www.", 4) == 0) ? 4 : 0;  // remove any leading "www."
      memcpy(downloadBuff + downloadBuffPtr, tokenItem + wwwOffset, itemLen - wwwOffset);
      downloadBuffPtr += itemLen;
      memcpy(downloadBuff + downloadBuffPtr, (uint8_t*)"\n", 1);
      downloadBuffPtr++;
    }
    tokenLine = strtok_r(NULL, "\n", &saveLine);
  }
  downloadBuff[downloadBuffPtr] = 0; // string terminator
  return downloadBuffPtr;
}

static bool createBlocklist() {
  // after blocklist file downloaded, the content is parsed to extract the domain names, then written to storage
  uint32_t createTime = millis();
  size_t blocklistSize = extractDomains();
  // check storage space available, else abort
  size_t storageAvailable = (USESPIFFS) ? (SPIFFS.totalBytes() - SPIFFS.usedBytes()) : (SD_MMC.totalBytes() - SD_MMC.usedBytes());
  storageAvailable -= 1024*32; // leave overhead space
  if (storageAvailable < blocklistSize) {
    printf("Aborting as insufficient storage %0.1fKB on %s ...\n", inKB(storageAvailable), whichStorage);
    storedURL(CLEAR);
    delay(100);
    ESP.restart();
  }
  printf("Creating extracted unsorted blocklist of %0.1fKB on %s\n", inKB(blocklistSize), whichStorage);
  File file = useFH.open(BLOCKLISTFILE, FILE_WRITE);
  if (file) {
    // write buffer to file
    size_t written = file.write(downloadBuff, blocklistSize);
    if (!written) {
      puts("Aborting as blocklist empty after writing ..."); // SPIFFS issue
      storedURL(CLEAR);
      delay(100);
      ESP.restart();
    }
    file.close();
    printf("Blocklist file of %0.1fKB created in %.01f secs\n", inKB(written), (float)((millis() - createTime) / 1000.0));
    return (sortBlocklist());
  } else printf("Failed to store blocklist %s\n", BLOCKLISTFILE);
  free(downloadBuff);
  return false;
}

static bool downloadFile() {
  size_t downloadBuffPtr = 0;
  WiFiClientSecure *client = new WiFiClientSecure;
  if (!client) {
    puts("Failed to create secure client");
    return false;
  } else {
    // scoping block
    {
      HTTPClient http;
      // open connection to blocklist host
      if (http.begin(*client, fileURL)) {
        printf("Download %s\n", fileURL);
        uint32_t loadTime = millis();
        // start connection and send HTTP header
        int httpCode = http.GET();

        if (httpCode > 0) {
          printf("Response code: %d\n", httpCode);
          if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY) {
            // get length of content (is -1 when Server sends no Content-Length header)
            int len = http.getSize();
            if (len > 0) printf("File size: %0.1fKB", inKB(len));
            else printf("File size unknown");
            size_t availableMem = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
            printf(", with %0.1fKB memory available for download ...\n", inKB(availableMem));
            if (len > 0 && len > availableMem) {
              puts("Aborting as file too large");
              storedURL(CLEAR);
              delay(100);
              ESP.restart();
            }

            int chunk = 128; // amount to consume per read of stream
            // allocate memory for download buffer
            downloadBuff = (psramFound()) ? (uint8_t*)ps_malloc(availableMem) : (uint8_t*)malloc(availableMem);
            WiFiClient * stream = http.getStreamPtr(); // stream data to client

            while (http.connected() && (len > 0 || len == -1)) {
              size_t streamSize = stream->available();
              if (streamSize) {
                // consume up to chunk bytes and write to memory
                int readc = stream->readBytes(downloadBuff + downloadBuffPtr, ((streamSize > chunk) ? chunk : streamSize));
                downloadBuffPtr += readc;
                if (len > 0) len -= readc;
                if ((downloadBuffPtr + chunk) >= availableMem) {
                  puts("Aborting as file too large");
                  storedURL(CLEAR);
                  delay(100);
                  ESP.restart();
                }
              }
              delay(1);
            }
            downloadBuff[downloadBuffPtr] = 0; // string terminator
            printf("Download completed in %0.1f secs, stored %0.1fKB\n", ((millis() - loadTime) / 1000.0), inKB(downloadBuffPtr));
          }
        } else printf("Connection failed with error: %s\n", http.errorToString(httpCode).c_str());
      } else {
        printf("Unable to download %s\n", fileURL);
        storedURL(CLEAR);
        delay(100);
        ESP.restart();
      }
      http.end();
    }
    delete client;
  }
  return (downloadBuffPtr) ? true : false;
}

static bool mountFS() {
  // set up required file system
  if (USESPIFFS) {
    if (SPIFFS.begin(true)) { // format on fail
      useFH = SPIFFS;
      strcpy(whichStorage, "SPIFFS");
      printf("SPIFFS: using %0.1fkB of total %0.1fKB\n", inKB(SPIFFS.usedBytes()), inKB(SPIFFS.totalBytes()));
      return true;
    } else puts("Failed to mount SPIFFS");
  } else {
    if (SD_MMC.begin("/sdcard", true)) {  // one line mode
      useFH = SD_MMC;
      strcpy(whichStorage, "SD_MMC");
      printf("SD card: using %0.1fMB of total %0.1fMB\n", (float)(SD_MMC.usedBytes() / (1024 * 1024)), (float)(SD_MMC.totalBytes() / (1024 * 1024)));
      return true;
    } else puts("Failed to mount SD_MMC");
  }
  return false;
}

static void storedURL(prefType action) {
  preferences.begin("ESP32_AdBlocker");
  if (action == GET) strncpy(fileURL, preferences.getString("fileURL").c_str(), jsonLen-1);
  else {
    if (action == SET) preferences.putString("fileURL", String(fileURL));
    else if (action == CLEAR) preferences.clear();
  }
  preferences.end();
}

static void refreshHandler(AsyncWebServerRequest *request) {
  // refresh web page with latest data
  static bool firstRefresh = true;
  if (firstRefresh) snprintf(jsonData, jsonLen, "{\"1\":\"%u\",\"2\":\"%u\",\"3\":\"%s\"}", allowCnt, blockCnt, fileURL);
  else snprintf(jsonData, jsonLen, "{\"1\":\"%u\",\"2\":\"%u\"}", allowCnt, blockCnt);
  firstRefresh = false;
  request->send(200, "application/json", jsonData);
}

static void resetHandler(AsyncWebServerRequest *request) {
  // factory reset
  request->send(200);
  puts("User requested reset of storage and NVS, restarting ...");
  storedURL(CLEAR);
  delay(100);
  ESP.restart();
}

static void updateHandler(AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
  // reload from supplied blocklist host site 
  request->send(200);
  // dirty extract of file URL
  memcpy(fileURL, (char*)data + 6, len - 6 - 2);
  fileURL[len - 6 - 2] = 0;
  printf("Restarting, user updated blocklist file URL: %s ...\n", fileURL);
  storedURL(SET);
  delay(100);
  ESP.restart();
}

static void startWebServer() {
  webServer.on("/", HTTP_GET, [](AsyncWebServerRequest * request) {
    request->send(200, "text/html", index_html);
  });
  webServer.on("/refresh", HTTP_GET, refreshHandler);
  webServer.on("/reset", HTTP_GET, resetHandler);
  webServer.on("/update", HTTP_POST, [](AsyncWebServerRequest * request) {}, NULL, updateHandler);
  webServer.onNotFound([](AsyncWebServerRequest * request) {
    request->send(404, "text/plain", "Not found: " + request->url());
  });
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Origin", "*"); // prevent CORS error
  webServer.begin();
  printf("Web Server started on %s:%d\n", WiFi.localIP().toString().c_str(), 80);
}

static inline time_t getEpochSecs() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec;
}

static void getNTP() {
  // get current time from NTP server and apply to ESP32
  const char* ntpServer = "pool.ntp.org";
  const long gmtOffset_sec = 0;  // offset from GMT
  const int daylightOffset_sec = 3600; // daylight savings offset in secs
  int i = 0;
  do {
    configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
    delay(1000);
  } while (getEpochSecs() < 1000 && i++ < 5); // try up to 5 times
  // set timezone as required
  setenv("TZ", TIMEZONE, 1);
  if (getEpochSecs() > 1000) {
    time_t currEpoch = getEpochSecs();
    char timeFormat[20];
    strftime(timeFormat, sizeof(timeFormat), "%d/%m/%Y %H:%M:%S", localtime(&currEpoch));
    printf("Got current time from NTP: %s\n", timeFormat);
  }
  else puts("Unable to sync with NTP");
}

static void checkAlarm() {
  // once per day at given time, load updated blocklist from host site
  static time_t rolloverEpoch = setAlarm(UPDATE_HOUR);
  if (getEpochSecs() >= rolloverEpoch) { 
    puts("Scheduled restart to load updated blocklist ...");
    delay(100);
    if (dnsTaskHandle != NULL) vTaskDelete(dnsTaskHandle);
    ESP.restart();
  }
}

static time_t setAlarm(uint8_t alarmHour) {
  // calculate future alarm datetime based on current datetime
  struct tm* timeinfo;
  time_t rawtime;
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  // set alarm date & time for next day at given hour
  timeinfo->tm_mday += 1; 
  timeinfo->tm_hour = alarmHour;
  timeinfo->tm_min = 0;
  // return future datetime as epoch seconds
  return mktime(timeinfo);
}
