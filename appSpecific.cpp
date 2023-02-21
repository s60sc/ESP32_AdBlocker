// AdBlocker specific functions
//

// s60sc 2020, 2023

#include "appGlobals.h"
#include "AdBlockerDNSServer.h" // customised

static uint8_t updateHour;
static size_t maxDomains; // for reserving ptrs memory
static size_t minMemory; // min free memory after vector populated
static const uint16_t maxLineLen = 1024; // max length of line processed in downloaded blocklists
static uint8_t maxDomLen; // max length of domain name in blocklist
static char fileURL[FILE_NAME_LEN];

static DNSServer dnsServer;
static const byte DNS_PORT = 53;
static TaskHandle_t dnsTaskHandle = NULL;
static int timeoutVal = 10000; // 10 secs on download stream data being available

static std::vector<std::string> blockVec; // holds sorted list of blocked domains in memory
static size_t blocklistSize = 0;
static uint8_t domainLine[maxLineLen];
static uint32_t blockCnt = 0, allowCnt = 0, itemsLoaded = 0;

size_t storageSize;
uint32_t* ptrs; // ordered pointers to domain names
char* storage; // linear domain name storage

struct {
  char* lastDomain;
  bool lastResult;
} lastCheck;

static float inline inKB(size_t inVal) {
  return (float)(inVal / 1024.0);
}

static void dnsTask(void* parameter) {
  // higher priority than loop()
  while (true) dnsServer.processNextRequest();
  vTaskDelete(NULL);
}

uint32_t binarySearch(const char* searchStr, bool isInsert = false) {
  // binary split search
  int first = 0, ptr = 0;
  int last = itemsLoaded - 1;
  while (first <= last) {
    ptr = (first + last) / 2;
    int diff = strcmp(storage + ptrs[ptr], searchStr);
    if (diff < 0) first = ptr + 1;     
    else if (diff > 0) last = ptr - 1;
    else return ptr; // match
  } 
  return isInsert ? ptr : 0; // end of search
}
 
void addDomain(const char* domainStr, size_t domLen) {
  // domain names stored linearly in 'storage' in order received
  // pointer to each domain stored in 'ptrs' sorted alphabetically by corresponding domain 
 
  // get location to insert domain pointer
  uint32_t ptr = binarySearch(domainStr, true);
  // check what is already at location 
  int diff = strcmp(storage + ptrs[ptr], domainStr);

  if (diff != 0) {
    // append domain name to storage
    memcpy(storage + blocklistSize, domainStr, domLen);
    // make space for new domain pointer at identified location by shifting following locations
    if (diff < 0) ptr++; // to insert after
    memmove(&ptrs[ptr + 1], &ptrs[ptr], (itemsLoaded - ptr) * sizeof(uint32_t));
    // insert new domain pointer
    ptrs[ptr] = blocklistSize; // points to latest domain name in 'storage'
    blocklistSize += domLen + 1;
    itemsLoaded++;
  } // ignore duplicate
}

IPAddress checkBlocklist(const char* domainName) {
  // called from ESP32_DNSServer
  IPAddress ip = IPAddress(0, 0, 0, 0); // IP to return for blocked domain
  if (strlen(domainName)) {
    uint64_t usElapsed = micros();
    // check if received domain name same as previous (due to multiple calls)
    bool blocked = false;
    if (!strcmp(domainName, lastCheck.lastDomain)) blocked = lastCheck.lastResult;
    // search for domain in blocklist
    else blocked = (bool)binarySearch(domainName);
    strcpy(lastCheck.lastDomain, domainName);
    lastCheck.lastResult = blocked;
    blocked ? ++blockCnt : ++allowCnt;
    uint64_t checkTime = micros() - usElapsed;
    uint32_t mselapsed = millis();
    // if not blocked, get IP address for domain from external DNS
    if (!blocked) WiFi.hostByName(domainName, ip);

    if (dbgVerbose) {
      char statusMsg[200];
      snprintf(statusMsg, 160, "%s %s in %lluus", (blocked) ? "*Blocked*" : "Allowed", domainName, checkTime);
      if (!blocked) sprintf(statusMsg + strlen(statusMsg), ", resolved to %s in %lums", ip.toString().c_str(), millis() - mselapsed);
      LOG_DBG("%s", statusMsg);
    }
  }
  return ip;
}

static void extractBlocklist() {
  // extract domain names from downloaded blocklist file
  char* saveItem = NULL;
  char* tokenItem;
  char* domStr = (char*)domainLine;

  // for each line
  if (strncmp(domStr, "127.0.0.1", 9) == 0 || strncmp(domStr, "0.0.0.0", 7) == 0) {
    // HOSTS file format matched, extract domain name
    tokenItem = strtok_r(domStr, " \t", &saveItem); // skip over first token
    if (tokenItem != NULL) tokenItem = strtok_r(NULL, " \t", &saveItem); // domain in second token
  } else {
    if (strncmp(domStr, "||", 2) == 0) tokenItem = strtok_r(domStr, "|^", &saveItem); // Adblock format - domain in first token
    else tokenItem = NULL; // no match
  }

  if (tokenItem != NULL) {
    // write processed line to storage
    int wwwOffset = (strncmp(tokenItem, "www.", 4) == 0) ? 4 : 0;  // remove any leading "www."
    char* domName = tokenItem + wwwOffset;
    size_t domLen = strlen(tokenItem) - wwwOffset;
    if (domLen < maxDomLen) addDomain(domName, domLen);
  }
}

static bool downloadFile() {
  // download blocklist file from web
  WiFiClientSecure wclient;
  HTTPClient https;
  size_t downloadSize = 0;
  char progStr[10];
  wclient.setCACert(git_rootCACertificate);  
  if (!https.begin(wclient, fileURL)) {
    char errBuf[100];
    wclient.lastError(errBuf, 100);
    LOG_ERR("Could not connect to github server, err: %s", errBuf);
    return false;
  } else {
    LOG_INF("Downloading %s\n", fileURL);    
    int httpCode = https.GET();
    if (httpCode > 0) {
      uint32_t loadTime = millis();
      if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY) {
        // file available for download
        // get length of content (is -1 when Server sends no Content-Length header)
        int left = https.getSize();
        left > 0 ? LOG_INF("File size: %u bytes", left) : LOG_WRN("File size unknown");
        LOG_INF("%0.1fKB memory available for download", inKB(storageSize));
        if (left > storageSize) LOG_WRN("File too large, will be truncated");
        WiFiClient* stream = https.getStreamPtr(); // stream data to client
        uint32_t lastRead = millis();
        size_t lineCnt = 0;
        
        while (https.connected() && (left > 0 || left == -1)) {
          if (stream->available()) {
            size_t lineSize = stream->readBytesUntil('\n', domainLine, maxLineLen); 
            domainLine[lineSize] = 0;
            lineSize++; // add in count for terminator
            downloadSize += lineSize;
            if (left > 0) left -= lineSize;
            extractBlocklist();
            if (itemsLoaded >= maxDomains) {
              LOG_WRN("Blocklist truncated as domain limit reached %u", maxDomains);
              break;
            }
            if (++lineCnt%1000 == 0) { 
              // periodically check remaining memory 
              size_t remaining = storageSize - blocklistSize;
              if (remaining < minMemory) {
                LOG_WRN("Blocklist truncated to avoid memory overflow, %u bytes remaining\n", remaining);
                break; 
              }
              // show progress 
              if (left > 0) {
                float loadProg = (float)(downloadSize * 100.0 / (downloadSize + left));
                logPrint("%0.1f%%\n", loadProg);
                sprintf(progStr, "%0.1f%%", loadProg);
                updateConfigVect("loadProg", progStr);
              }
              else showProgress();
            } 
            lastRead = millis();
          } else if (millis() - lastRead > timeoutVal) {
            // timed out on read
            LOG_WRN("Timeout on download, %u bytes unread", left);
            break;
          }
        }
        ptrs[itemsLoaded] = blocklistSize;
        LOG_INF("Download complete, processed %u bytes in %u secs", downloadSize, (millis() - loadTime)/1000);
        LOG_INF("Loaded %u blocked domains, using %0.1fKB of %0.1fKB", itemsLoaded, inKB(blocklistSize), inKB(storageSize));
        updateConfigVect("loadProg", "100%");
      } else LOG_WRN("Unexpected result code %u %s", httpCode, https.errorToString(httpCode).c_str());
    } else {
      LOG_ERR("Connection failed with error: %s", https.errorToString(httpCode).c_str());
      return false;
    }
  } 
  https.end();
  wclient.stop();
  return true;
}

static void prepDNS(const char* reason) {
  // load or refresh blocklist file
  static bool downloading = false;
  if (!downloading) {
    downloading = true;
    LOG_INF("%s load of latest blocklist", reason);
    if (dnsTaskHandle != NULL) vTaskDelete(dnsTaskHandle);
    
    while(!downloadFile()) {
      LOG_WRN("Failed to complete blocklist download, retry ...");
      delay(10000);
    }
  
    // DNS server startup
    delay(1000);
    dnsServer.setErrorReplyCode(DNSReplyCode::ServerFailure);
    if (dnsServer.start(DNS_PORT, "*", WiFi.localIP())) {
      LOG_INF("DNS Server started on %s:%d", WiFi.localIP().toString().c_str(), DNS_PORT);
      delay(100);
      xTaskCreate(&dnsTask, "dnsTask", 4096, NULL, 2, &dnsTaskHandle);
    } else {
      LOG_ERR("Aborting as DNS Server not running");
      delay(10000);
      ESP.restart();
    }
    downloading = false;
  } else LOG_WRN("Already downloading - ignored %s", reason);
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

static void checkAlarm() {
  // once per day at given time, load latest blocklist from host site
  static time_t rolloverEpoch = setAlarm(updateHour);
  if (getEpoch() >= rolloverEpoch) prepDNS("Scheduled");
}

void doAppPing() {
  if (timeSynchronized) checkAlarm();
}

void appSetup() {  
  if (!strlen(fileURL)) {
    LOG_WRN("Enter blocklist URL on web page ...");
    while (!strlen(fileURL)) delay(1000); // wait for file URL to be entered
  } 
  lastCheck.lastDomain = (char*)malloc(maxDomLen);
  
  ptrs = (uint32_t*)ps_malloc((maxDomains + 2) * sizeof(uint32_t));
  storageSize = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
  storage = (char*)ps_calloc(storageSize, sizeof(char));

  // prime domain storage
  memcpy(storage, "!", 1);
  blocklistSize = 2;
  itemsLoaded = 1;
  allowCnt = blockCnt = 0;
  updateConfigVect("blockCnt", "0");
  updateConfigVect("allowCnt", "0");   
  prepDNS("Initial");
}

/****************************** callbacks ******************************/

bool updateAppStatus(const char* variable, const char* value) {
  // update vars from browser input
  bool res = true; 
  int intVal = atoi(value);
  if (!strcmp(variable, "fileURL")) strncpy(fileURL, value, FILE_NAME_LEN-1);
  if (!strcmp(variable, "updateHour")) updateHour = intVal;
  if (!strcmp(variable, "maxDomains")) maxDomains = intVal * 1000;
  if (!strcmp(variable, "minMemory")) minMemory = intVal * 1024;
  if (!strcmp(variable, "maxDomLen")) maxDomLen = intVal;
  if (!strcmp(variable, "reload")) prepDNS("Requested");
  return res;
}

void wsAppSpecificHandler(const char* wsMsg) {
  // message from web socket
  int wsLen = strlen(wsMsg) - 1;
  switch ((char)wsMsg[0]) {
    case 'H': 
      // keepalive heartbeat, return status
    break;
    case 'S': 
      // status request
      buildJsonString(wsLen); // required config number 
      logPrint("%s\n", jsonBuff);
    break;   
    case 'U': 
      // update or control request
      memcpy(jsonBuff, wsMsg + 1, wsLen); // remove 'U'
      parseJson(wsLen);
    break;
    case 'K': 
      // kill websocket connection
      killWebSocket();
    break;
    default:
      LOG_WRN("unknown command %c", (char)wsMsg[0]);
    break;
  }
}

void buildAppJsonString(bool filter) {
  // build app specific part of json string
  char* p = jsonBuff + 1;
  *p = 0;
}

esp_err_t webAppSpecificHandler(httpd_req_t *req, const char* variable, const char* value) {
  char cntStr[20];
  sprintf(cntStr, "%u", blockCnt);
  updateConfigVect("blockCnt", cntStr);
  sprintf(cntStr, "%u", allowCnt);
  updateConfigVect("allowCnt", cntStr);
  return ESP_OK;
}

bool appDataFiles() {
  // callback from setupAssist.cpp, for any app specific files 
  return true;
}

void OTAprereq() {} // dummy 
