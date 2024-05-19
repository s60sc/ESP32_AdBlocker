// AdBlocker specific functions
//
// s60sc 2020, 2023

#include "appGlobals.h"
#include "AdBlockerDNSServer.h" // customised

const size_t prvtkey_len = 0;
const size_t cacert_len = 0;
const char* prvtkey_pem = "";
const char* cacert_pem = "";

static size_t maxDomains; // for reserving ptrs memory
static size_t minMemory; // min free memory after vector populated
static const uint16_t maxLineLen = 1024; // max length of line processed in downloaded blocklists
static uint8_t maxDomLen; // max length of domain name in blocklist
static char fileURL[IN_FILE_NAME_LEN] = {0};

static DNSServer dnsServer;
static const byte DNS_PORT = 53;
static TaskHandle_t dnsTaskHandle = NULL;
static int timeoutVal = 10000; // 10 secs on download stream data being available

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
  // the number of unique domains may be lower than the source file which may have
  // entries of the form www .vinted-pl-id002c.celebx.top and vinted-pl-id002c.celebx.top
  // which are treated in this app as a single entry as the www is ignored
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
                                                                
static bool downloadBlockList() {
  // download blocklist file from web
  bool res = false;
  WiFiClientSecure wclient;
  if (remoteServerConnect(wclient, GITHUB_HOST, HTTPS_PORT, git_rootCACertificate)) {
    HTTPClient https;
    size_t downloadSize = 0;
    char progStr[10];

    if (https.begin(wclient, fileURL)) {
      LOG_INF("Downloading %s\n", fileURL);
      int httpCode = https.GET();
      if (httpCode > 0) {
        uint32_t loadTime = millis();
        if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY) {
          // file available for download
          // get length of content (is -1 when Server sends no Content-Length header)
          int left = https.getSize();
          left > 0 ? LOG_INF("File size: %u bytes", left) : LOG_WRN("File size unknown");
          LOG_INF("%s memory available for download", fmtSize(storageSize));
          if (left > storageSize) LOG_WRN("File is larger than memory, may get truncated");
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
                LOG_ALT("Blocklist truncated as domain limit reached %u", maxDomains);
                break;
              }
              if (++lineCnt % 1000 == 0) {
                // periodically check remaining memory
                size_t remaining = storageSize - blocklistSize;
                if (remaining < minMemory) {
                  LOG_ALT("Blocklist truncated to avoid memory overflow, %u bytes remaining\n", remaining);
                  break;
                }
                // show progress
                if (left > 0) {
                  float loadProg = (float)(downloadSize * 100.0 / (downloadSize + left));
                  logPrint("%0.1f%%\n", loadProg);
                  sprintf(progStr, "%0.1f%%", loadProg);
                  updateConfigVect("loadProg", progStr);
                }
              }
              lastRead = millis();
            } else if (millis() - lastRead > timeoutVal) {
              // timed out on read
              if (left > 0) LOG_WRN("Timeout on download, %s unread", fmtSize(left));
              break;
            }
          }
          ptrs[itemsLoaded] = blocklistSize;
          LOG_INF("Download complete, processed %s in %u secs", fmtSize(downloadSize), (millis() - loadTime) / 1000);
          LOG_ALT("Loaded %u blocked domains, using %s of %s", itemsLoaded, fmtSize(blocklistSize), fmtSize(storageSize));
          updateConfigVect("loadProg", "Complete");
          res = true;
        } else LOG_WRN("Unexpected result code %u %s", httpCode, https.errorToString(httpCode).c_str());
      } else LOG_ERR("Connection failed with error: %s", https.errorToString(httpCode).c_str());
    } else {
      char errBuf[100] = {0};
      wclient.lastError(errBuf, 100);
      LOG_ERR("Could not connect to %s, err: %s", fileURL, errBuf);
    }
    https.end();
  } 
  remoteServerClose(wclient);
  return res;
}

static void prepDNS() {
  // DNS server startup
  if (dnsTaskHandle != NULL) vTaskDelete(dnsTaskHandle);
  dnsServer.setErrorReplyCode(DNSReplyCode::ServerFailure);
  if (dnsServer.start(DNS_PORT, "*", WiFi.localIP())) {
    LOG_INF("DNS Server started on %s:%d", WiFi.localIP().toString().c_str(), DNS_PORT);
    delay(100);
    xTaskCreate(&dnsTask, "dnsTask", 4096, NULL, 2, &dnsTaskHandle);
  } else doRestart("Aborting as DNS Server not running");
}

static void loadBlockList(const char* reason) {
  // load or refresh blocklist file
  static bool downloading = false;
  if (!downloading) {
    downloading = true;
    LOG_INF("%s load of latest blocklist", reason);
    while (!downloadBlockList()) {
      LOG_WRN("Failed to complete blocklist download, retry ...");
      delay(10000);
    }
    downloading = false;
  } else LOG_WRN("Ignore request as download in progress");
}

void appSetup() {
  if (!strlen(fileURL)) {
    LOG_WRN("Enter blocklist URL on web page ...");
    while (!strlen(fileURL)) delay(1000); // wait for file URL to be entered
  }
  lastCheck.lastDomain = (char*)malloc(maxDomLen);

  ptrs = (uint32_t*)ps_calloc((maxDomains + 2), sizeof(uint32_t));
  storageSize = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
  storage = (char*)ps_calloc(storageSize, sizeof(char));

  // prime domain storage
  memcpy(storage, "!", 1);
  blocklistSize = 2;
  itemsLoaded = 1;
  allowCnt = blockCnt = 0;
  updateConfigVect("blockCnt", "0");
  updateConfigVect("allowCnt", "0");
  loadBlockList("Initial");
  prepDNS();
}

void showBlockList(int maxItems) {
  // debug
  if (!maxItems) maxItems = itemsLoaded;
  for (int i = 0; i < maxItems; i++) logPrint("%d: %s\n", i, storage + ptrs[i]);
  logPrint("Total %u items\n", itemsLoaded - 1);
}

/************************ webServer callbacks *************************/

bool updateAppStatus(const char* variable, const char* value) {
  // update vars from configs and browser input
  bool res = true;
  int intVal = atoi(value);
  if (!strcmp(variable, "custom")) {
    // update config for latest stats to return on next main page call
    char cntStr[20];
    sprintf(cntStr, "%u", blockCnt);
    updateConfigVect("blockCnt", cntStr);
    sprintf(cntStr, "%u", allowCnt);
    updateConfigVect("allowCnt", cntStr);
  }
  else if (!strcmp(variable, "fileURL")) strncpy(fileURL, value, IN_FILE_NAME_LEN - 1);
  else if (!strcmp(variable, "maxDomains")) maxDomains = intVal * 1000;
  else if (!strcmp(variable, "minMemory")) minMemory = intVal * 1024;
  else if (!strcmp(variable, "maxDomLen")) maxDomLen = intVal;
  else if (!strcmp(variable, "showBL")) showBlockList(intVal);
  return res;
}

void appSpecificWsBinHandler(uint8_t* wsMsg, size_t wsMsgLen) {
  LOG_ERR("Unexpected websocket binary frame");
}

void appSpecificWsHandler(const char* wsMsg) {
  // message from web socket
  int wsLen = strlen(wsMsg) - 1;
  switch ((char)wsMsg[0]) {
    case 'X':
    break;
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
      killSocket();
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

esp_err_t appSpecificWebHandler(httpd_req_t *req, const char* variable, const char* value) {
  return ESP_OK;
}

esp_err_t appSpecificSustainHandler(httpd_req_t* req) {
  return ESP_OK;
}

void externalAlert(const char* subject, const char* message) {
  // alert any configured external servers
}

bool appDataFiles() {
  // callback from setupAssist.cpp, for any app specific files
  return true;
}

void doAppPing() {
  // if daily alarm occurs, load latest blocklist from host site
  if (checkAlarm()) loadBlockList("Scheduled");
}

void OTAprereq() {
  stopPing();
}

/************** default app configuration **************/
const char* appConfig = R"~(
restart~~99~T~na
ST_SSID~~0~T~Wifi SSID name
ST_Pass~~0~T~Wifi SSID password
ST_ip~~0~T~Static IP address
ST_gw~~0~T~Router IP address
ST_sn~255.255.255.0~0~T~Router subnet
ST_ns1~~0~T~DNS server
ST_ns2~~0~T~Alt DNS server
AP_Pass~~0~T~AP Password
AP_ip~~0~T~AP IP Address if not 192.168.4.1
AP_sn~~0~T~AP subnet
AP_gw~~0~T~AP gateway
allowAP~2~0~C~Allow simultaneous AP
timezone~GMT0~1~T~Timezone string: tinyurl.com/TZstring
logType~0~99~N~Output log selection
Auth_Name~~0~T~Optional user name for web page login
Auth_Pass~~0~T~Optional user name for web page password
formatIfMountFailed~0~1~C~Format file system on failure
wifiTimeoutSecs~30~0~N~WiFi connect timeout (secs)
alarmHour~4~1~N~Hour of day for blocklist update
maxDomains~150~1~N~Max number of domains (* 1000)
minMemory~128~1~N~Minimum free memory (KB)
maxDomLen~100~1~N~Max length of domain name
allowCnt~0~2~D~Allowed domains
blockCnt~0~2~D~Blocked domains
fileURL~https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts~2~T~URL for blocklist file
loadProg~0~2~D~Blocklist download progress
usePing~1~0~C~Use ping
)~";
