// AdBlocker specific functions
//
// dateno1 2026
// s60sc 2020, 2023, 2026

#include "appGlobals.h"
#include <algorithm>

const size_t prvtkey_len = 0;
const size_t cacert_len = 0;
const char* prvtkey_pem = "";
const char* cacert_pem = "";

static size_t maxDomains; // for reserving ptrs memory
static size_t minMemory; // min free memory after vector populated
static const uint16_t maxLineLen = 1024; // max length of line processed in downloaded blocklists
static uint8_t maxDomLen; // max length of domain name in blocklist
static char fileURL[IN_FILE_NAME_LEN] = {0};
static char fmtStorageSize[FILE_NAME_LEN];

static int timeoutVal = 10000; // 10 secs on download stream data being available
static size_t blocklistSize = 0;
static uint8_t domainLine[maxLineLen];
static uint32_t blockCnt = 0, allowCnt = 0, itemsLoaded = 0, pendingItems = 0, duplicates = 0;
static bool stopLoad = false;
static bool downloading = false;
static bool adBlockOn = true; // whether app is set to block or not by user
static bool useSnap = false; // whether flash is used to store snapshot
static volatile bool blocklistReady = false; // false while rebuilding/sorting ptrs[]
static SemaphoreHandle_t blMutex = NULL;
static char lastBlockedDomain[IN_FILE_NAME_LEN] = {0};
size_t storageSize;
uint32_t* ptrs; // ordered pointers to domain names
char* storage; // linear domain name storage
static uint32_t lastLoadMs = 0; // millis() of last successful blocklist download

static inline void blLock() {
  if (blMutex) xSemaphoreTake(blMutex, portMAX_DELAY);
}
static inline void blUnlock() {
  if (blMutex) xSemaphoreGive(blMutex);
}

/* Custom CA cache - kept for process lifetime, lives in PSRAM when
 * possible so even a multi-KB CA.pem never squeezes internal SRAM. */
static char*  g_caBuf = nullptr;  // NUL-terminated PEM text
static size_t g_caLen = 0;
static bool   g_caTried = false;  // load-once flag

static uint32_t binarySearch(const char* searchStr, bool doUpdate) {
  // binary split search
  // for an update, return 0 if found (duplicate) else return ptr
  // for a check, return ptr if found else return 0
  int first = 0, ptr = 0;
  int last = itemsLoaded - 1;
  while (first <= last) {
    ptr = (first + last) / 2;
    int diff = strcmp(storage + ptrs[ptr], searchStr);
    if (diff < 0) first = ptr + 1;
    else if (diff > 0) last = ptr - 1;
    else return doUpdate ? 0 : ptr; // found (diff = 0)
  }
  // not found
  return doUpdate ? ptr : 0;
}

static size_t formatDomain(char* domName) {
  // format input domain name by removing whitespace, www. prefix and converting to lowercase
  trim(domName);
  toCase(domName);
  size_t domLen = strlen(domName);
  int wwwOffset = (strncmp(domName, "www.", 4) == 0) ? 4 : 0;  // remove any leading "www."
  memmove(domName, domName + wwwOffset,  domLen + 1 - wwwOffset);
  return domLen - wwwOffset;
}

static void addDomain(uint32_t ptr, const char* domainStr, size_t domLen) {
  // domain names stored linearly in 'storage' in order received
  // pointer to each domain stored in 'ptrs' sorted alphabetically by corresponding domain
  // the number of unique domains may be lower than the source file which may have
  // entries of the form www .vinted-pl-id002c.celebx.top and vinted-pl-id002c.celebx.top
  // which are treated in this app as a single entry as the www is ignored

  // central capacity guard - protects storage and ptrs[] bounds for ALL callers
  if (blocklistSize + domLen + 1 > storageSize || itemsLoaded >= maxDomains) {
    LOG_VRB("Ignored '%s', blocklist storage/limit reached", domainStr);
    return;
  }
  // check what is already at location
  int diff = strcmp(storage + ptrs[ptr], domainStr);
  // append domain name to storage
  memcpy(storage + blocklistSize, domainStr, domLen);
  storage[blocklistSize + domLen] = 0;
  // make space for new domain pointer at identified location by shifting following locations
  if (diff < 0) ptr++; // to insert after
  memmove(&ptrs[ptr + 1], &ptrs[ptr], (itemsLoaded - ptr) * sizeof(uint32_t));
  
  // insert new domain pointer
  ptrs[ptr] = blocklistSize; // points to latest domain name in 'storage'
  blocklistSize += domLen + 1; // add terminator
  itemsLoaded++;
  ptrs[itemsLoaded] = blocklistSize;
  pendingItems = itemsLoaded;
}

/* Bulk load: downloaded domains are appended unsorted after the sorted prefix [0, itemsLoaded),
 * then sorted, deduplicated, and compacted in finalizeBlocklist().
 * DNS lookups only search [0, itemsLoaded) while downloading, and pause cleanly via
 * blMutex/blocklistReady during finalizeBlocklist(). */

static bool appendDomain(const char* domainStr, size_t domLen) {
  // cheap check for the common case of consecutive duplicates (eg "www.x" then "x")
  if (pendingItems > itemsLoaded && !strcmp(storage + ptrs[pendingItems - 1], domainStr)) {
    duplicates++;
    return true;
  }
  if (blocklistSize + domLen + 1 > storageSize || pendingItems >= maxDomains) {
    LOG_VRB("Ignored '%s', blocklist storage/limit reached", domainStr);
    return false;
  }
  memcpy(storage + blocklistSize, domainStr, domLen);
  storage[blocklistSize + domLen] = 0;
  ptrs[pendingItems++] = blocklistSize;
  blocklistSize += domLen + 1;
  return true;
}

static uint32_t cmpCount = 0;
static bool domainLess(uint32_t a, uint32_t b) {
  // yield occasionally so a long sort in PSRAM cannot starve other tasks or trip the watchdog
  if ((++cmpCount & 0x3FFF) == 0) vTaskDelay(1);
  return strcmp(storage + a, storage + b) < 0;
}

static void finalizeBlocklist() {
  // Sort pointer table in O(N log N), drop duplicates & empty (deleted) entries, and compact storage
  uint32_t n = pendingItems;
  if (n <= itemsLoaded) {
    blLock();
    ptrs[itemsLoaded] = blocklistSize;
    blocklistReady = true;
    blUnlock();
    return;
  }
  uint32_t t0 = millis();

  // Pause DNS lookups while ptrs[] and storage[] are reordered and compacted
  blLock();
  blocklistReady = false;
  lastBlockedDomain[0] = 0;
  blUnlock();

  std::sort(ptrs, ptrs + n, domainLess);

  // Deduplicate in place and drop empty (deleted) entries
  uint32_t u = 0;
  for (uint32_t i = 0; i < n; i++) {
    const char* cur = storage + ptrs[i];
    if (!*cur) continue;
    if (u > 0 && !strcmp(cur, storage + ptrs[u - 1])) {
      duplicates++;
    } else {
      ptrs[u++] = ptrs[i];
    }
    if ((i & 0xFFF) == 0) vTaskDelay(1);
  }

  // Compact storage: walk live names in storage order and slide each down over gaps
  vTaskDelay(1);
  std::sort(ptrs, ptrs + u);
  size_t w = 0;
  for (uint32_t i = 0; i < u; i++) {
    size_t len = strlen(storage + ptrs[i]) + 1;
    if (ptrs[i] != w) memmove(storage + w, storage + ptrs[i], len);
    ptrs[i] = w;
    w += len;
    if ((i & 0xFFF) == 0) vTaskDelay(1);
  }
  if (blocklistSize > w) memset(storage + w, 0, blocklistSize - w); // addDomain() relies on zeroed free space
  blocklistSize = w;

  std::sort(ptrs, ptrs + u, domainLess); // back into alphabetical order for binary search
  ptrs[u] = blocklistSize; // trailing sentinel
  vTaskDelay(1);

  blLock();
  pendingItems = u;
  itemsLoaded = u;
  lastBlockedDomain[0] = 0;
  blocklistReady = true;
  blUnlock();
  LOG_INF("Sorted & compacted %lu domains in %lums", (unsigned long)(u > 2 ? u - 2 : 0), (unsigned long)(millis() - t0));
}

static bool updateCustomFile(char* domainName, bool doDelete) {
  // user supplied domain to add to or delete from blocklist
  File file = STORAGE.open(CUSTOM_FILE_PATH, FILE_APPEND);
  if (file) {
    if (doDelete) file.print("#"); // mark as deleted
    file.println(domainName);
    file.close();
    return true;
  } else LOG_ERR("Failed to open %s", CUSTOM_FILE_PATH);
  return false;
}

bool isDomainBlocked(const char* domainName) {
  // normalize: strip trailing root dot, force lowercase, strip leading "www."
  // (matches formatDomain() used when populating the blocklist)
  char normName[IN_FILE_NAME_LEN];
  size_t n = strlen(domainName);
  if (n == 0 || n >= IN_FILE_NAME_LEN) return false;

  if (domainName[n - 1] == '.') n--; // tolerate "example.com."
  for (size_t i = 0; i < n; i++)
    normName[i] = (char)tolower((unsigned char)domainName[i]);
  normName[n] = 0;

  // RFC 6761: localhost is always loopback, never blocklisted
  if (!strcmp(normName, "localhost")) {
    ++allowCnt;
    LOG_VRB("%s -> loopback (fixed)", normName);
    return false;
  }

  // Strip leading "www." so "www.ads.example" matches stored "ads.example"
  const char* lookupName = (strncmp(normName, "www.", 4) == 0) ? normName + 4 : normName;

  bool blocked = false;
  if (adBlockOn) {
    uint64_t usElapsed = micros();
    blLock();
    if (blocklistReady && itemsLoaded > 2) {
      // check if received domain name same as previous blocked domain to skip search
      blocked = (lastBlockedDomain[0] && !strcmp(lookupName, lastBlockedDomain))
                ? true
                : (bool)binarySearch(lookupName, false);
      if (blocked) strlcpy(lastBlockedDomain, lookupName, sizeof(lastBlockedDomain));
    }
    blUnlock();
    blocked ? ++blockCnt : ++allowCnt;
    uint64_t checkTime = micros() - usElapsed;
    LOG_VRB("Check %s %s in %lluus", normName, (blocked) ? "*Blocked*" : "Allowed", checkTime);
  }
  return blocked;
}

DnsResult checkBlocklist(const char* domainName, IPAddress& retIP) {
  // legacy wrapper: check blocklist, else query upstream A forwarder
  char normName[IN_FILE_NAME_LEN];
  size_t n = strlen(domainName);
  if (n == 0 || n >= IN_FILE_NAME_LEN) {
    retIP = IPAddress(0, 0, 0, 0);
    return DNS_SERVFAIL;
  }
  if (domainName[n - 1] == '.') n--;
  for (size_t i = 0; i < n; i++)
    normName[i] = (char)tolower((unsigned char)domainName[i]);
  normName[n] = 0;

  if (!strcmp(normName, "localhost")) {
    retIP = IPAddress(127, 0, 0, 1);
    ++allowCnt;
    return DNS_RESOLVED;
  }
  if (isDomainBlocked(normName)) {
    retIP = IPAddress(0, 0, 0, 0);
    return DNS_BLOCKED;
  }
  return resolveDomainStatus(normName, retIP);
}

static void checkDomain(const char* inName, bool doUpdate, bool doDelete) {
  // check if user supplied domain name is present or update user supplied name
  char domName[IN_FILE_NAME_LEN];
  strncpy(domName, inName, sizeof(domName) - 1);
  domName[sizeof(domName) - 1] = 0;

  if (size_t domLen = formatDomain(domName); domLen > 0) {
    if (domLen >= maxDomLen) LOG_ALT("Domain name %s is too long to process", domName);
    else if (!blocklistReady || ((doUpdate || doDelete) && downloading)) LOG_ALT("Blocklist reload in progress, try again shortly");
    else {
      if (doUpdate) { // addition
        blLock();
        uint32_t blPtr = binarySearch(domName, true);
        blUnlock();
        if (blPtr) {
          // resolve outside lock to avoid blocking DNS queries during network I/O
          if (resolveDomain(domName) != IPAddress(0, 0, 0, 0)) {
            bool added = false, reloading = false;
            blLock();
            if (blocklistReady && !downloading) {
              blPtr = binarySearch(domName, true);
              if (blPtr) {
                addDomain(blPtr, domName, domLen);
                added = true;
              }
            } else reloading = true;
            blUnlock();
            if (added) {
              if (updateCustomFile(domName, false)) LOG_ALT("Domain name %s IS added to blocklist", domName);
            } else if (reloading) LOG_ALT("Blocklist reload in progress, try again shortly");
            else LOG_ALT("Domain name %s NOT added to blocklist as duplicate", domName);
          } else LOG_ALT("Domain name %s NOT added to blocklist as not resolved", domName);
        } else LOG_ALT("Domain name %s NOT added to blocklist as duplicate", domName);
      } else {
        // delete or just check
        blLock();
        uint32_t blPtr = binarySearch(domName, false);
        if (doDelete && blPtr) {
          *(storage + ptrs[blPtr]) = 0; // set domain name empty
          lastBlockedDomain[0] = 0;     // invalidate single-entry cache
        }
        blUnlock();
        if (doDelete) { // deletion
          if (blPtr) {
            if (updateCustomFile(domName, true)) LOG_ALT("Domain name %s IS deleted", domName);
          } else LOG_ALT("Domain name %s NOT deleted as not in blocklist", domName);
        } else LOG_ALT("Domain name %s %s in blocklist", domName, blPtr ? "IS" : "NOT"); // check only
      }
    }
  } else LOG_ALT("No domain name entered");
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
    // write processed domain to storage (sorted & deduplicated once download completes)
    size_t domLen = formatDomain(tokenItem);
    if (domLen && (domLen < maxDomLen)) {
      // never store loopback names from hosts file headers
      if (!strcasecmp(tokenItem, "localhost") ||
          !strcasecmp(tokenItem, "localhost.localdomain") ||
          !strcasecmp(tokenItem, "local")) return;
      appendDomain(tokenItem, domLen); // capacity is checked by the download loop
    }
  }
}

static bool loadCustomCAs() {
  if (g_caTried) return g_caLen > 0;   // cached verdict
  g_caTried = true;
  File f = STORAGE.open(CA_PEM_PATH, FILE_READ);
  if (!f) { LOG_INF("No %s - IDF bundle only", CA_PEM_PATH); return false; }
  size_t sz = f.size();
  if (sz == 0 || sz > CA_PEM_MAX) {    // reject empty / absurd sizes
    LOG_WRN("%s skipped (size %u)", CA_PEM_PATH, (unsigned)sz);
    f.close(); return false;
  }
  /* PSRAM first; SRAM only as tiny-file fallback */
  char* buf = (char*)ps_malloc(sz + 1);
  bool inPsram = true;
  if (!buf) { buf = (char*)malloc(sz + 1); inPsram = false; }
  if (!buf) { f.close(); return false; }
  size_t rd = f.readBytes(buf, sz);
  f.close();
  buf[rd] = 0;                          // setCACert expects C string
  g_caBuf = buf; g_caLen = rd;
  LOG_INF("CA store ready: %u bytes in %s", (unsigned)rd, inPsram ? "PSRAM" : "SRAM");
  return true;
}

static bool downloadBlockList() {
  // download blocklist file from github
  bool res = false;

  // try own obtained certificate first if available,
  // then try IDF Certificate Bundle
  // if both fail and user has allowed certificate checks to be skipped
  // then try connecting without certificate check (MITM risk)
  NetworkClientSecure wclient;
  if (loadCustomCAs()) {
    LOG_INF("Try own obtained certificate");
    res = remoteServerConnect(wclient, GITHUB_HOST, HTTPS_PORT, g_caBuf, BLOCKLIST);
  } 
  if (!res) {
    LOG_INF("Try IDF Certificate Bundle");
    res = remoteServerConnect(wclient, GITHUB_HOST, HTTPS_PORT, BLOCKLIST);
  }

  if (res) {
    res = false; // only true once HTTP download actually succeeds
    HTTPClient https;
    size_t downloadSize = 0;
    char progStr[10];

    if (https.begin(wclient, fileURL)) {
      downloading = true;
      LOG_INF("Downloading %s\n", fileURL);
      int httpCode = https.GET();
      if (httpCode > 0) {
        uint32_t loadTime = millis();
        if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY) {
          // file available for download
          // get length of content (is -1 when Server sends no Content-Length header)
          int left = https.getSize();
          if (left > 0) LOG_INF("File size: %s", fmtSize(left));
          else LOG_WRN("File size unknown");
          LOG_INF("%s memory available for download", fmtStorageSize);
          if (left > (int)storageSize) LOG_WRN("File is larger than memory, may get truncated");
          NetworkClient* stream = https.getStreamPtr(); // stream data to client
          uint32_t lastRead = millis();
          size_t lineCnt = 0;

          // Read in 4KB chunks instead of byte-by-byte readBytesUntil() TLS calls;
          // allocate temporarily in PSRAM/heap (with small stack fallback) to avoid permanent internal SRAM use.
          size_t rxBufSize = CHUNKSIZE;
          uint8_t* rxBuf = (uint8_t*)ps_malloc(rxBufSize);
          if (!rxBuf) rxBuf = (uint8_t*)malloc(rxBufSize);
          uint8_t fallbackBuf[256];
          bool freeRxBuf = (rxBuf != NULL);
          if (!rxBuf) {
            rxBuf = fallbackBuf;
            rxBufSize = sizeof(fallbackBuf);
          }

          size_t lineLen = 0;
          bool full = false;
          bool timedOut = false;
          size_t savedBlSize = blocklistSize;
          pendingItems = itemsLoaded; // append after the existing sorted prefix [0, itemsLoaded)

          // Returns false if storage / domain limit is still reached even after sorting out duplicates
          auto processLine = [&]() -> bool {
            domainLine[lineLen] = 0;
            lineLen = 0;
            extractBlocklist();
            if (pendingItems >= maxDomains || storageSize - blocklistSize < maxLineLen) {
              finalizeBlocklist(); // deduplicate and compact to reclaim space
              savedBlSize = blocklistSize;
              if (pendingItems >= maxDomains) {
                LOG_ALT("Blocklist truncated as domain limit reached %u", maxDomains);
                return false;
              }
              if (storageSize - blocklistSize < maxLineLen) {
                LOG_ALT("Blocklist truncated to avoid memory overflow, %u bytes remaining\n", (unsigned)(storageSize - blocklistSize));
                return false;
              }
            }
            if (++lineCnt % 1000 == 0 && left > 0) {
              // show progress
              float loadProg = (float)(downloadSize * 100.0 / (downloadSize + left));
              LOG_RAW("%0.1f%%\n", loadProg);
              sprintf(progStr, "%0.1f%%", loadProg);
              updateConfigVect("loadProg", progStr);
            }
            return true;
          };

          while (!full && (https.connected() || stream->available()) && (left > 0 || left == -1)) {
            if (stopLoad) break;
            int avail = stream->available();
            if (avail > 0) {
              size_t toRead = (size_t)avail;
              if (toRead > rxBufSize) toRead = rxBufSize;
              if (left > 0 && toRead > (size_t)left) toRead = (size_t)left;
              int got = stream->read(rxBuf, toRead);
              if (got <= 0) continue;
              downloadSize += got;
              if (left > 0) left = (got >= left) ? 0 : left - got;
              for (int i = 0; i < got && !full; i++) {
                uint8_t c = rxBuf[i];
                if (c == '\n') full = !processLine();
                else if (lineLen < maxLineLen - 1) domainLine[lineLen++] = c; // overlong lines truncated cleanly
              }
              lastRead = millis();
            } else if (millis() - lastRead > timeoutVal) {
              // timed out on read
              if (left > 0) LOG_WRN("Timeout on download, %s unread", fmtSize(left));
              else LOG_WRN("Timeout on download after %s", fmtSize(downloadSize));
              timedOut = true;
              break;
            } else delay(1); // nothing buffered yet, don't busy-spin
          }
          if (freeRxBuf) free(rxBuf);

          // A cut-off download (eg Wi-Fi drop or timeout) must not count as success,
          // otherwise a partial list replaces the active list and overwrites the flash snapshot.
          if ((left > 0 || timedOut || downloadSize == 0) && !full && !stopLoad) {
            if (blocklistSize > savedBlSize) {
              memset(storage + savedBlSize, 0, blocklistSize - savedBlSize);
              blocklistSize = savedBlSize;
            }
            pendingItems = itemsLoaded;
            if (left > 0) LOG_WRN("Download incomplete, %s missing - treated as failed", fmtSize(left));
            else LOG_WRN("Download incomplete (%s read) - treated as failed", fmtSize(downloadSize));
            res = false;
          } else {
            if (!full && lineLen) processLine(); // handle last line without trailing newline
            finalizeBlocklist();
            LOG_INF("Download complete, processed %s in %lu secs", fmtSize(downloadSize), (unsigned long)((millis() - loadTime) / 1000));
            LOG_ALT("Loaded %lu blocked domains excluding %lu duplicates, using %s of %s",
                    (unsigned long)(itemsLoaded > 2 ? itemsLoaded - 2 : 0), (unsigned long)duplicates, fmtSize(blocklistSize), fmtStorageSize);
            res = true;
          }
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
  if (stopLoad) {
    LOG_ALT("Blocklist load stopped by user request");
    updateConfigVect("loadProg", "Stopped");
    res = true;
  } else if (res) updateConfigVect("loadProg", "Complete");
  else updateConfigVect("loadProg", "Failed");
  return res;
}

static void loadCustom() {
  // process custom blocklist file entries
  File file;
  uint32_t customAdded = 0, customDeleted = 0;
  if (!STORAGE.exists(CUSTOM_FILE_PATH)) {
    // create file on first call
    file = STORAGE.open(CUSTOM_FILE_PATH, FILE_WRITE);
    if (file) file.close();
    else LOG_WRN("Failed to create file %s", CUSTOM_FILE_PATH);
  } else {
    // read in entries
    file = STORAGE.open(CUSTOM_FILE_PATH, FILE_READ);
    char domName[IN_FILE_NAME_LEN];
    while (file.available()) {
      bool doAdd = true;
      String customLineStr = file.readStringUntil('\n');
      customLineStr.trim();
      if (customLineStr.length()) {
        if (customLineStr.charAt(0) == '#') {
          doAdd = false;  // deletion
          strlcpy(domName, customLineStr.substring(1).c_str(), sizeof(domName));
        } else strlcpy(domName, customLineStr.c_str(), sizeof(domName)); // addition
        blLock();
        uint32_t blPtr = binarySearch(domName, doAdd);
        if (blPtr) {
          if (doAdd) {
            // addition
            addDomain(blPtr, domName, strlen(domName));
            customAdded++;
          } else {
            // deletion
            *(storage + ptrs[blPtr]) = 0; // set domain name empty
            lastBlockedDomain[0] = 0;
            customDeleted++;
          }
        } else LOG_WRN("Ignored custom %s of %s", doAdd ? "addition" : "deletion", domName);
        blUnlock();
      }
    }
    file.close();
  }
  LOG_ALT("Loaded %lu custom blocked domains, unblocked %lu domains", customAdded, customDeleted);
}

static void showBlockList(int maxItems = 0) {
  // for info
  if (!maxItems) maxItems = itemsLoaded;
  for (int i = 0; i < maxItems; i++) LOG_RAW("%d: %s\n", i, storage + ptrs[i]);
  LOG_RAW("Total %lu items\n", itemsLoaded);
}

/* incremental CRC32 */
static uint32_t crc32_begin() { return 0xFFFFFFFFu; }
static uint32_t crc32_upd(uint32_t c, const uint8_t* d, size_t n) {
  while (n--) { c ^= *d++;
    for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320 & (-(int32_t)(c & 1)));
  }
  return c;
}
static uint32_t crc32_end(uint32_t c) { return c ^ 0xFFFFFFFFu; }

/* Logs the reason, closes the snapshot file, and bails out.
   GCC/Clang string-concatenation with __VA_ARGS__ keeps printf formatting. */
#pragma pack(push, 1)
struct SnapHdr {
  uint32_t magic, items, blsize;
  uint32_t blockCnt, allowCnt, duplicates;
  uint32_t rawLen, compLen, crc;
  uint16_t ver;
};
#pragma pack(pop)

#define SNAP_FAIL(...)                                        \
  do {                                                        \
    LOG_WRN("Snapshot rejected: " __VA_ARGS__);               \
    f.close();                                                \
    return false;                                             \
  } while (0)

#define SNAP_PATH DATA_DIR "/blsnap.bin"
#define SNAP_MAGIC 0x314C4253   // "SBL1"
#define SNAP_VER   1

/* Persist the used portion of the arena, compressed. Called after every
 * successful download; LittleFS wear-leveling makes 1 write/day trivial. */
static void saveSnapshot() {
  if (itemsLoaded < 3 || blocklistSize < 4096) { 
    LOG_WRN("Snap skip: tiny"); 
    return; 
  }

  // LittleFS space check (worst-case encoding: every entry unmatched + trailing CRC)
  uint32_t worstCase = blocklistSize + itemsLoaded * 2 + sizeof(SnapHdr) + sizeof(uint32_t) + 4096;
  uint32_t freeFs = STORAGE.totalBytes() - STORAGE.usedBytes();
  if (freeFs < worstCase) {
    LOG_WRN("Snap skipped: flash free %uKB < needed ~%uKB",
            (unsigned)(freeFs / 1024), (unsigned)(worstCase / 1024));
    return;
  }

  // corruption tripwire accumulators
  uint32_t nameBytes  = 0;
  uint32_t matchBytes = 0;

  // Compute exact packed arena size expected by loadSnapshot() (accounts for deduped/deleted entries)
  uint32_t packedBlSize = 0;
  for (uint32_t i = 0; i < itemsLoaded; i++) {
    size_t maxCur = blocklistSize - ptrs[i];
    size_t cl = strnlen(storage + ptrs[i], maxCur);
    if (cl >= maxCur) {
      LOG_ERR("Snap: entry %u UNTERMINATED at offset %u", (unsigned)i, (unsigned)ptrs[i]);
      return;
    }
    packedBlSize += cl + 1;
  }

  SnapHdr h; 
  memset(&h, 0, sizeof(h));
  h.magic = SNAP_MAGIC; 
  h.ver = SNAP_VER;
  h.items = itemsLoaded; 
  h.blsize = packedBlSize;
  h.blockCnt = blockCnt; 
  h.allowCnt = allowCnt; 
  h.duplicates = duplicates;

  char tmpPath[80];
  snprintf(tmpPath, sizeof(tmpPath), "%s.tmp", SNAP_PATH);

  File f = STORAGE.open(tmpPath, FILE_WRITE);
  if (!f) { 
    LOG_ERR("Snap OPEN FAILED: %s", tmpPath); 
    return; 
  }
  
  // Write the initial header to the file
  if (f.write((uint8_t*)&h, sizeof(h)) != sizeof(h)) {
    LOG_ERR("Snap: header write failed");
    f.close();
    STORAGE.remove(tmpPath);
    return;
  }

  uint32_t crc      = crc32_begin();
  uint32_t encBytes = 0;
  const char* prev    = "";
  size_t      prevLen = 0;
  bool ok = true;
  uint32_t t0 = millis();

  // Buffered writing optimization for ESP32 flash architecture
  uint8_t buf[512];
  size_t bufIdx = 0;

  auto flushBuffer = [&]() -> bool {
    if (bufIdx > 0) {
      if (f.write(buf, bufIdx) != bufIdx) return false;
      bufIdx = 0;
    }
    return true;
  };

  for (uint32_t i = 0; i < itemsLoaded && ok; i++) {
    // Avoid TWDT reset triggers on huge blocklists
    if ((i & 0x7FF) == 0) {
      vTaskDelay(pdMS_TO_TICKS(1));
    }

    const char* cur    = storage + ptrs[i];
    size_t      maxCur = blocklistSize - ptrs[i];
    size_t      cl     = strnlen(cur, maxCur);     // BOUNDED strlen

    if (cl >= maxCur) {                            // unterminated entry!
      LOG_ERR("Snap: entry %u UNTERMINATED at offset %u",
              (unsigned)i, (unsigned)ptrs[i]);
      LOG_RAW("first32: ");
      for (size_t k = 0; k < 32 && ptrs[i] + k < blocklistSize; k++)
        LOG_RAW("%02x ", cur[k]);
      LOG_RAW("\n");
      ok = false;
      break;
    }

    size_t ml = 0;
    while (ml < cl && ml < prevLen && ml < 255 && cur[ml] == prev[ml]) {
      ml++;
    }
    size_t sl = cl - ml;
    if (sl > 255) { 
      ml -= (sl - 255); 
      sl = 255; 
    }

    uint8_t lens[2] = { (uint8_t)ml, (uint8_t)sl };
    crc = crc32_upd(crc, lens, 2);
    encBytes += 2;

    // Buffer management for lengths
    if (bufIdx + 2 > sizeof(buf)) {
      if (!flushBuffer()) { ok = false; break; }
    }
    buf[bufIdx++] = lens[0];
    buf[bufIdx++] = lens[1];

    // Buffer management for suffix strings
    if (sl > 0) {
      crc = crc32_upd(crc, (const uint8_t*)(cur + ml), sl);
      encBytes += sl;

      size_t remainingSl = sl;
      size_t srcOffset = 0;
      while (remainingSl > 0) {
        if (bufIdx >= sizeof(buf)) {
          if (!flushBuffer()) { ok = false; break; }
        }
        size_t chunk = sizeof(buf) - bufIdx;
        if (chunk > remainingSl) chunk = remainingSl;

        memcpy(buf + bufIdx, cur + ml + srcOffset, chunk);
        bufIdx += chunk;
        srcOffset += chunk;
        remainingSl -= chunk;
      }
      if (!ok) break;
    }

    nameBytes  += cl;
    matchBytes += ml;
    prev = cur;
    prevLen = cl;
  }

  // Flush remaining encoded data bytes
  if (ok && !flushBuffer()) ok = false;

  // Finalize serialization by appending trailing CRC32
  if (ok) {
    uint32_t finalCrc = crc32_end(crc);
    if (f.write((uint8_t*)&finalCrc, sizeof(finalCrc)) != sizeof(finalCrc)) {
      ok = false;
    } else {
      encBytes += sizeof(finalCrc);
    }
  }

  f.close();

  if (!ok) {
    LOG_ERR("Snap WRITE FAILED or corrupted. Cleaning up temporary files.");
    STORAGE.remove(tmpPath);
    return;
  }

  STORAGE.remove(SNAP_PATH);
  if (!STORAGE.rename(tmpPath, SNAP_PATH)) {
    LOG_ERR("Snap RENAME FAILED from %s to %s", tmpPath, SNAP_PATH);
    STORAGE.remove(tmpPath);
    return;
  }

  uint32_t t1 = millis();
  LOG_INF("Snap SAVED: %u items, %uKB raw -> %uKB enc (%u%%) in %ums",
          (unsigned)itemsLoaded,
          (unsigned)(blocklistSize / 1024),
          (unsigned)((encBytes + sizeof(h)) / 1024),
          (unsigned)((encBytes + sizeof(h)) * 100 / (blocklistSize ? blocklistSize : 1)),
          (unsigned)(t1 - t0));
}

static void resetBlocklistStorage();

/* Restore arena from snapshot. No WiFi / no valid clock required.
 * The sorted pointer table is rebuilt by walking the NUL-separated
 * entries, then verified against the stored item count. */
static bool loadSnapshot() {
  File f = STORAGE.open(SNAP_PATH, FILE_READ);
  if (!f) { 
    LOG_INF("No snapshot yet (%s)", SNAP_PATH); 
    return false; 
  }

  SnapHdr h;
  if (f.read((uint8_t*)&h, sizeof(h)) != sizeof(h)) {
    f.close();
    SNAP_FAIL("header read");
  }
  if (h.magic != SNAP_MAGIC) {
    f.close();
    SNAP_FAIL("bad magic");
  }
  if (h.ver   != SNAP_VER) {
    f.close();
    SNAP_FAIL("version %u", h.ver);
  }
  if (h.items < 2 || h.items > maxDomains) {
    f.close();
    SNAP_FAIL("item count %lu", (unsigned long)h.items);
  }
  if (h.blsize == 0 || h.blsize > storageSize) {
    f.close();
    SNAP_FAIL("arena %luKB exceeds storage %luKB",
              (unsigned long)(h.blsize / 1024), (unsigned long)(storageSize / 1024));
  }

  blLock();
  blocklistReady = false;
  lastBlockedDomain[0] = 0;
  blUnlock();

  memset(ptrs, 0, (maxDomains + 2) * sizeof(uint32_t));
  uint32_t crc = crc32_begin();
  uint32_t pos = 0, idx = 0, enc = 0;
  uint32_t prevPtr = 0;
  bool havePrev = false, ok = true;

  // Stream reader buffer to maximize SPI Flash throughput on ESP32-S3
  uint8_t buf[512];
  size_t bufIdx = 0;
  size_t bufLen = 0;

  auto fillBuffer = [&]() -> bool {
    if (bufIdx >= bufLen) {
      int readBytes = f.read(buf, sizeof(buf));
      if (readBytes <= 0) return false;
      bufLen = readBytes;
      bufIdx = 0;
    }
    return true;
  };

  auto readBufferedBytes = [&](uint8_t* dest, size_t count) -> bool {
    size_t copied = 0;
    while (copied < count) {
      if (!fillBuffer()) return false;
      size_t chunk = bufLen - bufIdx;
      if (chunk > (count - copied)) chunk = count - copied;
      memcpy(dest + copied, buf + bufIdx, chunk);
      bufIdx += chunk;
      copied += chunk;
    }
    return true;
  };

  while (idx < h.items && ok) {
    // Keep Watchdog active during execution bursts
    if ((idx & 0x7FF) == 0) {
      vTaskDelay(pdMS_TO_TICKS(1));
    }

    uint8_t lens[2];
    if (!readBufferedBytes(lens, 2)) { ok = false; break; }
    crc = crc32_upd(crc, lens, 2); 
    enc += 2;
    size_t ml = lens[0], sl = lens[1];

    ptrs[idx] = pos;
    if (ml) {                                   // shared prefix from neighbour
      if (!havePrev || ml > strlen(storage + prevPtr)) { ok = false; break; }
      memcpy(storage + pos, storage + prevPtr, ml);
    }
    if (sl) {
      if (pos + ml + sl + 1 > storageSize) { ok = false; break; }
      if (!readBufferedBytes((uint8_t*)storage + pos + ml, sl)) { ok = false; break; }
      crc = crc32_upd(crc, (const uint8_t*)storage + pos + ml, sl);
    }
    storage[pos + ml + sl] = 0;
    enc += sl;
    prevPtr = pos; 
    havePrev = true;
    pos += ml + sl + 1;
    idx++;
  }
  
  uint32_t computedCrc = crc32_end(crc);
  uint32_t fileCrc = 0;
  
  // Extract trailing 4-byte checksum using the active optimization buffer stream
  if (ok) {
    if (!readBufferedBytes((uint8_t*)&fileCrc, sizeof(fileCrc))) {
      ok = false;
    }
  }
  f.close();

  if (!ok || idx != h.items || pos != h.blsize || computedCrc != fileCrc) {
    LOG_WRN("Snapshot invalid (%s)",
            computedCrc != fileCrc ? "CRC" : idx != h.items ? "count" : "bounds");
    resetBlocklistStorage();
    return false;
  }
  
  blLock();
  ptrs[idx] = pos;                              // trailing sentinel
  blocklistSize = h.blsize;  
  itemsLoaded = h.items;
  pendingItems = itemsLoaded;
  blockCnt = h.blockCnt;     
  allowCnt = h.allowCnt; 
  duplicates = h.duplicates;
  lastLoadMs = millis();
  startupFailure[0] = 0;
  lastBlockedDomain[0] = 0;
  blocklistReady = true;
  blUnlock();
  
  LOG_ALT("Restored %lu domains (%s) from snapshot", (unsigned long)(itemsLoaded - 2), fmtSize(blocklistSize));
  return true;
}

/* Reset storage to the primed ("!" + "#") state so a retry never inherits
 * partial data from an interrupted download (dedupe counts, truncation). */
static void resetBlocklistStorage() {
  blLock();
  blocklistReady = false;
  lastBlockedDomain[0] = 0;
  memset(ptrs, 0, (maxDomains + 2) * sizeof(uint32_t));
  memset(storage, 0, storageSize);  // ← FULL WIPE (was: maxDomLen + 8)
  // prime domain storage for binary search to prevent pointer 0 being returned
  memcpy(storage, "!", 1); // always first so ptrs[0] = 0
  blocklistSize = 2;
  itemsLoaded = 1;
  duplicates = 0; // don't carry a restored snapshot's duplicate count into a fresh rebuild
  addDomain(0, "#", 1);
  blocklistReady = true;
  blUnlock();
}

static bool loadBlockList(const char* reason) {
  bool res = false;
  bool restored = false;
  if (!downloading) {
    downloading = true;
    duplicates = 0;
    updateConfigVect("loadProg", "0.0%");
    LOG_INF("%s load of latest blocklist", reason);

    /* instant restore needs neither WiFi nor valid clock */
    if (!strcmp(reason, "Initial") || !strcmp(reason, "Scheduled")) {
      if (useSnap) restored = loadSnapshot();
      if (restored) updateConfigVect("loadProg", "From Flash");   // honest UI state
    }

    /* REPLACE semantics: a successful full download rebuilds the list from scratch
     * Rollback safety: the previous generation lives in the flash snapshot.
     * Without a snapshot (very first ever run or not enabled), fall back to merge-mode */
    bool canReplace = restored || (useSnap && STORAGE.exists(SNAP_PATH));
    setLamp(DevStatus::DOWNLOAD); //Change Status LED
    if (timeSynchronized || !useSecure) {
      if (canReplace && itemsLoaded > 2) resetBlocklistStorage(); // fresh build, not merge
      res = downloadBlockList();
      if (!res && (canReplace || itemsLoaded <= 2)) resetBlocklistStorage();
      if (res) {
        setLamp(DevStatus::READY); //Change Status LED
        lastLoadMs = millis();
        startupFailure[0] = 0;
        if (useSnap) saveSnapshot(); // new generation persisted
      } else if (canReplace) {
        /* rebuild failed - reinstate previous generation from flash */
        resetBlocklistStorage();
        if (useSnap) restored = loadSnapshot();
        setLamp(DevStatus::OFFLINE); //Change Status LED
        if (itemsLoaded <= 2) {
          if (netMode == 0 && !ST_SSID[0])
            LOG_ALT("First-time setup: set router SSID/Password in Network Settings");
          else {
            snprintf(startupFailure, SF_LEN, STARTUP_FAIL "Blocklist URL %s failed to load", fileURL);
            setLamp(DevStatus::FAILURE); //Change Status LED
            LOG_WRN("%s", startupFailure);
          }
        } else {
          LOG_WRN("%s load failed - serving previous %lu-domain list", reason, itemsLoaded - 2);
        }
      } else if (itemsLoaded <= 2) {
        // snapshot not enabled / available
        if (netMode == 0 && !ST_SSID[0]) {
          LOG_ALT("First-time setup: set router SSID/Password in Network Settings");
        } else {
          snprintf(startupFailure, SF_LEN, STARTUP_FAIL "Blocklist URL %s failed to load", fileURL);
          LOG_WRN("%s", startupFailure);
        }
      } else {
        LOG_WRN("%s load failed - keeping existing %lu-domain blocklist (merge mode)", reason, itemsLoaded - 2);
      }
      loadCustom();  // apply user provided rules either way
    } else {
      bool unconfiguredWifi = (netMode == 0 && !ST_SSID[0]);
      LOG_WRN("Network/time not ready (%s)", unconfiguredWifi ? "unconfigured" : (netIsConnected() ? "clock" : (netMode > 0 ? "ethernet" : "wifi")));
      if (unconfiguredWifi) setLamp(DevStatus::AP_MODE); // prepDNS re-asserts anyway
      else if (itemsLoaded > 2) setLamp(DevStatus::OFFLINE);   // cached list serving
      else setLamp(DevStatus::FAILURE);
    }
    downloading = false;
  } else LOG_WRN("Ignore request as download in progress");
  return res;
}

bool appSetup() {
  if (!blMutex) blMutex = xSemaphoreCreateMutex();
  while (!fileURL[0]) {
    LOG_ALT("Enter blocklist URL on web page ...");
    delay(30000); // wait for file URL to be entered
  }
  ptrs = (uint32_t*)ps_calloc((maxDomains + 2), sizeof(uint32_t)); // for sorted pointers
  storageSize = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) - minMemory;
  if (!ptrs || storageSize < ONEMEG * 3) {
    snprintf(startupFailure, SF_LEN, STARTUP_FAIL "Insufficient PSRAM - reduce maxDomains");
    LOG_ERR("%s", startupFailure);
    return false;
  }
  strcpy(fmtStorageSize, fmtSize(storageSize));
  storage = (char*)ps_calloc(storageSize, sizeof(char));
  if (!storage) {
    snprintf(startupFailure, SF_LEN, STARTUP_FAIL "Failed to allocate %s domain storage", fmtStorageSize);
    LOG_ERR("%s", startupFailure);
    return false;
  }
  // ~28 bytes consumed per domain incl. pointer
  LOG_INF("Blocklist capacity: %s storage, approx %lu domains, limit %u",
          fmtStorageSize, (uint32_t)(storageSize / 28), maxDomains);
  resetBlocklistStorage();
  updateConfigVect("blockCnt", "0");
  updateConfigVect("allowCnt", "0");
  if (netMode == 0 && !ST_SSID[0]) setLamp(DevStatus::AP_MODE);   // setup-needed state ASAP
  loadBlockList("Initial"); // best effort - DNS starts regardless
  if (netMode == 0 && !ST_SSID[0]) setLamp(DevStatus::AP_MODE); //Change Status LED
  prepDNS();
  appSetupDone = true;
  return true;
}

/************************ webServer callbacks *************************/

bool updateAppStatus(const char* variable, const char* value, bool fromUser) {
  // update vars from configs and browser input
  bool res = true;
  int intVal = atoi(value);
  if (!strcmp(variable, "custom")) {
    // update config for latest stats to return on next main page call
    char cntStr[20];
    sprintf(cntStr, "%lu", blockCnt);
    updateConfigVect("blockCnt", cntStr);
    sprintf(cntStr, "%lu", allowCnt);
    updateConfigVect("allowCnt", cntStr);
  }
  else if (!strcmp(variable, "fileURLc")) strncpy(fileURL, value, IN_FILE_NAME_LEN - 1);
  else if (!strcmp(variable, "maxDomains")) maxDomains = intVal * 1000;
  else if (!strcmp(variable, "minMemory")) minMemory = intVal * 1024;
  else if (!strcmp(variable, "maxDomLen")) maxDomLen = intVal;
  else if (!strcmp(variable, "showBL")) showBlockList(intVal); // not on web page
  else if (!strcmp(variable, "useSnap")) useSnap = (bool)intVal;
  else if (fromUser && !strcmp(variable, "xStop")) {
    stopLoad = true;
    LOG_ALT("Blocklist load being stopped");
  }
  // add user supplied domain name to blocklist unless a duplicate or invalid
  else if (fromUser && !strcmp(variable, "uLoad")) checkDomain(value, true, false);
  // delete user supplied domain name from blocklist if present
  else if (fromUser && !strcmp(variable, "vLoad")) checkDomain(value, false, true);
  // check if user supplied domain name in blocklist
  else if (fromUser && !strcmp(variable, "wLoad")) checkDomain(value, false, false);
    else if (fromUser && !strcmp(variable, "zLoad")) {
    stopLoad = false;
    if (value[0]) {
      if (strcmp(value, fileURL) != 0) {
        /* genuinely new source: persist + controlled restart */
        strncpy(fileURL, value, IN_FILE_NAME_LEN - 1);
        fileURL[IN_FILE_NAME_LEN - 1] = 0;  // force NUL (hardening)
        updateConfigVect("fileURLc", value);
        updateStatus("save", "0");
      }
      doRestart("Reload blocklist request");
    } 
  }
  else if (fromUser && !strcmp(variable, "zzCustom")) {
    STORAGE.remove(CUSTOM_FILE_PATH);
    LOG_ALT("Deleted custom blocklist file");
  }
  else if (!strcmp(variable, "zzzAdblockOn")) {
    adBlockOn = (bool)intVal;
    if (adBlockOn) LOG_ALT("Ad blocking enabled");
    else LOG_WRN("Ad blocking disabled");
  }
  else if (!strcmp(variable, "lampPin")) lampPin = intVal;
  else if (!strcmp(variable, "lampActiveHi")) lampActiveHi = (bool)intVal;
  else if (!strcmp(variable, "lampType")) lampType = intVal;
  else if (!strcmp(variable, "lampLevel")) lampLevel = intVal;
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
      LOG_RAW("%s\n", jsonBuff);
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

char* buildAppJsonString(bool filter) {
  // build app specific part of json string
  char* p = jsonBuff + 1;
  return p;
}

esp_err_t appSpecificWebHandler(httpd_req_t *req, const char* variable, const char* value) {
  return ESP_FAIL;
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

void doAppPing(bool timeSynced) {
  static bool timeSyncRetryDone = false;
  if (timeSynced && !timeSyncRetryDone) {
    timeSyncRetryDone = true;
    if (!lastLoadMs) loadBlockList("Retry");
  } else if (checkAlarm() && fileURL[0]) loadBlockList("Scheduled");
}

void OTAprereq() {
  stopPing();
}

/************** Default App Configuration **************/
const char* appConfig = R"~(
restart~~99~T~na
ST_SSID~~0~T~Wifi SSID name
ST_Pass~~0~T~Wifi SSID Password
ST_ip~~0~T~Device static IP address
ST_gw~~0~T~Gateway IP address
ST_sn~255.255.255.0~0~T~Network Subnet
ST_ns1~1.1.1.1~0~T~Main DNS server
ST_ns2~1.0.0.1~0~T~Alt DNS server
AP_Pass~~0~T~AP Mode Wifi Password
AP_ip~~0~T~AP Mode IP Address (Blank=192.168.4.1)
AP_sn~~0~T~AP Mode Subnet
AP_gw~~0~T~AP Mode Gateway
useHttps~0~0~C~Enable HTTPS connection to app
useSecure~0~0~C~Must check remote server certificates
allowAP~1~0~C~Enable AP Mode If Fail to Connect SSID
timezone~GMT0~1~T~Timezone string: tinyurl.com/TZstring
logType~0~99~N~Output log selection
Auth_Name~~0~T~Admin user name for WebPage
Auth_Pass~~0~T~Admin password for WebPage
formatIfMountFailed~0~1~C~Format File System on Failure
wifiTimeoutSecs~30~0~N~WiFi connect timeout (secs)
usePing~1~0~C~Use ping
alarmHour~4~1~N~Hour of Day when Run Blocklist Update
)~"
#if CONFIG_IDF_TARGET_ESP32P4
"useSnap~1~1~C~Store copy of blocklist in flash\n"
#else
"useSnap~0~1~C~Store copy of blocklist in flash\n"
#endif
R"~(
maxDomains~200~1~N~Max number of domains (* 1000)
minMemory~128~1~N~Minimum free memory (KB)
maxDomLen~100~1~N~Max length of domain name
allowCnt~0~2~D~Allowed domains
blockCnt~0~2~D~Blocked domains
fileURLc~https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts~2~D~Current URL for blocklist file
fileURLn~~2~X~Enter new URL for blocklist file or domain
loadProg~0~2~D~Blocklist download progress
)~"
#if CONFIG_IDF_TARGET_ESP32P4
"netMode~1~3~S:WiFi:Ethernet:Eth+AP~Network interface selection\n"
#else
"netMode~0~3~S:WiFi:Ethernet:Eth+AP~Network interface selection\n"
#endif
R"~(
wLoad~Check Domain~2~A~Check if domain name is blocked
uLoad~Add Domain~2~A~Add to blocklist
vLoad~Del Domain~2~A~Delete from blocklist
zLoad~Reload~2~A~Reload Blocklist
xStop~Stop Load~2~A~Stop Blocklist Load
zzCustom~Clear~2~A~Clear custom blocklist
zzzAdblockOn~1~2~C~Enable AdBlocker
ethCS~-1~3~N~Ethernet CS pin
ethInt~-1~3~N~Ethernet Interrupt pin
ethRst~-1~3~N~Ethernet Reset pin
ethSclk~-1~3~N~Ethernet SPI clock pin
ethMiso~-1~3~N~Ethernet SPI MISO pin
ethMosi~-1~3~N~Ethernet SPI MOSI pin
lampPin~0~1~N~Led status pin
lampActiveHi~0~1~C~Led Led active on Lo or Hi
lampType~0~1~C~Simple or WS2812 Led 
lampLevel~2~1~R:0:4:1~Led brightness (0 off)
)~";
