// AdBlocker specific functions
//
// dateno1 2026
// s60sc 2020, 2023, 2026

#include "appGlobals.h"

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
static uint32_t blockCnt = 0, allowCnt = 0, itemsLoaded = 0, duplicates = 0;
static bool stopLoad = false;
static bool downloading = false;
static bool adBlockOn = true; // whether app is set to block or not by user
static bool useSnap = false; // whether flash is used to store snapshot
size_t storageSize;
uint32_t* ptrs; // ordered pointers to domain names
char* storage; // linear domain name storage
static uint32_t lastLoadMs = 0; // millis() of last successful blocklist download

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
  // make space for new domain pointer at identified location by shifting following locations
  if (diff < 0) ptr++; // to insert after
  memmove(&ptrs[ptr + 1], &ptrs[ptr], (itemsLoaded - ptr) * sizeof(uint32_t));
  
  // insert new domain pointer
  ptrs[ptr] = blocklistSize; // points to latest domain name in 'storage'
  blocklistSize += domLen + 1; // add terminator
  itemsLoaded++;
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

DnsResult checkBlocklist(const char* domainName, IPAddress& retIP) {
  // called from externalDNS.cpp
  // normalise the query, test blocklist, return response type + answer IP
  // normalize: strip single trailing root dot, force lowercase
  // (DNS names are case-insensitive; blocklist storage is lowercase)

  // use IN_FILE_NAME_LEN (128) so names up to maxDomLen (100) + dot fit
  char normName[IN_FILE_NAME_LEN];
  size_t n = strlen(domainName);
  if (n == 0 || n >= IN_FILE_NAME_LEN) {
    retIP = IPAddress(0, 0, 0, 0);
    return DNS_SERVFAIL;
  }

  if (domainName[n - 1] == '.') n--; // tolerate "example.com."
  for (size_t i = 0; i < n; i++)
    normName[i] = (char)tolower((unsigned char)domainName[i]);
  normName[n] = 0;

  // RFC 6761: localhost is always loopback, never blocklisted
  if (!strcmp(normName, "localhost")) {
    retIP = IPAddress(127, 0, 0, 1);
    ++allowCnt;
    LOG_VRB("%s -> loopback (fixed)", normName);
    return DNS_RESOLVED;
  }

  bool blocked = false;
  if (adBlockOn) {
    static char blockedDomain[IN_FILE_NAME_LEN] = {0};
    uint64_t usElapsed = micros();
    // check if received domain name same as previous blocked domain to skip search
    blocked = !strcmp(normName, blockedDomain) ? true : (bool)binarySearch(normName, false);
    if (blocked) strcpy(blockedDomain, normName);
    blocked ? ++blockCnt : ++allowCnt;
    uint64_t checkTime = micros() - usElapsed;
    LOG_VRB("Check %s %s in %lluus", normName, (blocked) ? "*Blocked*" : "Allowed", checkTime);
  }
  if (blocked) {
    retIP = IPAddress(0, 0, 0, 0); // sinkhole only for blocklist hits
    return DNS_BLOCKED;
  }
  // not in blocklist -> query forwarder, distinguishing NXDOMAIN from SERVFAIL
  return resolveDomainStatus(normName, retIP);
}

static void checkDomain(const char* inName, bool doUpdate, bool doDelete) {
  // check if user supplied domain name is present or update user supplied name
  char domName[IN_FILE_NAME_LEN];
  strncpy(domName, inName, sizeof(domName) - 1);
  domName[sizeof(domName) - 1] = 0;

  if (size_t domLen = formatDomain(domName); domLen > 0) {
    if (domLen >= maxDomLen) LOG_ALT("Domain name %s is too long to process", domName);
    else {
      uint32_t blPtr = binarySearch(domName, doUpdate);
      if (doUpdate) { // addition
        if (blPtr) {
          // not found, so insert domain if resolves at blPtr location
          if (resolveDomain(domName) != IPAddress(0, 0, 0, 0)) {
            // resolved
            addDomain(blPtr, domName, domLen);
            if (updateCustomFile(domName, false)) LOG_ALT("Domain name %s IS added to blocklist", domName);
          } else LOG_ALT("Domain name %s NOT added to blocklist as not resolved", domName);
        } else LOG_ALT("Domain name %s NOT added to blocklist as duplicate", domName);
      } else {
        // delete or just check
        if (doDelete) { // deletion
          if (blPtr) {
            // found, so delete
            *(storage + ptrs[blPtr]) = 0; // set domain name empty
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
    // write processed domain to storage
    size_t domLen = formatDomain(tokenItem);
    if (domLen && (domLen < maxDomLen)) {
      // never store loopback names from hosts file headers
      if (!strcasecmp(tokenItem, "localhost") ||
          !strcasecmp(tokenItem, "localhost.localdomain") ||
          !strcasecmp(tokenItem, "local")) return;
      uint32_t ptr = binarySearch(tokenItem, true);
      if (ptr) addDomain(ptr, tokenItem, domLen);
      else duplicates++;
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
          if (left > storageSize) LOG_WRN("File is larger than memory, may get truncated");
          WiFiClient* stream = https.getStreamPtr(); // stream data to client
          uint32_t lastRead = millis();
          size_t lineCnt = 0;

          while (https.connected() && (left > 0 || left == -1)) {
            if (stopLoad) break;
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
                if (remaining < maxLineLen) {
                  LOG_ALT("Blocklist truncated to avoid memory overflow, %u bytes remaining\n", remaining);
                  break;
                }
                // show progress
                if (left > 0) {
                  float loadProg = (float)(downloadSize * 100.0 / (downloadSize + left));
                  LOG_SEND("%0.1f%%\n", loadProg);
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
          LOG_INF("Download complete, processed %s in %lu secs", fmtSize(downloadSize), (millis() - loadTime) / 1000);
          LOG_ALT("Loaded %lu blocked domains excluding %lu duplicates, using %s of %s", itemsLoaded - 2, duplicates, fmtSize(blocklistSize), fmtStorageSize);
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
  static uint32_t customAdded = 0, customDeleted = 0;
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
          strcpy(domName, customLineStr.substring(1).c_str());
        } else strcpy(domName, customLineStr.c_str()); // addition
        uint32_t blPtr = binarySearch(domName, doAdd);
        if (blPtr) {
          if (doAdd) {
            // addition
            addDomain(blPtr, domName, strlen(domName));
            customAdded++;
          } else {
			// deletion
            *(storage + ptrs[blPtr]) = 0; // set domain name empty
            customDeleted++;
          }
        } else LOG_WRN("Ignored custom %s of %s", doAdd ? "addition" : "deletion", domName);
      }
    }
    file.close();
  }
  LOG_ALT("Loaded %lu custom blocked domains, unblocked %lu domains", customAdded, customDeleted);
}

static void showBlockList(int maxItems = 0) {
  // for info
  if (!maxItems) maxItems = itemsLoaded;
  for (int i = 0; i < maxItems; i++) LOG_SEND("%d: %s\n", i, storage + ptrs[i]);
  LOG_SEND("Total %lu items\n", itemsLoaded);
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
  if (itemsLoaded < 3 || blocklistSize < 4096) { LOG_WRN("Snap skip: tiny"); return; }

  // LittleFS space check (worst-case encoding: every entry unmatched)
  uint32_t worstCase = blocklistSize + itemsLoaded * 2 + sizeof(SnapHdr) + 4096;
  uint32_t freeFs = STORAGE.totalBytes() - STORAGE.usedBytes();
  if (freeFs < worstCase) {
    LOG_WRN("Snap skipped: flash free %uKB < needed ~%uKB",
            (unsigned)(freeFs / 1024), (unsigned)(worstCase / 1024));
    return;
  }

  // corruption tripwire accumulators
  uint32_t nameBytes  = 0;
  uint32_t matchBytes = 0;

  SnapHdr h; memset(&h, 0, sizeof(h));
  h.magic = SNAP_MAGIC; h.ver = SNAP_VER;
  h.items = itemsLoaded; h.blsize = blocklistSize;
  h.blockCnt = blockCnt; h.allowCnt = allowCnt; h.duplicates = duplicates;

  char tmpPath[80];
  snprintf(tmpPath, sizeof(tmpPath), "%s.tmp", SNAP_PATH);

  File f = STORAGE.open(tmpPath, FILE_WRITE);
  if (!f) { LOG_ERR("Snap OPEN FAILED: %s", tmpPath); return; }
  f.write((uint8_t*)&h, sizeof(h));              // placeholder header, finalized below

  uint32_t crc      = crc32_begin();
  uint32_t encBytes = 0;
  const char* prev    = "";
  size_t      prevLen = 0;
  bool ok = true;
  uint32_t t0 = millis();

  for (uint32_t i = 0; i < itemsLoaded && ok; i++) {
    const char* cur    = storage + ptrs[i];
    size_t      maxCur = blocklistSize - ptrs[i];
    size_t      cl     = strnlen(cur, maxCur);     // BOUNDED strlen

    if (cl >= maxCur) {                            // unterminated entry!
      LOG_ERR("Snap: entry %u UNTERMINATED at offset %u",
              (unsigned)i, (unsigned)ptrs[i]);
      LOG_SEND("first32: ");
      for (size_t k = 0; k < 32 && ptrs[i] + k < blocklistSize; k++)
        LOG_SEND("%02x ", cur[k]);
      LOG_SEND("\n");
      ok = false;
      break;
    }

    size_t ml = 0;
    while (ml < cl && ml < prevLen && ml < 255 && cur[ml] == prev[ml]) ml++;
    size_t sl = cl - ml;
    if (sl > 255) { ml -= (sl - 255); sl = 255; }

    uint8_t lens[2] = { (uint8_t)ml, (uint8_t)sl };
    crc = crc32_upd(crc, lens, 2);
    crc = crc32_upd(crc, (const uint8_t*)cur + ml, sl);
    ok = f.write(lens, 2) == 2 &&
         (sl == 0 || f.write((const uint8_t*)cur + ml, sl) == sl);
    encBytes   += 2 + sl;
    nameBytes  += cl;
    matchBytes += ml;
    prev = cur; prevLen = cl;
  }

  // corruption tripwire: encoded stream can never exceed names + 2B/entry
  if (encBytes > nameBytes + itemsLoaded * 2 + 16) {
    f.close();
    STORAGE.remove(tmpPath);
    LOG_ERR("Snap ABORTED: encoder wrote %luKB for %luKB of names "
            "(entries=%u matched=%luKB) - memory corruption suspected",
            (unsigned long)(encBytes / 1024), (unsigned long)(nameBytes / 1024),
            (unsigned)itemsLoaded, (unsigned long)(matchBytes / 1024));
    return;                                        // flash untouched
  }

  if (ok) {
    h.rawLen = encBytes;
    h.crc    = crc32_end(crc);
    f.seek(0);
    f.write((uint8_t*)&h, sizeof(h));              // finalize header
  }
  f.close();

  if (!ok) {
    STORAGE.remove(tmpPath);
    LOG_WRN("Snapshot encode failed - removed");
    return;
  }

  STORAGE.remove(SNAP_PATH);                       // drop previous generation
  if (!STORAGE.rename(tmpPath, SNAP_PATH)) {
    LOG_ERR("Snap rename %s -> %s failed", tmpPath, SNAP_PATH);
    STORAGE.remove(tmpPath);
    return;
  }

    LOG_INF("Snapshot saved: %u domains, %luKB -> %luKB (%lu s) "
          "[names %luKB, prefix-matched %luKB]",
          (unsigned)(itemsLoaded - 2), (unsigned long)(blocklistSize / 1024),
          (unsigned long)(encBytes / 1024), (unsigned long)((millis() - t0) / 1000),
          (unsigned long)(nameBytes / 1024), (unsigned long)(matchBytes / 1024));
}

/* Restore arena from snapshot. No WiFi / no valid clock required.
 * The sorted pointer table is rebuilt by walking the NUL-separated
 * entries, then verified against the stored item count. */
static bool loadSnapshot() {
  File f = STORAGE.open(SNAP_PATH, FILE_READ);
  if (!f) { LOG_INF("No snapshot yet (%s)", SNAP_PATH); return false; }

  SnapHdr h;
  if (f.read((uint8_t*)&h, sizeof(h)) != sizeof(h))
    SNAP_FAIL("header read");
  if (h.magic != SNAP_MAGIC)
    SNAP_FAIL("bad magic");
  if (h.ver   != SNAP_VER)
    SNAP_FAIL("version %u", h.ver);
  if (h.items < 2 || h.items > maxDomains)
    SNAP_FAIL("item count %lu", h.items);
  if (h.blsize == 0 || h.blsize > storageSize)
    SNAP_FAIL("arena %luKB exceeds storage %luKB",
              (unsigned long)(h.blsize / 1024), (unsigned long)(storageSize / 1024));

  memset(ptrs, 0, (maxDomains + 2) * sizeof(uint32_t));
  uint32_t crc = crc32_begin();
  uint32_t pos = 0, idx = 0, enc = 0;
  uint32_t prevPtr = 0;
  bool havePrev = false, ok = true;

  while (idx < h.items && ok) {
    uint8_t lens[2];
    if (f.read(lens, 2) != 2) { ok = false; break; }
    crc = crc32_upd(crc, lens, 2); enc += 2;
    size_t ml = lens[0], sl = lens[1];

    ptrs[idx] = pos;
    if (ml) {                                   // shared prefix from neighbour
      if (!havePrev || ml > strlen(storage + prevPtr)) { ok = false; break; }
      memcpy(storage + pos, storage + prevPtr, ml);
    }
    if (sl) {
      if (pos + ml + sl + 1 > storageSize) { ok = false; break; }
      if (f.read((uint8_t*)storage + pos + ml, sl) != sl) { ok = false; break; }
      crc = crc32_upd(crc, (const uint8_t*)storage + pos + ml, sl);
    }
    storage[pos + ml + sl] = 0;
    enc += sl;
    prevPtr = pos; havePrev = true;
    pos += ml + sl + 1;
    idx++;
  }
  crc = crc32_end(crc);
  f.close();

  if (!ok || idx != h.items || pos != h.blsize || crc != h.crc) {
    LOG_WRN("Snapshot invalid (%s)",
            crc != h.crc ? "CRC" : idx != h.items ? "count" : "bounds");
    return false;
  }
  ptrs[idx] = pos;                              // trailing sentinel
  blocklistSize = h.blsize;  itemsLoaded = h.items;
  blockCnt = h.blockCnt;     allowCnt = h.allowCnt; duplicates = h.duplicates;
  lastLoadMs = millis();
  startupFailure[0] = 0;
  LOG_ALT("Restored %lu domains (%s) from snapshot", itemsLoaded - 2, fmtSize(blocklistSize));
  return true;
}

/* Reset storage to the primed ("!" + "#") state so a retry never inherits
 * partial data from an interrupted download (dedupe counts, truncation). */
static void resetBlocklistStorage() {
  memset(ptrs, 0, (maxDomains + 2) * sizeof(uint32_t));
  memset(storage, 0, storageSize);  // ← FULL WIPE (was: maxDomLen + 8)
  // prime domain storage for binary search to prevent pointer 0 being returned
  memcpy(storage, "!", 1); // always first so ptrs[0] = 0
  blocklistSize = 2;
  itemsLoaded = 1;
  addDomain(0, "#", 1);
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
    bool canReplace = restored || STORAGE.exists(SNAP_PATH);
    
    if (timeSynchronized || !useSecure) {
      if (canReplace && itemsLoaded > 2) resetBlocklistStorage(); // fresh build, not merge
      res = downloadBlockList();
      if (!res) resetBlocklistStorage();
      if (res) {
        lastLoadMs = millis();
        startupFailure[0] = 0;
        if (useSnap) saveSnapshot(); // new generation persisted
      } else if (canReplace) {
        /* rebuild failed - reinstate previous generation from flash */
        resetBlocklistStorage();
        if (useSnap) restored = loadSnapshot();
        if (itemsLoaded <= 2) {
          if (!strlen(ST_SSID))
            LOG_ALT("First-time setup: set router SSID/Password in Network Settings");
          else {
            snprintf(startupFailure, SF_LEN, STARTUP_FAIL "Blocklist URL %s failed to load", fileURL);
            LOG_WRN("%s", startupFailure);
          }
        } else {
          LOG_WRN("%s load failed - serving previous %lu-domain list", reason, itemsLoaded - 2);
        }
      } else if (itemsLoaded <= 2) {
        // snapshot not enabled / available
        if (!strlen(ST_SSID)) {
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
      LOG_WRN("Network/time not ready (%s)", strlen(ST_SSID) ? (netIsConnected() ? "clock" : "wifi") : "unconfigured");
    }
    downloading = false;
  } else LOG_WRN("Ignore request as download in progress");
  return res;
}

bool appSetup() {
  while (!strlen(fileURL)) {
    LOG_ALT("Enter blocklist URL on web page ...");
    delay(30000); // wait for file URL to be entered
  }
  ptrs = (uint32_t*)ps_calloc((maxDomains + 2), sizeof(uint32_t)); // for sorted pointers
  storageSize = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) - minMemory;
  if (!ptrs || storageSize < ONEMEG * 4) {
    snprintf(startupFailure, SF_LEN, STARTUP_FAIL "Insufficient PSRAM for useful blocklist");
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
  loadBlockList("Initial"); // best effort - DNS starts regardless
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
    if (strlen(value)) {
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
      LOG_SEND("%s\n", jsonBuff);
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
  } else if (checkAlarm() && strlen(fileURL)) loadBlockList("Scheduled");
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
useSnap~0~1~C~Store copy of blocklist in flash
maxDomains~250~1~N~Max number of domains (* 1000)
minMemory~128~1~N~Minimum free memory (KB)
maxDomLen~100~1~N~Max length of domain name
allowCnt~0~2~D~Allowed domains
blockCnt~0~2~D~Blocked domains
fileURLc~https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts~2~D~Current URL for blocklist file
fileURLn~~2~X~Enter new URL for blocklist file or domain
loadProg~0~2~D~Blocklist download progress
netMode~0~3~S:WiFi:Ethernet:Eth+AP~Network interface selection
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
)~";
