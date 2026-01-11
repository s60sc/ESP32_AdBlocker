// Query external DNS 
//
// s60sc 2026

#include "appGlobals.h"
#include <lwip/netdb.h>
#include <lwip/dns.h>

#define CACHE_SIZE 20 //number of previous domain names & IPs cached
#define DEFAULT_TTL 300000 // 5 minutes in ms
#define MAX_HOSTNAME 256

struct CacheEntry {
  char hostname[MAX_HOSTNAME] = {0};
  IPAddress ip;
  uint32_t expiry;
};
CacheEntry dnsCache[CACHE_SIZE];

IPAddress resolveDomain(const char* host) {
  // determine how to resolve received domain name
  static int cacheIndex = 0;
  uint16_t hostLen = strlen(host);
  // Ignore internal discovery
  bool isLocal = false;
  if (strstr(host, "wpad") == host) isLocal = true;
  if (!isLocal && hostLen >= 5 && strcmp(host + hostLen - 5, ".home") == 0) isLocal = true;
  if (!isLocal && hostLen >= 6 && strcmp(host + hostLen - 6, ".local") == 0) isLocal = true;
  if (isLocal) {
    LOG_VRB("Ignore internal discovery: %s", host);
    return IPAddress(0, 0, 0, 0); 
  }

  // Cached check
  uint32_t now = millis();
  for (int i = 0; i < CACHE_SIZE; i++) {
    if (dnsCache[i].hostname[0] != '\0' && strcmp(dnsCache[i].hostname, host) == 0) {
      if (now < dnsCache[i].expiry) {
        LOG_VRB("Resolved %s using cache to %s\n", host, dnsCache[i].ip.toString().c_str());
        return dnsCache[i].ip;
      } else dnsCache[i].hostname[0] = 0; // Invalidate expired
    }
  }

  // External DNS Lookup with Secondary Failover
  const char* DNSserverIPs[] = {ST_ns1, ST_ns2};
  struct addrinfo hints, *res;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;

  for (int i = 0; i < 2; i++) {
    ip_addr_t d; 
    d.type = IPADDR_TYPE_V4;
    ip4addr_aton(DNSserverIPs[i], &d.u_addr.ip4);
    dns_setserver(0, &d);

    uint32_t start = millis();
    int err = getaddrinfo(host, NULL, &hints, &res);
    uint32_t duration = millis() - start;

    if (err == 0 && res != NULL) {
      struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
      IPAddress result = IPAddress(addr->sin_addr.s_addr);
      freeaddrinfo(res);
      LOG_VRB("Resolved %s using %s to %s in %ums", host, DNSserverIPs[i], result.toString().c_str(), duration);

      // Save to local cache
      strncpy(dnsCache[cacheIndex].hostname, host, MAX_HOSTNAME - 1);
      dnsCache[cacheIndex].hostname[MAX_HOSTNAME - 1] = 0; // in case too long
      dnsCache[cacheIndex].ip = result;
      dnsCache[cacheIndex].expiry = millis() + DEFAULT_TTL;
      cacheIndex = (cacheIndex + 1) % CACHE_SIZE;
      return result;
    }
    LOG_VRB("DNS server %s unable to resolve", DNSserverIPs[i]);
  }
  return IPAddress(0, 0, 0, 0);
}
