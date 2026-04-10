// Query external DNS 
//
// s60sc 2026

#include "appGlobals.h"
#include <lwip/netdb.h>
#include <lwip/dns.h>
#include <AsyncUDP.h>

#define DNS_DEFAULT_PORT 53
#define CACHE_SIZE 20 //number of previous domain names & IPs cached
#define DEFAULT_TTL 300000 // 5 minutes in ms
#define MAX_HOSTNAME 256

/************************ DNS Receiver ***************************/

AsyncUDP udp;

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed)) dns_header_t;

int parseDNSname(uint8_t *packet, int offset, char *out) {
  int i = 0;
  while (packet[offset] != 0) {
    int len = packet[offset++];
    for (int j = 0; j < len; j++) out[i++] = packet[offset++];
    out[i++] = '.';
  }
  out[i - 1] = '\0';
  return offset + 1;
}

void handleDNSpacket(AsyncUDPPacket packet) {
  uint8_t *rx = (uint8_t *)packet.data();
  int len = packet.length();

  int offset = sizeof(dns_header_t);
  if (len < offset) return;
  char domain[MAX_HOSTNAME];
  int new_offset = parseDNSname(rx, offset, domain);
  if (new_offset < 0) return;
  offset = new_offset;
  offset += 4; // skip QTYPE + QCLASS

  // Build response
  uint8_t tx[512];
  memcpy(tx, rx, len);
  dns_header_t *res = (dns_header_t *)tx;

  res->flags = htons(0x8180); // response + no error
  res->ancount = htons(1);
  int resp_offset = offset;

  // Answer: pointer to name (compression)
  tx[resp_offset++] = 0xC0;
  tx[resp_offset++] = 0x0C;

  // Type A
  tx[resp_offset++] = 0x00;
  tx[resp_offset++] = 0x01;

  // Class IN
  tx[resp_offset++] = 0x00;
  tx[resp_offset++] = 0x01;

  // TTL
  tx[resp_offset++] = 0x00;
  tx[resp_offset++] = 0x00;
  tx[resp_offset++] = 0x00;
  tx[resp_offset++] = 0x3C;

  // Data length
  tx[resp_offset++] = 0x00;
  tx[resp_offset++] = 0x04;

  // return IP to use
  IPAddress gotIP = checkBlocklist(domain);
  tx[resp_offset++] = gotIP[0];
  tx[resp_offset++] = gotIP[1];
  tx[resp_offset++] = gotIP[2];
  tx[resp_offset++] = gotIP[3];

  // Send response
  packet.write(tx, resp_offset);
}

void prepDNS() {
  if (udp.listen(DNS_DEFAULT_PORT)) {
    LOG_INF("AdBlocker server started on port %d", DNS_DEFAULT_PORT);
    udp.onPacket([](AsyncUDPPacket packet) { handleDNSpacket(packet); });
    LOG_INF("DNS Server started on %s:%d", formatIPstr(), DNS_DEFAULT_PORT);
  } else {
    snprintf(startupFailure, SF_LEN, STARTUP_FAIL "DNS server not started");
    LOG_WRN("%s", startupFailure);
  }
}

/************************ DNS Forwarder **************************/

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
        LOG_VRB("Resolved %s using cache to %d.%d.%d.%d\n", host, dnsCache[i].ip[0], dnsCache[i].ip[1], dnsCache[i].ip[2], dnsCache[i].ip[3]);
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
      LOG_VRB("Resolved %s using %s to %d.%d.%d.%d in %lums", host, DNSserverIPs[i], result[0], result[1], result[2], result[3], duration);

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
