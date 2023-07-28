/*
   ESP32_AdBlocker acts as a DNS Sinkhole by returning 0.0.0.0 for any domain names in its blocked list, 
   else forwards to an external DNS server to resolve IP addresses. This prevents content being retrieved 
   from or sent to blocked domains. Checks generally take <100us.

   To use ESP32_AdBlocker, enter its IP address in place of the DNS server IPs in your router/devices.
   Currently it does not have an IPv6 address and some devices use IPv6 by default, so disable IPv6 DNS on 
   your device / router to force it to use IPv4 DNS.

   Blocklist files can downloaded from hosting sites and should either be in HOSTS format 
   or Adblock format (only domain name entries processed)

   arduino-esp32 library DNSServer.cpp modified as custom AdBlockerDNSServer.cpp so that DNSServer::processNextRequest()
   calls checkBlocklist() in ESP32_AdBlocker to check if domain blocked, which returns the relevant IP. 
   Based on idea from https://github.com/rubfi/esphole

   s60sc 2020, 2023
*/

#include "appGlobals.h"

static bool startedUp = false;

void setup() { 
  logSetup();
  if (!psramFound()) sprintf(startupFailure, "Startup Failure: Need PSRAM to be enabled");
  startStorage();
  loadConfig();

#ifdef DEV_ONLY
  devSetup();
#endif

  // connect wifi or start config AP if router details not available
  startWifi(); 
  
  startWebServer();
  if (strlen(startupFailure)) LOG_ERR("%s", startupFailure);
  else {
    // start rest of services
    checkMemory();
    appSetup();
    LOG_INF(APP_NAME " v" APP_VER " ready ...");
    startedUp = true;
    checkMemory();
  }
}

void loop() {
  vTaskDelete(NULL);
}
