/*
   ESP32_AdBlocker acts as a DNS Sinkhole by returning 0.0.0.0 for any domain names in its blocked list, 
   else forwards to an external DNS server to resolve IP addresses. This prevents content being retrieved 
   from or sent to blocked domains. Checks generally take <100us.

   To use ESP32_AdBlocker, enter its IP address in place of the DNS server IPs in your router/devices.
   Currently it does not have an IPv6 address and some devices use IPv6 by default, so disable IPv6 DNS on 
   your device / router to force it to use IPv4 DNS.

   Blocklist files can be downloaded from hosting sites and should either be in HOSTS format 
   or Adblock format (only domain name entries processed)

   arduino-esp32 library DNSServer.cpp modified as custom AdBlockerDNSServer.cpp so that DNSServer::processNextRequest()
   calls checkBlocklist() in ESP32_AdBlocker to check if domain blocked, which returns the relevant IP. 
   Based on idea from https://github.com/rubfi/esphole

   s60sc 2020, 2023
*/

#include "appGlobals.h"

void setup() { 
  logSetup();
  // prep data storage
  if (startStorage()) {
    // Load saved user configuration
    if (loadConfig()) {
      if (psramFound()) {
        LOG_INF("PSRAM size: %s", fmtSize(ESP.getPsramSize()));
        if (ESP.getPsramSize() < 3 * ONEMEG) 
          snprintf(startupFailure, SF_LEN, STARTUP_FAIL "Insufficient PSRAM for app");
      }
      else snprintf(startupFailure, SF_LEN, STARTUP_FAIL "Need PSRAM to be enabled");
    }
  }

#ifdef DEV_ONLY
  devSetup();
#endif

  // connect wifi or start config AP if router details not available
  startNetwork(); 
  
  if (startWebServer()) {
    // start rest of services
    appSetup();
    checkMemory();
  }
}

void loop() {
  // confirm not blocked in setup
  LOG_INF("=============== Total tasks: %u ===============\n", uxTaskGetNumberOfTasks() - 1);
  delay(1000);
  vTaskDelete(NULL); // free 8k ram
}
