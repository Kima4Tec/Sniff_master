#include "Arduino.h"
#include "esp_wifi.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiClientSecure.h>
#include "mbedtls/sha256.h"
#include <ArduinoJson.h>
#include "secrets.h"   // SSID, WIFIPASSWORD
#include "config.h"    // DEVICENAME
#include "ca_cert.h"   // ikke længere brugt, men beholdt for kompatibilitet

// ===================== CONFIG =====================
// UDP destination — sæt til laptoppens IP og port
#define UDP_HOST     "192.168.0.144"   // <-- SKIFT TIL LAPTOPPENS IP
#define UDP_PORT     5005

// Master-position i rummet (meter)
#define MASTER_X   0.0f
#define MASTER_Y   4.0f

#define WINDOW_MS   2000
#define MIN_RSSI    -85
#define MAX_DEVICES  40
#define THROTTLE_MS  500
#define ROUTER_CHANNEL 6

// ===================== UDP =====================
static WiFiUDP udp;

void sendUDP(const char* payload) {
  udp.beginPacket(UDP_HOST, UDP_PORT);
  udp.write((const uint8_t*)payload, strlen(payload));
  udp.endPacket();
}

// ===================== DAGLIGT SALT =====================
static char dailySalt[16] = "SALT_INIT";

void updateDailySalt() {
  struct tm t;
  if (getLocalTime(&t)) {
    snprintf(dailySalt, sizeof(dailySalt), "%04d%02d%02d",
      t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);
  }
}



// ===================== ANONYMISERING =====================
void makeDevId(const char* macHash, char* outDevId) {
  char input[32];
  snprintf(input, sizeof(input), "%s%s", macHash, dailySalt);
  uint8_t digest[32];
  mbedtls_sha256_ret((const uint8_t*)input, strlen(input), digest, 0);
  snprintf(outDevId, 10, "DEV-%02X%02X", digest[0], digest[1]);
}

// ===================== MAC HASH =====================
void macToHash(const uint8_t* mac, char* outHex8) {
  uint8_t input[6 + 20];
  memcpy(input, mac, 6);
  memcpy(input + 6, SALT, strlen(SALT));
  uint8_t digest[32];
  mbedtls_sha256_ret(input, 6 + strlen(SALT), digest, 0);
  snprintf(outHex8, 9, "%02X%02X%02X%02X",
    digest[0], digest[1], digest[2], digest[3]);
}

// ===================== DEVICE TABLE =====================
typedef struct {
  char          macHash[9];
  char          devId[10];
  float         axPos, ayPos;
  int8_t        aRssi;
  unsigned long aTime;
  float         bxPos, byPos;
  int8_t        bRssi;
  unsigned long bTime;
  float         mxPos, myPos;
  int8_t        mRssi;
  unsigned long mTime;
  float         estX, estY;
  bool          published;
} DeviceEntry;

static DeviceEntry devices[MAX_DEVICES];
static int         deviceCount = 0;

DeviceEntry* findOrCreate(const char* macHash) {
  for (int i = 0; i < deviceCount; i++) {
    if (strcmp(devices[i].macHash, macHash) == 0) return &devices[i];
  }
  if (deviceCount >= MAX_DEVICES) {
    int oldest = 0;
    unsigned long minTime = ULONG_MAX;
    for (int i = 0; i < MAX_DEVICES; i++) {
      unsigned long t = max({devices[i].aTime, devices[i].bTime, devices[i].mTime});
      if (t < minTime) { minTime = t; oldest = i; }
    }
    memset(&devices[oldest], 0, sizeof(DeviceEntry));
    strncpy(devices[oldest].macHash, macHash, 9);
    makeDevId(macHash, devices[oldest].devId);
    return &devices[oldest];
  }
  DeviceEntry* e = &devices[deviceCount++];
  memset(e, 0, sizeof(DeviceEntry));
  strncpy(e->macHash, macHash, 9);
  makeDevId(macHash, e->devId);
  return e;
}

// ===================== TRILATERERING =====================
float rssiToDistance(int8_t rssi, int txPower = -59, float n = 2.5) {
  return pow(10.0f, (txPower - rssi) / (10.0f * n));
}

static bool weightedCentroid(float x1, float y1, int8_t r1,
                              float x2, float y2, int8_t r2,
                              float* outX, float* outY) {
  float d1 = rssiToDistance(r1), w1 = 1.0f / (d1*d1 + 0.001f);
  float d2 = rssiToDistance(r2), w2 = 1.0f / (d2*d2 + 0.001f);
  float total = w1 + w2;
  *outX = (w1*x1 + w2*x2) / total;
  *outY = (w1*y1 + w2*y2) / total;
  return true;
}

bool triangulate(DeviceEntry* dev, float* outX, float* outY) {
  unsigned long now = millis();
  bool hasA = (dev->aTime > 0) && ((now - dev->aTime) < WINDOW_MS) && (dev->aRssi > MIN_RSSI);
  bool hasB = (dev->bTime > 0) && ((now - dev->bTime) < WINDOW_MS) && (dev->bRssi > MIN_RSSI);
  bool hasM = (dev->mTime > 0) && ((now - dev->mTime) < WINDOW_MS) && (dev->mRssi > MIN_RSSI);

  int count = (int)hasA + (int)hasB + (int)hasM;
  if (count == 0) return false;

  if (count == 1) {
    if (hasA)      { *outX = dev->axPos; *outY = dev->ayPos; }
    else if (hasB) { *outX = dev->bxPos; *outY = dev->byPos; }
    else           { *outX = MASTER_X;   *outY = MASTER_Y; }
    return true;
  }

  if (count == 2) {
    float x1, y1, x2, y2; int8_t r1, r2;
    if      (!hasA) { x1=dev->bxPos; y1=dev->byPos; r1=dev->bRssi; x2=MASTER_X;   y2=MASTER_Y;   r2=dev->mRssi; }
    else if (!hasB) { x1=dev->axPos; y1=dev->ayPos; r1=dev->aRssi; x2=MASTER_X;   y2=MASTER_Y;   r2=dev->mRssi; }
    else            { x1=dev->axPos; y1=dev->ayPos; r1=dev->aRssi; x2=dev->bxPos; y2=dev->byPos; r2=dev->bRssi; }
    return weightedCentroid(x1, y1, r1, x2, y2, r2, outX, outY);
  }

  // Alle 3 — ægte trilaterering med Cramers regel
  float x1 = dev->axPos, y1 = dev->ayPos, d1 = rssiToDistance(dev->aRssi);
  float x2 = dev->bxPos, y2 = dev->byPos, d2 = rssiToDistance(dev->bRssi);
  float x3 = MASTER_X,   y3 = MASTER_Y,   d3 = rssiToDistance(dev->mRssi);

  float A11 = 2*(x2-x1), A12 = 2*(y2-y1);
  float A21 = 2*(x3-x1), A22 = 2*(y3-y1);
  float b1  = d1*d1 - d2*d2 - x1*x1 + x2*x2 - y1*y1 + y2*y2;
  float b2  = d1*d1 - d3*d3 - x1*x1 + x3*x3 - y1*y1 + y3*y3;
  float det = A11*A22 - A12*A21;

  if (fabsf(det) < 0.001f) {
    float totalW = 0, sumX = 0, sumY = 0;
    auto add = [&](float x, float y, int8_t rssi) {
      float d = rssiToDistance(rssi);
      float w = 1.0f / (d*d + 0.001f);
      sumX += w*x; sumY += w*y; totalW += w;
    };
    add(x1, y1, dev->aRssi);
    add(x2, y2, dev->bRssi);
    add(x3, y3, dev->mRssi);
    *outX = sumX / totalW;
    *outY = sumY / totalW;
    return true;
  }

  *outX = (b1*A22 - b2*A12) / det;
  *outY = (A11*b2 - A21*b1) / det;
  return true;
}

// ===================== SNIFFER =====================
#define QUEUE_SIZE 32

typedef struct { uint8_t mac[6]; int8_t rssi; } SniffEvent;
static SniffEvent    sniffQueue[QUEUE_SIZE];
static volatile int  qHead = 0;
static volatile int  qTail = 0;
static inline bool   qFull()  { return ((qTail + 1) % QUEUE_SIZE) == qHead; }
static inline bool   qEmpty() { return qHead == qTail; }

typedef struct {
  uint8_t frame_ctrl[2], duration[2], addr1[6], addr2[6], addr3[6], seq_ctrl[2];
} wifi_ieee80211_mac_hdr_t;
typedef struct { wifi_ieee80211_mac_hdr_t hdr; uint8_t payload[0]; } wifi_ieee80211_packet_t;

void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  wifi_promiscuous_pkt_t*  pkt  = (wifi_promiscuous_pkt_t*)buf;
  wifi_ieee80211_packet_t* ipkt = (wifi_ieee80211_packet_t*)pkt->payload;
  uint8_t* mac = ipkt->hdr.addr2;
  if (mac[0] & 0x01) return;
  if (mac[0] & 0x02) return;
  if (!qFull()) {
    memcpy(sniffQueue[qTail].mac, mac, 6);
    sniffQueue[qTail].rssi = pkt->rx_ctrl.rssi;
    qTail = (qTail + 1) % QUEUE_SIZE;
  }
}

// ===================== SLAVE DATA VIA UDP INDGÅENDE =====================
// Slaverne sender stadig til MQTT-brokeren — masteren abonnerer IKKE længere.
// Slaves' data modtages via dedikeret UDP-port fra slaverne direkte.
// Slave skal sende til MASTER_UDP_PORT i stedet for MQTT.
#define SLAVE_UDP_PORT 5006
static WiFiUDP slaveUdp;

void processSlavePacket(const char* buf, size_t len) {
  char tmp[256];
  if (len >= sizeof(tmp)) return;
  memcpy(tmp, buf, len);
  tmp[len] = '\0';

  JsonDocument doc;
  if (deserializeJson(doc, tmp)) return;

  const char* macHash = doc["macHash"];
  int8_t      rssi    = doc["rssi"];
  float       sx      = doc["x"];
  float       sy      = doc["y"];
  const char* slave   = doc["slave"];

  if (!macHash || !slave || rssi >= 0 || rssi < MIN_RSSI) return;

  DeviceEntry* dev = findOrCreate(macHash);
  unsigned long now = millis();

  // Identificer slave på navn
  if (strstr(slave, "ESP32_A")) {
    dev->aRssi = rssi; dev->axPos = sx; dev->ayPos = sy; dev->aTime = now;
  } else if (strstr(slave, "ESP32_B")) {
    dev->bRssi = rssi; dev->bxPos = sx; dev->byPos = sy; dev->bTime = now;
  }

  float ex, ey;
  if (triangulate(dev, &ex, &ey)) {
    dev->estX = ex; dev->estY = ey; dev->published = false;
  }
}

// ===================== THROTTLE =====================
#define THROTTLE_SLOTS 32
typedef struct { char hash[9]; unsigned long lastSent; } ThrottleEntry;
static ThrottleEntry throttleTable[THROTTLE_SLOTS];
static int           throttleCount = 0;

bool shouldProcess(const char* hash) {
  unsigned long now = millis();
  for (int i = 0; i < throttleCount; i++) {
    if (strcmp(throttleTable[i].hash, hash) == 0) {
      if (now - throttleTable[i].lastSent < THROTTLE_MS) return false;
      throttleTable[i].lastSent = now;
      return true;
    }
  }
  if (throttleCount < THROTTLE_SLOTS) {
    strncpy(throttleTable[throttleCount].hash, hash, 9);
    throttleTable[throttleCount].lastSent = now;
    throttleCount++;
  }
  return true;
}

// ===================== TIMESTAMP =====================
String getTimestamp() {
  struct tm t;
  char buf[30] = "unknown";
  if (getLocalTime(&t)) strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &t);
  return String(buf);
}

// ===================== WIFI =====================
void initWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(SSID, WIFIPASSWORD);
  Serial.print("[WIFI] Forbinder");
  while (WiFi.status() != WL_CONNECTED) { Serial.print("."); delay(500); }
  Serial.println("\n[WIFI] Forbundet: " + WiFi.localIP().toString());
}

// ===================== SETUP =====================
void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("========================================");
  Serial.printf("[BOOT] Master starter @ (%.1f, %.1f)\n", MASTER_X, MASTER_Y);
  Serial.printf("[BOOT] UDP → %s:%d\n", UDP_HOST, UDP_PORT);
  Serial.println("========================================");

  initWiFi();

  udp.begin(WiFi.localIP(), 0);
  slaveUdp.begin(SLAVE_UDP_PORT);
  Serial.printf("[UDP] Lytter på slave-data port %d\n", SLAVE_UDP_PORT);

  configTime(0, 0, "pool.ntp.org");
  setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3", 1);
  tzset();
  delay(1500);
  Serial.println("[NTP] Tid synkroniseret");

  updateDailySalt();
  Serial.printf("[MASTER] Salt: %s\n", dailySalt);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_channel(ROUTER_CHANNEL, WIFI_SECOND_CHAN_NONE);
  Serial.printf("[SNIFFER] Kørende på kanal %d\n", ROUTER_CHANNEL);
  Serial.println("========================================");
}

// ===================== LOOP =====================
static unsigned long lastSaltCheck = 0;
static int           lastDay       = -1;

void loop() {
  // Opdater dagligt salt
  if (millis() - lastSaltCheck > 60000) {
    lastSaltCheck = millis();
    struct tm t;
    if (getLocalTime(&t) && t.tm_mday != lastDay) {
      lastDay = t.tm_mday;
      updateDailySalt();
      Serial.printf("[MASTER] Salt opdateret: %s\n", dailySalt);
    }
  }

  // Modtag slave-pakker via UDP
  int pktSize = slaveUdp.parsePacket();
  if (pktSize > 0 && pktSize < 256) {
    char buf[256];
    int len = slaveUdp.read(buf, sizeof(buf) - 1);
    if (len > 0) processSlavePacket(buf, len);
  }

  // Drain master sniffer queue
  while (!qEmpty()) {
    SniffEvent evt = sniffQueue[qHead];
    qHead = (qHead + 1) % QUEUE_SIZE;

    char macHash[9];
    macToHash(evt.mac, macHash);
    if (!shouldProcess(macHash)) continue;

    DeviceEntry* dev = findOrCreate(macHash);
    dev->mRssi = evt.rssi;
    dev->mxPos = MASTER_X;
    dev->myPos = MASTER_Y;
    dev->mTime = millis();

    float ex, ey;
    if (triangulate(dev, &ex, &ey)) {
      dev->estX = ex; dev->estY = ey; dev->published = false;
    }
  }

  // Send klar-til-send entries via UDP til laptop
  for (int i = 0; i < deviceCount; i++) {
    if (!devices[i].published) {
      char payload[192];
      snprintf(payload, sizeof(payload),
        "{\"devId\":\"%s\",\"x\":%.2f,\"y\":%.2f,\"ts\":\"%s\"}",
        devices[i].devId, devices[i].estX, devices[i].estY,
        getTimestamp().c_str());
      sendUDP(payload);
      devices[i].published = true;
      Serial.printf("[UDP] Sendt: %s @ (%.2f, %.2f)\n",
        devices[i].devId, devices[i].estX, devices[i].estY);
    }
  }

  // Ryd enheder ikke set i 30 sek
  unsigned long now = millis();
  for (int i = 0; i < deviceCount; i++) {
    unsigned long newest = max({devices[i].aTime, devices[i].bTime, devices[i].mTime});
    if (newest > 0 && (now - newest) > 30000) {
      devices[i] = devices[deviceCount - 1];
      memset(&devices[deviceCount - 1], 0, sizeof(DeviceEntry));
      deviceCount--;
      i--;
    }
  }
}
