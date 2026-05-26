#include "Arduino.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "nvs_flash.h"
#include <WiFi.h>
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include "secrets.h"
#include "config.h"
#include "ca_cert.h"
#include "mbedtls/sha256.h"
#include <math.h>

// ===================== ESP-NOW PAKKE =====================
typedef struct {
  char   nodeName[16];
  char   deviceName[16];
  int8_t rssi;
  float  distance;
} EspNowPayload;

// ===================== DETECTION QUEUE =====================
#define QUEUE_SIZE 32

typedef struct {
  char    anonId[65];
  int8_t  rssi;
  float   distance;
  bool    isKnown;
  int     knownIndex;
  bool    fromESPNow;
  char    espNowNode[16];
  char    espNowDevice[16];
} DetectionEvent;

static DetectionEvent eventQueue[QUEUE_SIZE];
static volatile int   queueHead = 0;
static volatile int   queueTail = 0;

static inline bool queueFull()  { return ((queueTail + 1) % QUEUE_SIZE) == queueHead; }
static inline bool queueEmpty() { return queueHead == queueTail; }

static inline void enqueueLocal(const char* anonId, int8_t rssi, float distance, bool isKnown, int knownIndex) {
  if (!queueFull()) {
    strncpy(eventQueue[queueTail].anonId, anonId, 65);
    eventQueue[queueTail].rssi        = rssi;
    eventQueue[queueTail].distance    = distance;
    eventQueue[queueTail].isKnown     = isKnown;
    eventQueue[queueTail].knownIndex  = knownIndex;
    eventQueue[queueTail].fromESPNow  = false;
    queueTail = (queueTail + 1) % QUEUE_SIZE;
  }
}

static inline void enqueueESPNow(const EspNowPayload* pkt) {
  if (!queueFull()) {
    eventQueue[queueTail].fromESPNow = true;
    strncpy(eventQueue[queueTail].espNowNode,   pkt->nodeName,   16);
    strncpy(eventQueue[queueTail].espNowDevice, pkt->deviceName, 16);
    eventQueue[queueTail].rssi     = pkt->rssi;
    eventQueue[queueTail].distance = pkt->distance;
    queueTail = (queueTail + 1) % QUEUE_SIZE;
  }
}

static bool dequeueEvent(DetectionEvent* out) {
  if (queueEmpty()) return false;
  *out = eventQueue[queueHead];
  queueHead = (queueHead + 1) % QUEUE_SIZE;
  return true;
}

// ===================== TRILATERATION =====================
// Gemmer seneste måling fra hver node: { nodeName, x, y, distance, timestamp }
typedef struct {
  char  nodeName[16];
  float x;
  float y;
  float distance;
  unsigned long timestamp;
} NodeMeasurement;

#define MAX_NODES 3
#define MEASUREMENT_TIMEOUT_MS (60UL * 1000UL) // 60 sekunder

static NodeMeasurement measurements[MAX_NODES];
static int measurementCount = 0;

// Find eller opret slot til en node
static int findOrCreateSlot(const char* nodeName) {
  for (int i = 0; i < measurementCount; i++) {
    if (strcmp(measurements[i].nodeName, nodeName) == 0) return i;
  }
  if (measurementCount < MAX_NODES) {
    return measurementCount++;
  }
  return -1;
}

// Ryd målinger ældre end timeout
static void cleanOldMeasurements() {
  unsigned long now = millis();
  for (int i = 0; i < measurementCount; i++) {
    if (now - measurements[i].timestamp > MEASUREMENT_TIMEOUT_MS) {
      Serial.printf("[DATA] Sletter forældet måling fra %s\n", measurements[i].nodeName);
      // Flyt sidste element til denne plads
      measurements[i] = measurements[measurementCount - 1];
      measurementCount--;
      i--;
    }
  }
}

// Trilateration — mindste kvadraters metode med 3 punkter
static bool calculatePosition(float* outX, float* outY) {
  if (measurementCount < 3) return false;

  float x1 = measurements[0].x, y1 = measurements[0].y, r1 = measurements[0].distance;
  float x2 = measurements[1].x, y2 = measurements[1].y, r2 = measurements[1].distance;
  float x3 = measurements[2].x, y3 = measurements[2].y, r3 = measurements[2].distance;

  // Løs lineært ligningssystem afledt fra tre cirkelligninger
  float A = 2 * (x2 - x1);
  float B = 2 * (y2 - y1);
  float C = r1*r1 - r2*r2 - x1*x1 + x2*x2 - y1*y1 + y2*y2;
  float D = 2 * (x3 - x2);
  float E = 2 * (y3 - y2);
  float F = r2*r2 - r3*r3 - x2*x2 + x3*x3 - y2*y2 + y3*y3;

  float denom = A * E - B * D;
  if (fabs(denom) < 0.0001) return false; // Singulær — ESP32'er på linje

  *outX = (C * E - F * B) / denom;
  *outY = (A * F - D * C) / denom;
  return true;
}

// ===================== DEVICE IDENTITY =====================
String myName = "UNKNOWN";
float  myX    = 0.0;
float  myY    = 0.0;

// ===================== TIMESTAMP =====================
String getTimestamp() {
  struct tm timeinfo;
  char timestamp[30] = "unknown";
  if (getLocalTime(&timeinfo)) {
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", &timeinfo);
  }
  return String(timestamp);
}

// ===================== HASH MAC =====================
void hashMAC(uint8_t* mac, char* output) {
  uint8_t input[6 + 20];
  memcpy(input, mac, 6);
  memcpy(input + 6, SALT, strlen(SALT));
  byte hash[32];
  mbedtls_sha256_ret(input, 6 + strlen(SALT), hash, 0);
  for (int i = 0; i < 32; i++) {
    sprintf(output + i * 2, "%02x", hash[i]);
  }
  output[64] = '\0';
}

// ===================== MQTT =====================
static WiFiClientSecure tlsClient;
static PubSubClient     mqttClient(tlsClient);

// ===================== AFSTAND FRA RSSI =====================
float calculateDistance(int rssi, int txPower = -59, float n = 2.5) {
  return pow(10.0, (txPower - rssi) / (10.0 * n));
}

// ===================== DEVICE ID =====================
void espId() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  Serial.printf("[BOOT] Min MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  for (int i = 0; i < 3; i++) {
    if (memcmp(mac, espMACs[i], 6) == 0) {
      myName = espNames[i];
      myX    = espPositions[i][0];
      myY    = espPositions[i][1];
      Serial.printf("[BOOT] %s på position (%.1f, %.1f)\n", myName.c_str(), myX, myY);
      return;
    }
  }
  Serial.println("[BOOT] ADVARSEL — MAC ikke genkendt i secrets.h!");
}

// ===================== GEM MÅLING OG BEREGN =====================
void storeMeasurementAndCalculate(const char* nodeName, float nodeX, float nodeY,
                                   float distance, const char* deviceName) {
  int slot = findOrCreateSlot(nodeName);
  if (slot < 0) return;

  strncpy(measurements[slot].nodeName, nodeName, 16);
  measurements[slot].x         = nodeX;
  measurements[slot].y         = nodeY;
  measurements[slot].distance  = distance;
  measurements[slot].timestamp = millis();

  cleanOldMeasurements();

  if (measurementCount < 3) {
    Serial.printf("[TRILAT] Venter — har %d/3 målinger\n", measurementCount);
    return;
  }

  float posX, posY;
  if (calculatePosition(&posX, &posY)) {
    Serial.printf("[TRILAT] Position beregnet: (%.2f, %.2f)\n", posX, posY);

    if (mqttClient.connected()) {
      char payload[192];
      snprintf(payload, sizeof(payload),
        "{\"device\":\"%s\",\"x\":%.2f,\"y\":%.2f,\"timestamp\":\"%s\"}",
        deviceName,
        posX,
        posY,
        getTimestamp().c_str()
      );
      mqttClient.publish("/devices/device03/position", payload);
      Serial.println("[MQTT] Position sendt: " + String(payload));
    }

    // Ryd efter beregning
    measurementCount = 0;
    Serial.println("[DATA] Målinger ryddet efter beregning");
  } else {
    Serial.println("[TRILAT] Beregning fejlede — ESP32'er muligvis på linje");
  }
}

// ===================== ESP-NOW MODTAG =====================
void onESPNowReceive(const uint8_t* mac, const uint8_t* data, int len) {
  if (len != sizeof(EspNowPayload)) return;
  EspNowPayload pkt;
  memcpy(&pkt, data, sizeof(pkt));
  enqueueESPNow(&pkt);
}

// ===================== SNIFFER CALLBACK =====================
void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;

  typedef struct {
    uint8_t frame_ctrl[2];
    uint8_t duration[2];
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint8_t seq_ctrl[2];
  } hdr_t;

  hdr_t* hdr = (hdr_t*)pkt->payload;
  uint8_t* mac = hdr->addr2;
  if (mac[0] & 0x01) return;

  int8_t rssi    = pkt->rx_ctrl.rssi;
  float distance = calculateDistance(rssi);

  bool isKnown   = false;
  int knownIndex = -1;
  for (int i = 0; i < knownMACCount; i++) {
    if (memcmp(mac, knownMACs[i], 6) == 0) {
      isKnown    = true;
      knownIndex = i;
      break;
    }
  }

  char anonId[65];
  hashMAC(mac, anonId);
  enqueueLocal(anonId, rssi, distance, isKnown, knownIndex);
}

// ===================== WIFI =====================
void initWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(SSID, WIFIPASSWORD);
  Serial.print("[WIFI] Forbinder");
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(500);
  }
  Serial.println("\n[WIFI] Forbundet: " + WiFi.localIP().toString());
}

// ===================== MQTT RECONNECT =====================
void reconnectMQTT() {
  int attempts = 0;
  while (!mqttClient.connected() && attempts < 5) {
    Serial.printf("[MQTT] Forbinder til %s:%d ...\n", MQTT_HOST, MQTT_PORT);
    String clientId = "ESP32Master-" + String(random(0xffff), HEX);
    if (mqttClient.connect(clientId.c_str(), MQTT_USER, MQTT_PASS)) {
      Serial.println("[MQTT] Forbundet!");
    } else {
      Serial.printf("[MQTT] Fejlede, rc=%d — prøver igen om 5 sek\n", mqttClient.state());
      attempts++;
      delay(5000);
    }
  }
  if (!mqttClient.connected()) {
    Serial.println("[MQTT] Kunne ikke forbinde efter 5 forsøg");
  }
}

// ===================== SETUP =====================
void setup() {
  Serial.begin(115200);
  delay(200);

  Serial.println("========================================");
  Serial.println("[BOOT] MASTER starter");
  Serial.println("========================================");

  initWiFi();

  if (esp_now_init() != ESP_OK) {
    Serial.println("[ESP-NOW] Init fejlede!");
  } else {
    esp_now_register_recv_cb(onESPNowReceive);
    Serial.println("[ESP-NOW] Klar — lytter efter slaves");
  }

  tlsClient.setCACert(MQTT_CA_CERT);
  mqttClient.setServer(MQTT_HOST, MQTT_PORT);
  mqttClient.setBufferSize(512);

  espId();
  reconnectMQTT();

  configTime(0, 0, "pool.ntp.org");
  setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3", 1);
  tzset();
  delay(1500);
  Serial.println("[NTP] Tid synkroniseret");

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

  Serial.println("[SNIFFER] Kørende");
  Serial.println("========================================");
}

// ===================== LOOP =====================
void loop() {
  if (!mqttClient.connected()) {
    Serial.println("[MQTT] Forbindelse tabt — genopretter...");
    reconnectMQTT();
  }
  mqttClient.loop();

  DetectionEvent evt;
  while (dequeueEvent(&evt)) {
    if (evt.fromESPNow) {
      // Måling fra slave via ESP-NOW
      Serial.printf("[ESP-NOW] %s ser '%s' — RSSI: %d dBm  ~%.1f m\n",
        evt.espNowNode, evt.espNowDevice, evt.rssi, evt.distance);

      // Find ESP32-position fra secrets.h
      float nodeX = 0.0, nodeY = 0.0;
      for (int i = 0; i < 3; i++) {
        if (strcmp(evt.espNowNode, espNames[i]) == 0) {
          nodeX = espPositions[i][0];
          nodeY = espPositions[i][1];
          break;
        }
      }
      storeMeasurementAndCalculate(evt.espNowNode, nodeX, nodeY,
                                    evt.distance, evt.espNowDevice);

    } else if (evt.isKnown) {
      // Lokal måling fra master selv
      Serial.printf("[SNIFFER] Master ser '%s' — RSSI: %d dBm  ~%.1f m\n",
        knownNames[evt.knownIndex], evt.rssi, evt.distance);

      storeMeasurementAndCalculate(myName.c_str(), myX, myY,
                                    evt.distance, knownNames[evt.knownIndex]);
    }
  }

}