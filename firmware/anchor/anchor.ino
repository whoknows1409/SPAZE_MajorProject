/*
 * SPAZE Anchor Firmware v3.0
 * ESP32-WROOM-32 BLE Scanner (Workstation Node)
 *
 * Scans for SPAZE badges, measures RSSI,
 * and outputs JSON over USB Serial for the Python agent.
 *
 * v2.0: also accepts PAKL badges (rolling token in manufacturer data,
 * company ID 0xFFFF, magic 0x5A) and forwards the token as "tok" (hex).
 * Legacy badges advertising the SPAZE service UUID are still reported.
 *
 * v3.1 (PAKL-CR): serial command
 *     CHAL <32 hex nonce> <delay_ms> [repeats]
 * writes the nonce to the badge over a BLE connection `repeats` times back to
 * back (default 3), times each notification with the microsecond timer, and
 * prints the FASTEST round trip:
 *     {"cr":1,"badge_mac":..,"n":nonce,"r":answer,"rtt":min_us,"k":repeats,
 *      "rtts":"us,us,us","d":delay,"a":attestation}
 * where attestation = HMAC-SHA256(ANCHOR_KEY, "AT"||nonce||answer||rtt_be32)[:16],
 * so the agent cannot alter the measured round-trip time. A genuine badge almost
 * always produces one fast exchange; a relay adds its latency to every exchange.
 *     SCAN OFF / SCAN ON   pause / resume scanning (calibration bench only)
 *
 * v3.2: the challenge target moves to a different device only when the current
 * badge has gone quiet or the new token counter is higher, so a replayed (older)
 * broadcast cannot pull the connection away from a present badge. A connection
 * to the wrong device, or one without the CR service, is dropped before
 * reconnecting, and after CR_MAX_CONNECT_FAILS failed connects in a row while
 * the target is still heard the anchor restarts (the Bluedroid client can stay
 * stuck after a half-open connection).
 */

#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEClient.h>
#include "mbedtls/md.h"
#include "esp_timer.h"

#if __has_include("anchor_secrets.h")
#include "anchor_secrets.h"
#define HAVE_ANCHOR_KEY 1
#else
#define HAVE_ANCHOR_KEY 0
#endif

// ===== Configuration =====
#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

#define SERVICE_UUID     "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CR_CHAR_UUID     "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define SCAN_DURATION    1    // BLE scan duration in seconds
#define ANCHOR_ID        "ANCHOR_WS_01"
#define TOKEN_LEN        20
#define TOKEN_MAGIC      0x5A
#define CR_NONCE_LEN     16
#define CR_TIMEOUT_MS    1000
#define CR_REPEATS       3     // exchanges per challenge; the fastest is reported
#define TARGET_STALE_MS  3000  // target not heard this long -> another device may take over
#define CR_MAX_CONNECT_FAILS 3

BLEScan *pBLEScan;
unsigned long scanCount = 0;
bool scanningEnabled = true;

// Last badge seen (target of challenge-response connections)
BLEAddress lastBadgeAddr("00:00:00:00:00:00");
esp_ble_addr_type_t lastBadgeType = BLE_ADDR_TYPE_PUBLIC;
uint32_t lastBadgeCtr = 0;
bool haveBadge = false;
unsigned long lastBadgeSeenMs = 0;
unsigned long lastConnectTryMs = 0;
int crConnectFails = 0;

// Challenge-response state
BLEClient *pClient = nullptr;
BLERemoteCharacteristic *pCrRemote = nullptr;
volatile bool crGot = false;
volatile int64_t crT1 = 0;
uint8_t crResp[8];
String serialLine = "";

static void toHex(const uint8_t *b, size_t n, char *out) {
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hexd[b[i] >> 4];
        out[2 * i + 1] = hexd[b[i] & 0x0F];
    }
    out[2 * n] = '\0';
}

static bool fromHex(const char *s, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char h[3] = {s[2 * i], s[2 * i + 1], 0};
        if (!isxdigit((unsigned char)h[0]) || !isxdigit((unsigned char)h[1])) return false;
        out[i] = (uint8_t)strtoul(h, nullptr, 16);
    }
    return true;
}

class BadgeDetectionCallback : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
        // PAKL badge: rolling token in manufacturer data
        String tokHex = "";
        bool haveCtr = false;
        uint32_t ctr = 0;
        if (advertisedDevice.haveManufacturerData()) {
            String md = advertisedDevice.getManufacturerData();
            const uint8_t *b = (const uint8_t *)md.c_str();
            if (md.length() == TOKEN_LEN && b[0] == 0xFF && b[1] == 0xFF && b[2] == TOKEN_MAGIC) {
                char buf[TOKEN_LEN * 2 + 1];
                toHex(b, TOKEN_LEN, buf);
                tokHex = String(buf);
                ctr = ((uint32_t)b[8] << 24) | ((uint32_t)b[9] << 16) | ((uint32_t)b[10] << 8) | b[11];
                haveCtr = true;
            }
        }
        // Legacy badge: SPAZE service UUID
        bool legacy = advertisedDevice.haveServiceUUID() &&
                      advertisedDevice.isAdvertisingService(BLEUUID(SERVICE_UUID));

        if (legacy || tokHex.length() > 0) {

            int rssi = advertisedDevice.getRSSI();
            String mac = advertisedDevice.getAddress().toString().c_str();
            String name = advertisedDevice.haveName() ?
                          advertisedDevice.getName().c_str() : "unknown";

            // Challenge target: a different device takes over only if the
            // current one has gone quiet or carries a newer token
            BLEAddress addr = advertisedDevice.getAddress();
            bool same = haveBadge && addr.equals(lastBadgeAddr);
            if (!haveBadge || same || millis() - lastBadgeSeenMs > TARGET_STALE_MS ||
                (haveCtr && ctr > lastBadgeCtr)) {
                lastBadgeAddr = addr;
                lastBadgeType = (esp_ble_addr_type_t)advertisedDevice.getAddressType();
                lastBadgeCtr = haveCtr ? ctr : 0;
                haveBadge = true;
                lastBadgeSeenMs = millis();
            }

            // Blink LED on detection
            digitalWrite(LED_BUILTIN, HIGH);

            // Output JSON line — the Python agent will parse this
            if (tokHex.length() > 0) {
                Serial.printf("{\"anchor\":\"%s\",\"badge_name\":\"%s\",\"badge_mac\":\"%s\",\"rssi\":%d,\"ts\":%lu,\"tok\":\"%s\"}\n",
                    ANCHOR_ID, name.c_str(), mac.c_str(), rssi, millis(), tokHex.c_str());
            } else {
                Serial.printf("{\"anchor\":\"%s\",\"badge_name\":\"%s\",\"badge_mac\":\"%s\",\"rssi\":%d,\"ts\":%lu}\n",
                    ANCHOR_ID, name.c_str(), mac.c_str(), rssi, millis());
            }

            digitalWrite(LED_BUILTIN, LOW);
        }
    }
};

class CrClientCallbacks : public BLEClientCallbacks {
    void onConnect(BLEClient *c) {}
    void onDisconnect(BLEClient *c) { pCrRemote = nullptr; }
};

static void crNotify(BLERemoteCharacteristic *ch, uint8_t *data, size_t len, bool isNotify) {
    int64_t t = esp_timer_get_time();   // timestamp first
    if (len >= 8 && !crGot) {
        memcpy(crResp, data, 8);
        crT1 = t;
        crGot = true;
    }
}

static bool ensureConnected() {
    if (pClient != nullptr && pClient->isConnected() && pCrRemote != nullptr &&
        pClient->getPeerAddress().equals(lastBadgeAddr)) return true;
    if (!haveBadge) return false;
    if (pClient == nullptr) {
        pClient = BLEDevice::createClient();
        pClient->setClientCallbacks(new CrClientCallbacks());
    }
    if (pClient->isConnected()) {
        // Connected to a former target or without the CR service: start clean
        pCrRemote = nullptr;
        pClient->disconnect();
        unsigned long t = millis();
        while (pClient->isConnected() && millis() - t < 1000) delay(10);
        if (pClient->isConnected()) return false;
    }
    if (!pClient->connect(lastBadgeAddr, lastBadgeType, 3000)) return false;
    BLERemoteService *svc = pClient->getService(SERVICE_UUID);
    if (svc == nullptr) { pClient->disconnect(); return false; }
    BLERemoteCharacteristic *ch = svc->getCharacteristic(CR_CHAR_UUID);
    if (ch == nullptr || !ch->canNotify()) { pClient->disconnect(); return false; }
    ch->registerForNotify(crNotify);
    // Shortest connection interval (7.5 ms) for a tight RTT distribution
    pClient->updateConnParams(6, 6, 0, 200);
    delay(300);  // let the parameter update complete
    pCrRemote = ch;
    return true;
}

// Called after every failed connect. Restarting is the only reliable way out
// of a stuck Bluedroid client; only done while the target is still heard,
// so a badge that simply left does not cause restarts.
static void noteConnectResult(bool ok) {
    if (ok) {
        crConnectFails = 0;
        return;
    }
    crConnectFails++;
    if (crConnectFails >= CR_MAX_CONNECT_FAILS && millis() - lastBadgeSeenMs < 1500) {
        Serial.printf("[Anchor] %d challenge connects failed in a row - restarting\n", crConnectFails);
        Serial.flush();
        ESP.restart();
    }
}

static void crFail(const char *nonceHex, const char *err) {
    Serial.printf("{\"cr\":0,\"n\":\"%s\",\"err\":\"%s\"}\n", nonceHex, err);
}

static void doChallenge(const char *nonceHex, int delayMs, int repeats) {
#if !HAVE_ANCHOR_KEY
    crFail(nonceHex, "no_anchor_key");
    return;
#else
    uint8_t nonce[CR_NONCE_LEN];
    if (strlen(nonceHex) != 2 * CR_NONCE_LEN || !fromHex(nonceHex, nonce, CR_NONCE_LEN)) {
        crFail(nonceHex, "bad_nonce");
        return;
    }
    if (!ensureConnected()) {
        crFail(nonceHex, "connect");      // answer the agent before a possible restart
        noteConnectResult(false);
        return;
    }
    noteConnectResult(true);
    uint8_t payload[CR_NONCE_LEN + 1];
    memcpy(payload, nonce, CR_NONCE_LEN);
    payload[CR_NONCE_LEN] = (uint8_t)constrain(delayMs, 0, 255);

    repeats = constrain(repeats, 1, 5);
    uint32_t rtt = 0xFFFFFFFF;
    char rttList[64] = {0};
    size_t used = 0;
    for (int i = 0; i < repeats; i++) {
        crGot = false;
        int64_t t0 = esp_timer_get_time();
        pCrRemote->writeValue(payload, sizeof(payload), false);   // write without response
        while (!crGot && (esp_timer_get_time() - t0) < (int64_t)CR_TIMEOUT_MS * 1000) {
            delay(1);
        }
        if (!crGot) {
            crFail(nonceHex, "timeout");
            return;
        }
        uint32_t one = (uint32_t)(crT1 - t0);
        if (one < rtt) rtt = one;
        used += snprintf(rttList + used, sizeof(rttList) - used, i ? ",%lu" : "%lu", (unsigned long)one);
    }

    // Attestation over nonce || answer || rtt (big endian)
    uint8_t msg[2 + CR_NONCE_LEN + 8 + 4];
    msg[0] = 'A'; msg[1] = 'T';
    memcpy(msg + 2, nonce, CR_NONCE_LEN);
    memcpy(msg + 2 + CR_NONCE_LEN, crResp, 8);
    msg[2 + CR_NONCE_LEN + 8] = (rtt >> 24) & 0xFF;
    msg[2 + CR_NONCE_LEN + 9] = (rtt >> 16) & 0xFF;
    msg[2 + CR_NONCE_LEN + 10] = (rtt >> 8) & 0xFF;
    msg[2 + CR_NONCE_LEN + 11] = rtt & 0xFF;
    uint8_t mac[32];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    ANCHOR_KEY, sizeof(ANCHOR_KEY), msg, sizeof(msg), mac);

    char respHex[17], attHex[33];
    toHex(crResp, 8, respHex);
    toHex(mac, 16, attHex);
    Serial.printf("{\"cr\":1,\"badge_mac\":\"%s\",\"n\":\"%s\",\"r\":\"%s\",\"rtt\":%lu,\"k\":%d,\"rtts\":\"%s\",\"d\":%d,\"a\":\"%s\"}\n",
                  lastBadgeAddr.toString().c_str(), nonceHex, respHex, (unsigned long)rtt,
                  repeats, rttList, (int)payload[CR_NONCE_LEN], attHex);
#endif
}

static void handleSerial() {
    while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\n' || c == '\r') {
            if (serialLine.length() > 0) {
                if (serialLine.startsWith("CHAL ")) {
                    char nonceHex[2 * CR_NONCE_LEN + 1] = {0};
                    int delayMs = 0, repeats = CR_REPEATS;
                    sscanf(serialLine.c_str() + 5, "%32s %d %d", nonceHex, &delayMs, &repeats);
                    doChallenge(nonceHex, delayMs, repeats);
                } else if (serialLine == "SCAN OFF") {
                    scanningEnabled = false;
                } else if (serialLine == "SCAN ON") {
                    scanningEnabled = true;
                }
                serialLine = "";
            }
        } else if (serialLine.length() < 96) {
            serialLine += c;
        }
    }
}

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("============================");
    Serial.println("  SPAZE Anchor v3.2");
    Serial.println("============================");
    Serial.printf("Anchor ID: %s\n", ANCHOR_ID);
    Serial.printf("Scan Duration: %ds\n", SCAN_DURATION);
    Serial.printf("Challenge-response: %s\n", HAVE_ANCHOR_KEY ? "enabled" : "disabled (no anchor_secrets.h)");
    Serial.println();

    pinMode(LED_BUILTIN, OUTPUT);

    BLEDevice::init("SZ-Anchor");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new BadgeDetectionCallback());
    pBLEScan->setActiveScan(true);   // Active scan gets device name & scan response
    pBLEScan->setInterval(100);      // Scan interval in 0.625ms units
    pBLEScan->setWindow(99);         // Scan window (nearly continuous)

    Serial.println(">> Scanning for SPAZE badges...");
    Serial.println();
}

void loop() {
    handleSerial();

    if (!scanningEnabled) {
        delay(2);
        return;
    }

    // Run BLE scan
    BLEScanResults *results = pBLEScan->start(SCAN_DURATION, false);

    int found = results->getCount();
    scanCount++;

    // Print scan summary every 10 scans if no badges found
    if (found == 0 && scanCount % 10 == 0) {
        Serial.printf("[Anchor] Scan #%lu — no badges in range\n", scanCount);
    }

    pBLEScan->clearResults();  // Free memory
    handleSerial();

#if HAVE_ANCHOR_KEY
    // Keep a connection to a badge heard recently, so challenges are answered quickly
    bool connected = (pClient != nullptr && pClient->isConnected() && pCrRemote != nullptr);
    if (!connected && haveBadge && millis() - lastBadgeSeenMs < 2000 &&
        millis() - lastConnectTryMs > 5000) {
        lastConnectTryMs = millis();
        noteConnectResult(ensureConnected());
    }
#endif
    delay(100);  // Small gap between scans
}
