/*
 * SecureZone Anchor Firmware v1.0
 * ESP32-WROOM-32 BLE Scanner (Workstation Node)
 * 
 * Scans for SecureZone badges, measures RSSI,
 * and outputs JSON over USB Serial for the Python agent.
 */

#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

// ===== Configuration =====
#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

#define SERVICE_UUID     "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define SCAN_DURATION    1    // BLE scan duration in seconds
#define ANCHOR_ID        "ANCHOR_WS_01"

BLEScan *pBLEScan;
unsigned long scanCount = 0;

class BadgeDetectionCallback : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
        // Only process SecureZone badges (filter by service UUID)
        if (advertisedDevice.haveServiceUUID() && 
            advertisedDevice.isAdvertisingService(BLEUUID(SERVICE_UUID))) {
            
            int rssi = advertisedDevice.getRSSI();
            String mac = advertisedDevice.getAddress().toString().c_str();
            String name = advertisedDevice.haveName() ? 
                          advertisedDevice.getName().c_str() : "unknown";
            
            // Blink LED on detection
            digitalWrite(LED_BUILTIN, HIGH);
            
            // Output JSON line — the Python agent will parse this
            Serial.printf("{\"anchor\":\"%s\",\"badge_name\":\"%s\",\"badge_mac\":\"%s\",\"rssi\":%d,\"ts\":%lu}\n",
                ANCHOR_ID,
                name.c_str(),
                mac.c_str(),
                rssi,
                millis()
            );
            
            digitalWrite(LED_BUILTIN, LOW);
        }
    }
};

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("============================");
    Serial.println("  SecureZone Anchor v1.0");
    Serial.println("============================");
    Serial.printf("Anchor ID: %s\n", ANCHOR_ID);
    Serial.printf("Scan Duration: %ds\n", SCAN_DURATION);
    Serial.printf("Looking for Service UUID: %s\n", SERVICE_UUID);
    Serial.println();
    
    pinMode(LED_BUILTIN, OUTPUT);
    
    BLEDevice::init("SZ-Anchor");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new BadgeDetectionCallback());
    pBLEScan->setActiveScan(true);   // Active scan gets device name & scan response
    pBLEScan->setInterval(100);      // Scan interval in 0.625ms units
    pBLEScan->setWindow(99);         // Scan window (nearly continuous)
    
    Serial.println(">> Scanning for SecureZone badges...");
    Serial.println(">> LED blinks on each badge detection.");
    Serial.println();
}

void loop() {
    // Run BLE scan
    BLEScanResults *results = pBLEScan->start(SCAN_DURATION, false);
    
    int found = results->getCount();
    scanCount++;
    
    // Print scan summary every 10 scans if no badges found
    if (found == 0 && scanCount % 10 == 0) {
        Serial.printf("[Anchor] Scan #%lu — no badges in range\n", scanCount);
    }
    
    pBLEScan->clearResults();  // Free memory
    delay(100);  // Small gap between scans
}
