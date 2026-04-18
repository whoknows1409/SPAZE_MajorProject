/*
 * SecureZone Anchor Firmware
 * ESP32-WROOM-32 BLE Scanner (Workstation / Door Node)
 * 
 * Scans for SecureZone badges and reports proximity data
 * via Serial (workstation) or MQTT (door anchor).
 */

#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

// ===== Configuration =====
#define SERVICE_UUID     "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define SCAN_DURATION    1    // BLE scan duration in seconds
#define SCAN_INTERVAL_MS 500  // Time between scans
#define RSSI_THRESHOLD   -65  // ~2 meter range (calibrate per environment)

// ===== Anchor Type =====
// Set to true for door anchors, false for workstation anchors
#define IS_DOOR_ANCHOR   false
#define ANCHOR_ID        "ANCHOR_001"

BLEScan *pBLEScan;

class BadgeDetectionCallback : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
        // Check if this is a SecureZone badge
        if (advertisedDevice.haveServiceUUID() && 
            advertisedDevice.isAdvertisingService(BLEUUID(SERVICE_UUID))) {
            
            int rssi = advertisedDevice.getRSSI();
            String address = advertisedDevice.getAddress().toString().c_str();
            
            // Output as JSON for the host agent to parse
            Serial.printf("{\"anchor\":\"%s\",\"badge_mac\":\"%s\",\"rssi\":%d,\"in_range\":%s,\"is_door\":%s}\n",
                ANCHOR_ID,
                address.c_str(),
                rssi,
                rssi >= RSSI_THRESHOLD ? "true" : "false",
                IS_DOOR_ANCHOR ? "true" : "false"
            );
        }
    }
};

void setup() {
    Serial.begin(115200);
    Serial.printf("SecureZone Anchor [%s] initializing...\n", ANCHOR_ID);
    Serial.printf("Type: %s | RSSI Threshold: %d dBm\n", 
        IS_DOOR_ANCHOR ? "DOOR" : "WORKSTATION", RSSI_THRESHOLD);
    
    BLEDevice::init("SZ-Anchor");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new BadgeDetectionCallback());
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(100);
    pBLEScan->setWindow(99);
    
    Serial.println("Anchor ready. Scanning for badges...");
}

void loop() {
    pBLEScan->start(SCAN_DURATION, false);
    pBLEScan->clearResults();
    delay(SCAN_INTERVAL_MS);
}
