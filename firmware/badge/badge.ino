/*
 * SPAZE Badge Firmware v1.0
 * ESP32-WROOM-32 BLE Advertiser
 * 
 * Broadcasts BLE advertisements containing badge ID.
 * The anchor node picks these up and measures RSSI.
 * 
 * Phase 1: Simple continuous advertising (no deep sleep yet).
 */

#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEAdvertising.h>

// ===== Configuration =====
#ifndef LED_BUILTIN
#define LED_BUILTIN 2   // GPIO 2 = built-in LED on most ESP32 DevKits
#endif
#define DEVICE_NAME         "SZ-BADGE-001"
#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define BADGE_ID            "BADGE_001"

// Advertising interval: lower = faster detection, higher = less power
// 100ms (0x00A0) is a good balance for proximity detection
#define ADV_INTERVAL_MIN    0x00A0   // 100ms in 0.625ms units
#define ADV_INTERVAL_MAX    0x00A0   // 100ms

// ===== Globals =====
BLEAdvertising *pAdvertising;
uint32_t bootCount = 0;

void setup() {
    Serial.begin(115200);
    delay(1000);  // Give serial time to connect
    
    Serial.println("============================");
    Serial.println("  SPAZE Badge v1.0");
    Serial.println("============================");
    Serial.printf("Badge ID: %s\n", BADGE_ID);
    Serial.printf("Device Name: %s\n", DEVICE_NAME);
    Serial.println();
    
    // Initialize BLE
    BLEDevice::init(DEVICE_NAME);
    
    // Set transmit power (default ESP_PWR_LVL_P3 = +3dBm)
    // Keep default for now — we'll calibrate in testing
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P3);
    
    // Configure advertising
    pAdvertising = BLEDevice::getAdvertising();
    
    // Add service UUID so the anchor can filter for our badges
    pAdvertising->addServiceUUID(SERVICE_UUID);
    
    // Enable scan response to include device name
    pAdvertising->setScanResponse(true);
    
    // Set advertising interval
    pAdvertising->setMinPreferred(ADV_INTERVAL_MIN);
    pAdvertising->setMaxPreferred(ADV_INTERVAL_MAX);
    
    // Include TX power in advertisement (helps with distance estimation)
    BLEAdvertisementData advData;
    advData.setFlags(ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT);
    advData.setCompleteServices(BLEUUID(SERVICE_UUID));
    advData.setName(DEVICE_NAME);
    pAdvertising->setAdvertisementData(advData);
    
    // Start advertising (runs continuously)
    pAdvertising->start();
    
    Serial.println(">> BLE Advertising started!");
    Serial.println(">> Anchor should now detect this badge.");
    Serial.println(">> LED will blink every 2s to confirm running.");
    Serial.println();
    
    // Use built-in LED as heartbeat indicator
    pinMode(LED_BUILTIN, OUTPUT);
}

void loop() {
    // Heartbeat blink — confirms badge is running
    digitalWrite(LED_BUILTIN, HIGH);
    delay(100);
    digitalWrite(LED_BUILTIN, LOW);
    delay(1900);
    
    // Print status every 10 seconds
    bootCount++;
    if (bootCount % 5 == 0) {
        Serial.printf("[Badge] Running... uptime: %lus | Advertising: %s\n", 
                      millis() / 1000, DEVICE_NAME);
    }
}
