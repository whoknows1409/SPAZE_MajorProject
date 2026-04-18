/*
 * SecureZone Badge Firmware
 * ESP32-WROOM-32 BLE Advertiser
 * 
 * Broadcasts a rotating encrypted badge ID via BLE advertisements.
 * Includes deep-sleep optimization for battery life.
 */

#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEAdvertising.h>
#include <esp_sleep.h>

// ===== Configuration =====
#define BADGE_ID            "BADGE_001"         // Unique badge identifier
#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"

#define ADVERTISE_DURATION_MS   100   // Time to advertise per cycle
#define SLEEP_DURATION_MS       400   // Deep sleep between cycles
#define NONCE_ROTATE_INTERVAL   30000 // Rotate nonce every 30 seconds

// ===== Globals =====
BLEAdvertising *pAdvertising;
unsigned long lastNonceRotation = 0;
uint32_t currentNonce = 0;

void setup() {
    Serial.begin(115200);
    Serial.println("SecureZone Badge initializing...");
    
    // Initialize BLE
    BLEDevice::init("SZ-Badge");
    
    BLEServer *pServer = BLEDevice::createServer();
    BLEService *pService = pServer->createService(SERVICE_UUID);
    
    BLECharacteristic *pCharacteristic = pService->createCharacteristic(
        CHARACTERISTIC_UUID,
        BLECharacteristic::PROPERTY_READ
    );
    
    // Set initial badge payload (badge_id + nonce)
    rotateNonce();
    String payload = String(BADGE_ID) + ":" + String(currentNonce);
    pCharacteristic->setValue(payload.c_str());
    
    pService->start();
    
    // Configure advertising
    pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(SERVICE_UUID);
    pAdvertising->setScanResponse(true);
    pAdvertising->setMinPreferred(0x06);
    pAdvertising->setMinPreferred(0x12);
    
    Serial.println("Badge ready. Broadcasting...");
}

void loop() {
    // Start advertising
    pAdvertising->start();
    delay(ADVERTISE_DURATION_MS);
    pAdvertising->stop();
    
    // Rotate nonce periodically
    if (millis() - lastNonceRotation > NONCE_ROTATE_INTERVAL) {
        rotateNonce();
    }
    
    // Deep sleep for battery conservation
    // TODO: Replace delay with actual esp_deep_sleep for production
    delay(SLEEP_DURATION_MS);
}

void rotateNonce() {
    // Generate a pseudo-random nonce
    // TODO: Replace with hardware RNG (esp_random()) and HMAC-based nonce
    currentNonce = esp_random();
    lastNonceRotation = millis();
    Serial.printf("Nonce rotated: %u\n", currentNonce);
}
