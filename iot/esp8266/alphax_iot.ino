#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <TinyGPS++.h>

// Configure these values before flashing the board.
const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
const char* BACKEND_URL = "https://alphax-backend-dexi.onrender.com/api/iot/data";
const char* DEVICE_ID = "ESP001";
const float VIBRATION_THRESHOLD = 0.50;
const int VIBRATION_PIN = A0;
TinyGPSPlus gps;

void setup() { Serial.begin(9600); WiFi.begin(WIFI_SSID, WIFI_PASSWORD); while (WiFi.status()!=WL_CONNECTED) delay(500); }
void loop() {
  while (Serial.available()) gps.encode(Serial.read());
  if (WiFi.status()==WL_CONNECTED && gps.location.isValid()) {
    float vibration = analogRead(VIBRATION_PIN) / 1023.0;
    WiFiClient client; HTTPClient http; http.begin(client, BACKEND_URL); http.addHeader("Content-Type", "application/json");
    String body = String("{\"device_id\":\"")+DEVICE_ID+"\",\"latitude\":"+String(gps.location.lat(),6)+",\"longitude\":"+String(gps.location.lng(),6)+",\"vibration\":"+String(vibration,3)+",\"online\":true}";
    http.POST(body); http.end();
  }
  delay(5000);
}
