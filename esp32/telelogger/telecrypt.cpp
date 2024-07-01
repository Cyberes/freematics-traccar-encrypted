#include "config.h"
#include <string.h>
#include <stdio.h>
#include <ChaChaPoly.h>
#include <HardwareSerial.h>
#include "Crypto.h"

void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        Serial.printf("%02x", data[i]);
    }
    Serial.println();
}

void encrypt_string(const unsigned char *input, size_t length, unsigned char *output) {
    ChaChaPoly chachaPoly;

    // Initialize the encryption key
    unsigned char key[32];
    for (int i = 0; i < 32; ++i) {
        sscanf(CHACHA20_KEY + 2*i, "%02x", &key[i]);
    }
    chachaPoly.setKey(key, sizeof(key));

    // Generate a random nonce (IV)
    unsigned char nonce[12];
    esp_fill_random(nonce, sizeof(nonce)); // Use the ESP-IDF random number generator
    chachaPoly.setIV(nonce, sizeof(nonce));

    // Encrypt the input data
    chachaPoly.encrypt(output + sizeof(nonce), input, length);

    // Compute the authentication tag
    chachaPoly.computeTag(output + sizeof(nonce) + length, chachaPoly.tagSize());

    // Prepend the nonce to the output
    memcpy(output, nonce, sizeof(nonce));

    chachaPoly.clear();
}

void decrypt_string(const unsigned char *input, size_t length, unsigned char *output) {
    ChaChaPoly chachaPoly;

    // Initialize the decryption key
    unsigned char key[32];
    for (int i = 0; i < 32; ++i) {
        sscanf(CHACHA20_KEY + 2*i, "%02x", &key[i]);
    }
    chachaPoly.setKey(key, sizeof(key));

    // Extract the nonce (IV) from the input
    unsigned char nonce[12];
    memcpy(nonce, input, sizeof(nonce));
    chachaPoly.setIV(nonce, sizeof(nonce));

    // Check that length is long enough to contain a nonce and a tag.
    if (length < sizeof(nonce) + chachaPoly.tagSize()) {
        Serial.print("[CHACHA] Input too short to contain nonce and tag: ");
        print_hex(input, length);
        output[0] = '\0'; // Set output to an empty string
        return;
    }

    // Decrypt the input data
    size_t decryptedLength = length - sizeof(nonce) - chachaPoly.tagSize();
    chachaPoly.decrypt(output, input + sizeof(nonce), decryptedLength);

    // String decryptedString = "";
    // for (size_t i = 0; i < decryptedLength; i++) {
    //     decryptedString += (char)output[i];
    // }
    // Serial.println(decryptedString);
    
    const unsigned char *tagPtr = input + sizeof(nonce) + decryptedLength; // actual tag
    uint8_t computedTag[16]; // computed tag
    chachaPoly.computeTag(computedTag, sizeof(computedTag));

    // Serial.print("Tag: ");
    // for (size_t i = 0; i < chachaPoly.tagSize(); i++) {
    //     Serial.print(tagPtr[i], HEX);
    //     Serial.print(" ");
    // }
    // Serial.println();
    // Serial.print("Computed Tag: ");
    // for (size_t i = 0; i < sizeof(computedTag); i++) {
    //     Serial.print(computedTag[i], HEX);
    //     Serial.print(" ");
    // }
    // Serial.println();

    ///// BEGIN TAG VERIFY
    // The crypto library implementation of tag verification crashes.

    // Can never match if the expected tag length is too long.
    if (chachaPoly.tagSize() > 16) {
        Serial.println("[CHACHA] Authentication failed: expected tag length is too long");
        output[0] = '\0'; // Set output to an empty string
        return;
    }

    // Compute the tag and check it.
    bool equal = secure_compare(computedTag, tagPtr, chachaPoly.tagSize());
    clean(computedTag);

    if (!equal) {
        Serial.println("[CHACHA] Authentication failed!");
        output[0] = '\0';
        return;
    }

    ///// END TAG VERIFY

    output[decryptedLength] = '\0';
    chachaPoly.clear();
}