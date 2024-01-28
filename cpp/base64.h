#pragma once
#include <string>
#include <vector>
#include <array>

// Base64 Characters
static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

// Base64 Lookup Table for Decoding
static const std::array<uint8_t, 256> base64_lookup = [] {
    std::array<uint8_t, 256> lookup{};
    lookup.fill(255); // Mark non-Base64 characters as 255
    for (int i = 0; i < 64; i++) {
        lookup[static_cast<uint8_t>(base64_chars[i])] = i;
    }
    return lookup;
}();

// Function to Encode ByteArray to Base64
std::string byteArrayToBase64(const unsigned char* buf, unsigned int bufLen) {
    std::string base64;
    base64.reserve((bufLen + 2) / 3 * 4); // Pre-allocate memory

    for (unsigned int i = 0; i < bufLen; ) {
        unsigned char char_array_3[3] = {0, 0, 0};
        unsigned char char_array_4[4];

        int len = 0;
        for (len = 0; len < 3 && i < bufLen; ++len, ++i) {
            char_array_3[len] = buf[i];
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (int j = 0; j < len + 1; ++j) {
            base64 += base64_chars[char_array_4[j]];
        }

        for (; len < 3; ++len) {
            base64 += '=';
        }
    }

    return base64;
}

// Function to Decode Base64 to ByteArray
std::vector<uint8_t> base64ToByteArray(const std::string& base64) {
    std::vector<uint8_t> ret;
    ret.reserve(base64.size() * 3 / 4); // Pre-allocate memory

    unsigned char char_array_4[4], char_array_3[3];
    int i = 0, in_ = 0;

    while (base64[in_] != '=' && in_ < base64.size()) {
        char_array_4[i++] = base64_lookup[base64[in_++]];
        if (i == 4) {
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++) ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i > 0) {
        for (int j = i; j < 4; j++) char_array_4[j] = 0;

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        if (i > 1) char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        if (i > 2) char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (int j = 0; j < i - 1; j++) ret.push_back(char_array_3[j]);
    }

    return ret;
}

///tests

#include <iostream>
#include <vector>
#include <string>

bool compareByteArrays(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

std::string testEncodeDecode() {
    const std::string original = "Hello, World!";
    const std::string encoded = byteArrayToBase64(reinterpret_cast<const unsigned char*>(original.data()), original.size());
    const std::vector<uint8_t> decoded = base64ToByteArray(encoded);

    std::string decodedString(decoded.begin(), decoded.end());
    return (original == decodedString) ? "testEncodeDecode: Passed\n" : "testEncodeDecode: Failed\n";
}

std::string testEmptyString() {
    const std::string original = "";
    const std::string encoded = byteArrayToBase64(reinterpret_cast<const unsigned char*>(original.data()), original.size());
    const std::vector<uint8_t> decoded = base64ToByteArray(encoded);

    std::string decodedString(decoded.begin(), decoded.end());
    return (original == decodedString) ? "testEmptyString: Passed\n" : "testEmptyString: Failed\n";
}

std::string testBinaryData() {
    const std::vector<uint8_t> original = {0x00, 0x01, 0x02, 0x03, 0x04, 0xFF};
    const std::string encoded = byteArrayToBase64(original.data(), original.size());
    const std::vector<uint8_t> decoded = base64ToByteArray(encoded);

    return (compareByteArrays(original, decoded)) ? "testBinaryData: Passed\n" : "testBinaryData: Failed\n";
}

std::string testLargeData() {
    std::string original(10000, 'x');
    const std::string encoded = byteArrayToBase64(reinterpret_cast<const unsigned char*>(original.data()), original.size());
    const std::vector<uint8_t> decoded = base64ToByteArray(encoded);

    std::string decodedString(decoded.begin(), decoded.end());
    return (original == decodedString) ? "testLargeData: Passed\n" : "testLargeData: Failed\n";
}

std::string testNonAlphanumericCharacters() {
    const std::string original = "!@#$%^&*()_+-=[]{}|;':,./<>?";
    const std::string encoded = byteArrayToBase64(reinterpret_cast<const unsigned char*>(original.data()), original.size());
    const std::vector<uint8_t> decoded = base64ToByteArray(encoded);

    std::string decodedString(decoded.begin(), decoded.end());
    return (original == decodedString) ? "testNonAlphanumericCharacters: Passed\n" : "testNonAlphanumericCharacters: Failed\n";
}

// std::string testUnicodeCharacters() {
//     const std::string original = u8"こんにちは"; // Japanese for "Hello"
//     const std::string encoded = byteArrayToBase64(reinterpret_cast<const unsigned char*>(original.data()), original.size());
//     const std::vector<uint8_t> decoded = base64ToByteArray(encoded);
//
//     std::string decodedString(decoded.begin(), decoded.end());
//     return (original == decodedString) ? "testUnicodeCharacters: Passed\n" : "testUnicodeCharacters: Failed\n";
// }

std::string testSingleByteData() {
    const std::vector<uint8_t> original = {0x7F}; // Single byte data
    const std::string encoded = byteArrayToBase64(original.data(), original.size());
    const std::vector<uint8_t> decoded = base64ToByteArray(encoded);

    return (compareByteArrays(original, decoded)) ? "testSingleByteData: Passed\n" : "testSingleByteData: Failed\n";
}

std::string testIncompleteBase64() {
    const std::string incompleteBase64 = "SGVsbG8"; // "Hello" without proper padding
    const std::vector<uint8_t> decoded = base64ToByteArray(incompleteBase64);
    const std::string expectedDecoded = "Hello";

    std::string decodedString(decoded.begin(), decoded.end());
    return (decodedString == expectedDecoded) ? "testIncompleteBase64: Passed\n" : "testIncompleteBase64: Failed\n";
}


std::string testsss() {
    std::cout << "Onload" << std::endl;
    std::string result;

    result += testEncodeDecode();
    result += testEmptyString();
    result += testBinaryData();
    result += testLargeData();
    result += testNonAlphanumericCharacters();
//     result += testUnicodeCharacters();
    result += testSingleByteData();
    result += testIncompleteBase64();

    return result;
}
