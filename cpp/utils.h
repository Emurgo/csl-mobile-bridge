#include <inttypes.h>
#include <string>

extern "C" {
    #include "react_native_haskell_shelley.h"
}

#include "base64.h"

//the function converts a string from rust to c++ and frees the rust string
std::string charPtrToString(CharPtr* ptr) {
    std::string str = *ptr;
    charptr_free(ptr);
    return str;
}

std::string ptrToHexString(void* ptr) {
    std::string str(sizeof(void*) * 2, ' '); // Pre-size the string
    snprintf(&str[0], str.size() + 1, "%" PRIxPTR, reinterpret_cast<uintptr_t>(ptr));
    return str;
}

void* hexStringToPtr(const std::string& str) {
    uintptr_t ptrValue;
    if (sscanf(str.c_str(), "%" SCNxPTR, &ptrValue) != 1) {
        // Handle error: input string is not a valid hex format
        return nullptr;
    }
    return reinterpret_cast<void*>(ptrValue);
}

RPtr stringToRptr(const std::string &str) {
    RPtr ptr;
    ptr._0 = hexStringToPtr(str);
    return ptr;
}

std::string rptrToString(RPtr ptr) {
    return ptrToHexString(ptr._0);
}

//the function converts a data array from rust to base64 string and frees the rust data array
std::string dataPtrToBase64(DataPtr *ptr) {
    std::string base64Str = byteArrayToBase64(ptr->ptr, ptr->len);
    dataptr_free(ptr);
    return base64Str;
}

std::vector<uint8_t> base64ToBytes(const std::string& base64) {
    return base64ToByteArray(base64);
}

DataPtr bytesToDataPtr(const std::vector<uint8_t>& bytes) {
    DataPtr ptr;
    ptr.ptr = bytes.data();
    ptr.len = bytes.size();
    return ptr;
}

CharPtr stringToCharPtr(const std::string& str) {
    return str.c_str();
}


