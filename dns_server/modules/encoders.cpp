/*################################*/
/*---------[ Disclaimer ]---------*/
/*################################*/

/**
 * This script is generated with ChatGPT for demonstration purposes.
 * In case you want to use them, make sure to have a look on the code!
 */

#include "encoders.h"

const std::string base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string base32_decode(const std::string &input) {
    std::string output;
    int bits = 0;
    int value = 0;

    for (const auto &c : input) {
        if (c == '=') {
            break;
        }

        int index = base32_chars.find(c);
        if (index == std::string::npos) {
            continue;
        }

        value = (value << 5) + index;
        bits += 5;

        if (bits >= 8) {
            output += static_cast<char>((value >> (bits - 8)) & 255);
            bits -= 8;
        }
    }

    return output;
}

std::string base32_encode(const std::string &input) {
    std::string output;
    int bits = 0;
    int value = 0;

    for (const auto &c : input) {
        value = (value << 8) + static_cast<unsigned char>(c);
        bits += 8;

        while (bits >= 5) {
            output += base32_chars[(value >> (bits - 5)) & 31];
            bits -= 5;
        }
    }

    if (bits > 0) {
        output += base32_chars[(value << (5 - bits)) & 31];
    }

    while (output.size() % 8 != 0) {
        output += '=';
    }

    return output;
}


std::string base64_encode(const std::string &input) {
    std::string encoded_string;
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded_string.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        encoded_string.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (encoded_string.size() % 4) {
        encoded_string.push_back('=');
    }
    return encoded_string;
}


std::string base64_decode(const std::string &input) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    std::string decoded_string;
    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            decoded_string.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded_string;
}