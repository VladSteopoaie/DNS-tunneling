#ifndef ENCODERS_H
#define ENCODERS_H

#include <iostream>
#include <string>
#include <bitset>
#include <vector>

std::string base32_decode(const std::string &input);
std::string base32_encode(const std::string &input);
std::string base64_encode(const std::string &input);
std::string base64_decode(const std::string &input);

#endif