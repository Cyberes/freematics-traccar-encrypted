#include "config.h"
#include <string.h>
#include <stdio.h>
#include <ChaChaPoly.h>
#include <HardwareSerial.h>

void encrypt_string(const unsigned char *input, size_t length, unsigned char *output);
void decrypt_string(const unsigned char *input, size_t length, unsigned char *output);
void print_hex(const unsigned char *data, size_t length);