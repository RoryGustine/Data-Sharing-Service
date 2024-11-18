#ifndef DATA_SHARE_H
#define DATA_SHARE_H

#include <stdint.h>
#include <stdbool.h>

uint8_t sendNewBlock(const char *ID, const uint8_t *secret, uint32_t data_length, const void *data);

uint8_t updateBlock(const char *ID, const uint8_t *secret, const void *new_data, uint32_t new_data_length, uint32_t start_position);

uint8_t getBlock(const char *ID, const uint8_t *secret, uint32_t buffer_size, void *buffer, uint32_t start_position, uint32_t length);

uint8_t updateAccess(const char *ID, const uint8_t *secret, const uint8_t *new_secret, int permissions);

bool checkDataValid(const char *ID, const uint8_t *secret);

#endif
