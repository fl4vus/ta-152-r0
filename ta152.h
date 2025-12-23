#ifndef TA152_H
#define TA152_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

//uint8_t ta152_round(uint8_t key, uint8_t *base_mx, uint8_t *inverse_mx);

uint8_t ta152_encrypt_chunk(uint8_t input_chunk, uint8_t key_byte, uint8_t *base_mx, uint8_t *inverse_mx);

uint8_t ta152_decrypt_chunk(uint8_t input_chunk, uint8_t key_byte, uint8_t *base_mx, uint8_t *inverse_mx);

int ta152_encrypt(const char *in_path, const char *key_file);

int ta152_decrypt(const char *in_path, const char *key_file);

#endif