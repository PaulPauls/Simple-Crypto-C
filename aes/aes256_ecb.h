#ifndef _AES256_ECB_H_
#define _AES256_ECB_H_

#include <stdint.h> // uint8_t
#include <stddef.h> // size_t



void aes256_ecb_encrypt(const uint8_t *input, size_t inputSize, const uint8_t *key, size_t keySize, uint8_t *state, size_t stateSize);

void aes256_ecb_decrypt(const uint8_t *input, size_t inputSize, const uint8_t *key, size_t keySize, uint8_t *state, size_t stateSize);



#endif

