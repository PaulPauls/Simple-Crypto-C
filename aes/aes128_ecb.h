#ifndef AES128_ECB_H
#define AES128_ECB_H

#include <stdint.h> // uint8_t
#include <stddef.h> // size_t



int aes128_ecb_encrypt(const uint8_t *input, size_t inputSize,
	const uint8_t *key, size_t keySize, uint8_t *state, size_t stateSize);

int aes128_ecb_decrypt(const uint8_t *input, size_t inputSize,
	const uint8_t *key, size_t keySize, uint8_t *state, size_t stateSize);



#endif

