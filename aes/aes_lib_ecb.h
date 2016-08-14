#ifndef AES_LIB_ECB_H
#define AES_LIB_ECB_H

#include <stdint.h> // uint8_t
#include <stddef.h> // size_t



void add_round_key(uint8_t *state, const uint8_t *expandedKey, int round);

void sub_bytes(uint8_t *state, const uint8_t *sbox);

void shift_row(uint8_t *state);

void inv_shift_row(uint8_t *state);

void mix_columns(uint8_t *state, const uint8_t *mixMultMatrix);

uint8_t galois_mul(uint8_t a, uint8_t b);



#endif

