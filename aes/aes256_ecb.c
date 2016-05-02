#include <stdint.h> // uint8_t
#include <stddef.h> // size_t
#include <stdio.h>  // fprintf()
#include <stdlib.h> // EXIT_FAILURE



void aes256_ecb_encrypt(const uint8_t *input, size_t inputSize,
	const uint8_t *key, size_t keySize, uint8_t *state, size_t stateSize);
void aes256_ecb_decrypt(const uint8_t *input, size_t inputSize,
	const uint8_t *key, size_t keySize, uint8_t *state, size_t stateSize);

void copy_block(const uint8_t *input, size_t inputSize, uint8_t *state);
void key_expansion(const uint8_t *key, uint8_t *expandedKey, const uint8_t *sbox);
void add_round_key(uint8_t *state, const uint8_t *expandedKey, int round);
void sub_bytes(uint8_t *state, const uint8_t *sbox);
void shift_row(uint8_t *state);
void mix_columns(uint8_t *state, const uint8_t *mixMultMatrix);
uint8_t galois_mul(uint8_t a, uint8_t b);



// ########################
// ### Public Functions ###
// ########################



/* Encrypts input with key to output with AES256 in ECB Mode
 *
 * Input:
 *	const uint8_t *input	byte-array of arbitrary content to encrypt
 * 	size_t inputSize	size of input in bytes. Arbitrary.
 *	const uint8_t *key	byte-array of key, can be arbitrary
 *	size_t keySize		size of key in bytes. Has to be 32byte/256bit
 *	uint8_t *state		byte-array of result, will be overwritten
 *	size_t stateSize	size of result in bytes, has to a multiplicity
 *				of 16bytes and larger than the size of input
 *
 * Output: Saves the with key encrypted input to state
 *
 * Process:
 *	[1] check for correct parameters
 *	[2] define arrays specific to the AES algorithm
 *	[3] expand the key according to AES specification
 *	[4] copy the input to the state as AES can be applied in memory and
 *		the input array should not be changed
 *	[5] Apply the 14 rounds of the AES core algorithm to the state
 */
void aes256_ecb_encrypt(const uint8_t *input, size_t inputSize,
	const uint8_t *key, size_t keySize, uint8_t *state, size_t stateSize)
{
	if (keySize != 32 || inputSize > stateSize || stateSize % 16 != 0) {
		perror("aes256_ecb_encrypt(...) was called with one of the following errors:\n \
			\t Size of key was not 256 bit\n \
			\t OR inputarray was larger than the resultarray\n \
			\t OR the size of the resultarray was not a multiplicity of 16 bytes\n");

		exit(EXIT_FAILURE);
	}


	uint8_t sbox[] = {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};
	uint8_t mixMultMatrix[]	= {0x02, 0x03, 0x01, 0x01,
		0x01, 0x02, 0x03, 0x01,
		0x01, 0x01, 0x02, 0x03,
		0x03, 0x01, 0x01, 0x02};
	uint8_t expandedKey[240]; // 240 = 16 * 15 = blocksize * (NrOfRounds+1)

	// AES can be applied in-memory, however as we deliver a seperate
	// outputcipher we first have to copy the input to the output to leave the
	// input unchanged
	copy_block(input, inputSize, state);

	// Expand Key
	key_expansion(key, expandedKey, sbox);

	//Execute Algorithm for every 16 Bytes of the state
	for (int stateOffset = 0; stateOffset < stateSize; stateOffset += 16) {
    		// initialRound
		add_round_key(&state[stateOffset], expandedKey, 0);

		// middleRounds
		for (int round = 1; round < 14; round++) {
			sub_bytes(&state[stateOffset], sbox);
			shift_row(&state[stateOffset]);
			mix_columns(&state[stateOffset], mixMultMatrix);
			add_round_key(&state[stateOffset], expandedKey, round);
		}

    		// lastRound
		sub_bytes(&state[stateOffset], sbox);
		shift_row(&state[stateOffset]);
		add_round_key(&state[stateOffset], expandedKey, 14);
	}
}



void aes256_ecb_decrypt(const uint8_t *input, size_t inputSize,
	const uint8_t *key, size_t keySize, uint8_t *state, size_t stateSize)
{

}



// #########################
// ### Private Functions ###
// #########################



/* Copies all bytes of input in order to the state, which size has to be bigger
 * than the size of the input
 */
void copy_block(const uint8_t *input, size_t inputSize, uint8_t *state)
{
	for (int i = 0; i < inputSize; i++) {
		state[i] = input[i];
	}
}



/* Input: const uint8_t *key	byte-array with original 256bit key
 *		  uint8_t *expandedKey	arbitrary byte-array with 240 bytes
 *		  const uint8_t *sbox	byte-array AES sbox
 *
 * Output: expands the key to the 240 key values according to AES specification
 */
void key_expansion(const uint8_t *key, uint8_t *expandedKey, const uint8_t *sbox)
{
	uint8_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};
	int round;

	// First Copy the given key into the expandedKey as a basis to start expanding on
	for (round = 0; round < (32 / 4); round++) {
		expandedKey[(4 * round) + 0] = key[(4 * round) + 0];
		expandedKey[(4 * round) + 1] = key[(4 * round) + 1];
		expandedKey[(4 * round) + 2] = key[(4 * round) + 2];
		expandedKey[(4 * round) + 3] = key[(4 * round) + 3];
	}

	// Now walk through the generation of the remaining bytes of the expandedKey
	for (round = 8; round < (240 / 4); round++) {
		if (round % 4 == 0) {
			if (round % 8 == 0) {
				// RoundKey =
				// sub_word(rot_word(expanded_key(round - 1) * 4)))
				// XOR rcon((round / 8) - 1)
				// XOR expanded_key((round - 8) * 4)
				expandedKey[(4 * round) + 0] =
					sbox[expandedKey[(4 * (round - 1)) + 1]]
					^ rcon[(round / 8) - 1]
					^ expandedKey[(4 * (round - 8)) + 0];
				expandedKey[(4 * round) + 1] =
					sbox[expandedKey[(4 * (round - 1)) + 2]]
					^ 0x00
					^ expandedKey[(4 * (round - 8)) + 1];
				expandedKey[(4 * round) + 2] =
					sbox[expandedKey[(4 * (round - 1)) + 3]]
					^ 0x00
					^ expandedKey[(4 * (round - 8)) + 2];
				expandedKey[(4 * round) + 3] =
					sbox[expandedKey[(4 * (round - 1)) + 0]]
					^ 0x00
					^ expandedKey[(4 * (round - 8)) + 3];
			} else {
				// RoundKey =
				// sub_word(expanded_key(round - 1) * 4))
				// XOR expanded_key((round - 8) * 4)
				expandedKey[(4 * round) + 0] =
					sbox[expandedKey[(4 * (round - 1)) + 0]]
					^ expandedKey[(4 * (round - 8)) + 0];
				expandedKey[(4 * round) + 1] =
					sbox[expandedKey[(4 * (round - 1)) + 1]]
					^ expandedKey[(4 * (round - 8)) + 1];
				expandedKey[(4 * round) + 2] =
					sbox[expandedKey[(4 * (round - 1)) + 2]]
					^ expandedKey[(4 * (round - 8)) + 2];
				expandedKey[(4 * round) + 3] =
					sbox[expandedKey[(4 * (round - 1)) + 3]]
					^ expandedKey[(4 * (round - 8)) + 3];
			}
		} else {
			// RoundKey =
			// expanded_key((round - 1) * 4)
			// XOR expanded_key((round - 8) * 4)
			expandedKey[(4 * round) + 0] =
				expandedKey[(4 * (round - 1)) + 0]
				^ expandedKey[(4 * (round - 8)) + 0];
			expandedKey[(4 * round) + 1] =
				expandedKey[(4 * (round - 1)) + 1]
				^ expandedKey[(4 * (round - 8)) + 1];
			expandedKey[(4 * round) + 2] =
				expandedKey[(4 * (round - 1)) + 2]
				^ expandedKey[(4 * (round - 8)) + 2];
			expandedKey[(4 * round) + 3] =
				expandedKey[(4 * (round - 1)) + 3]
				^ expandedKey[(4 * (round - 8)) + 3];
		}
	}
}



/* XOR's each byte of the state block with the round corresponding
 * expandedKey byte
 */
void add_round_key(uint8_t *state, const uint8_t *expandedKey, int round)
{
	for (int i = 0; i < 16; i++) {
		state[i] = state[i] ^ expandedKey[(16 * round) + i];
	}
}



/* Replaces each byte of the state block with the corresponding sbox byte
 */
void sub_bytes(uint8_t *state, const uint8_t *sbox)
{
	for (int i = 0; i < 16; i++) {
		state[i] = sbox[state[i]];
	}
}



/* Seeing the state as a downward developing 4x4 matrix, the shift_row function
 * shifts the rows according to the inline comments
 */
void shift_row(uint8_t *state)
{
	uint8_t tmp;

	// Shift second row one to the left
	tmp       = state[1];
	state[1]  = state[5];
	state[5]  = state[9];
	state[9]  = state[13];
	state[13] = tmp;

	// Shift third row two to the left
	tmp 	  = state[2];
	state[2]  = state[10];
	state[10] = tmp;
	tmp		  = state[6];
	state[6]  = state[14];
	state[14] = tmp;

	// Shift fourth row three to the left
	tmp       = state[3];
	state[3]  = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7]  = tmp;
}



/* Seeing the state as a downward developing 4x4 matrix, the mix_columns
 * function multiplies this state-matrix with the AES specified mix-matrix
 * in the galois field GF(2^8)
 */
void mix_columns(uint8_t *state, const uint8_t *mixMultMatrix)
{
	// Because state[1|2|3] need state[0] for calculation state[0] can not
	// be overwritten before all calulation is done. Therefore save the
	// Calculation results in tmp array
	uint8_t tmp[4];

	for (int i = 0; i < 4; i++) {
		tmp[0] = galois_mul(state[(4 * i) + 0], mixMultMatrix[0])
			^ galois_mul(state[(4 * i) + 1], mixMultMatrix[1])
			^ galois_mul(state[(4 * i) + 2], mixMultMatrix[2])
			^ galois_mul(state[(4 * i) + 3], mixMultMatrix[3]);
		tmp[1] = galois_mul(state[(4 * i) + 0], mixMultMatrix[4])
			^ galois_mul(state[(4 * i) + 1], mixMultMatrix[5])
			^ galois_mul(state[(4 * i) + 2], mixMultMatrix[6])
			^ galois_mul(state[(4 * i) + 3], mixMultMatrix[7]);
		tmp[2] = galois_mul(state[(4 * i) + 0], mixMultMatrix[8])
			^ galois_mul(state[(4 * i) + 1], mixMultMatrix[9])
			^ galois_mul(state[(4 * i) + 2], mixMultMatrix[10])
			^ galois_mul(state[(4 * i) + 3], mixMultMatrix[11]);
		tmp[3] = galois_mul(state[(4 * i) + 0], mixMultMatrix[12])
			^ galois_mul(state[(4 * i) + 1], mixMultMatrix[13])
			^ galois_mul(state[(4 * i) + 2], mixMultMatrix[14])
			^ galois_mul(state[(4 * i) + 3], mixMultMatrix[15]);

		state[(4 * i) + 0] = tmp[0];
		state[(4 * i) + 1] = tmp[1];
		state[(4 * i) + 2] = tmp[2];
		state[(4 * i) + 3] = tmp[3];
	}
}



/* For more Information about this algorithm and Galois Field
 * Multiplication see
 * https://en.wikipedia.org/wiki/Finite_field_arithmetic
 */
uint8_t galois_mul(uint8_t a, uint8_t b)
{
	// p as the product of the multiplication
	uint8_t p = 0;

	while (b) {
		// If b odd, then add corresponding a to p
        	if (b & 1) {
			// In GF(2^m), addition is XOR
			p = p ^ a;
		}

		// If a >= 128 it will overflow when shifted left, so reduce
    		if(a & 0x80) {
			// XOR with primitive polynomial x^8 + x^4 + x^3 + x + 1
			a = (a << 1) ^ 0x11b;
		} else {
			// Multiply a by 2
			a <<= 1;
		}

		// Divide b by 2
        	b >>= 1;
	}

	return p;
}

