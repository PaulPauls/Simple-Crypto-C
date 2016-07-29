#include <stdint.h> // uint8_t
#include <stdlib.h> // size_t



// public functions
void key_expansion(const uint8_t *key, size_t keySize, uint8_t *expandedKey,
	size_t expandedKeySize, const uint8_t *sbox);
void add_round_key(uint8_t *state, const uint8_t *expandedKey, int round);
void sub_bytes(uint8_t *state, const uint8_t *sbox);
void shift_row(uint8_t *state);
void inv_shift_row(uint8_t *state);
void mix_columns(uint8_t *state, const uint8_t *mixMultMatrix);
uint8_t galois_mul(uint8_t a, uint8_t b);



/* Input: const uint8_t *key	byte-array with original 256bit key
 *		  uint8_t *expandedKey	arbitrary byte-array with 240 bytes
 *		  const uint8_t *sbox	byte-array AES sbox
 *
 * Output: expands the key to the 240 key values according to AES specification
 */
void key_expansion(const uint8_t *key, size_t keySize, uint8_t *expandedKey,
	size_t expandedKeySize, const uint8_t *sbox)
{
	static const uint8_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};
	int round;

	// First Copy the given key into the expandedKey as a basis to start expanding on
	for (round = 0; round < (keySize / 4); round++) {
		expandedKey[(4 * round) + 0] = key[(4 * round) + 0];
		expandedKey[(4 * round) + 1] = key[(4 * round) + 1];
		expandedKey[(4 * round) + 2] = key[(4 * round) + 2];
		expandedKey[(4 * round) + 3] = key[(4 * round) + 3];
	}

	// Now walk through the generation of the remaining bytes of the expandedKey
	for (round = 8; round < (expandedKeySize / 4); round++) {
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
		state[i] ^= expandedKey[(16 * round) + i];
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
	tmp       = state[2];
	state[2]  = state[10];
	state[10] = tmp;
	tmp       = state[6];
	state[6]  = state[14];
	state[14] = tmp;

	// Shift fourth row three to the left
	tmp       = state[3];
	state[3]  = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7]  = tmp;
}



/* Seeing the state as a downward developing 4x4 matrix, the inv_shift_row
 * function shifts the rows according to the inline comments
 */
void inv_shift_row(uint8_t *state)
{
	uint8_t tmp;

	// Shift second row one to the right
	tmp       = state[1];
	state[1]  = state[13];
	state[13] = state[9];
	state[9]  = state[5];
	state[5]  = tmp;

	// Shift third row two to the right
	tmp       = state[2];
	state[2]  = state[10];
	state[10] = tmp;
	tmp       = state[6];
	state[6]  = state[14];
	state[14] = tmp;

	// Shift fourth row three to the right
	tmp       = state[3];
	state[3]  = state[7];
	state[7]  = state[11];
	state[11] = state[15];
	state[15] = tmp;
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

