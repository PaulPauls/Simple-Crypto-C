#include <stdio.h>   // printf(...), fprintf(...)
#include <stdlib.h>  // ERROR_SUCCESS, ERROR_FAILURE
#include <stdint.h>  // uint8_t
#include <stdbool.h> // true, false

#include "aes192_ecb.h" // aes192_ecb_encrypt(...), aes192_ecb_decrypt(...)



// private functions
int main();
void plain_cipher_cmp(const uint8_t *plaintext, size_t plainSize, const uint8_t *key, size_t keySize);
void print_hex(const uint8_t *hex, size_t size);



/* Demo of the functions defined in aes192_ecb.c. Key and plaintexts are test
 * vectors from the NIST SP800-38A document and were tested successfully.
 */
int main()
{
	uint8_t key[] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
		0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
	uint8_t plaintext[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
	uint8_t ciphertext[sizeof(plaintext)];
	uint8_t decryptedCiphertext[sizeof(plaintext)];
	int cmpCorrect = true;


	if (aes192_ecb_encrypt(plaintext, sizeof(plaintext), key, sizeof(key), ciphertext, sizeof(ciphertext)) < 0) {
		fprintf(stderr, "Error when calling aes192_ecb_encrypt(...)");
		return EXIT_FAILURE;
	}

	if (aes192_ecb_decrypt(ciphertext, sizeof(ciphertext), key, sizeof(key), decryptedCiphertext, sizeof(decryptedCiphertext)) < 0) {
		fprintf(stderr, "Error when calling aes192_ecb_decrypt(...)");
		return EXIT_FAILURE;
	}


	printf("****************************************\n");
	printf("Key:\n");
	print_hex(key, sizeof(key));
	printf("\nPlaintext:\n");
	print_hex(plaintext, sizeof(plaintext));
	printf("\nCiphertext:\n");
	print_hex(ciphertext, sizeof(ciphertext));
	printf("\nDecrypted Ciphertext:\n");
	print_hex(decryptedCiphertext, sizeof(decryptedCiphertext));

	printf("\nPlaintext equals decrypted Ciphertext: ");
	if (sizeof(plaintext) != sizeof(decryptedCiphertext)) {
		cmpCorrect = false;
	}

	for (int i = 0; i < sizeof(plaintext); i++) {
		if(plaintext[i] != decryptedCiphertext[i]) {
			cmpCorrect = false;
		}
	}

	if (cmpCorrect) {
		printf("YES!\n");
	} else {
		printf("NO!\n");
	}

	printf("****************************************\n");


	return EXIT_SUCCESS;
}



/* Prints each byte of the input array as a hex encoded number.
 * Line break at each 8th number.
 *
 * uint8_t *input: arbitrary byte-array
 * size_t size:    size of 'input' in byte
 */
void print_hex(const uint8_t *input, size_t size)
{
	for (int i = 0; i < size; i++) {
		printf("0x%.2x ", input[i]);

		if ((i+1) % 8 == 0) {
			printf("\n");
		}
	}
}

