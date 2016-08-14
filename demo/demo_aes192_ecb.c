#include <stdio.h>   // printf(), fprintf()
#include <stdlib.h>  // ERROR_SUCCESS
#include <stdint.h>  // uint8_t
#include <stdbool.h> // true, false

#include "aes192_ecb.h" // aes192_ecb_encrypt(), aes192_ecb_decrypt()



int main();
void plain_cipher_cmp(const uint8_t *plaintext, size_t plainSize,
	const uint8_t *key, size_t keySize, int nr);
void print_hex(const uint8_t *hex, size_t size);



/* Demo of the aes192 ECB mode, which uses the key and the plaintexts defined
 * as test vectors in 'NIST SP 800-38A' document.
 */
int main()
{
	uint8_t key[] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
		0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
	uint8_t plaintext1[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
	uint8_t plaintext2[] = {0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
	uint8_t plaintext3[] = {0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef};
	uint8_t plaintext4[] = {0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
	uint8_t plaintext5[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};


	plain_cipher_cmp(plaintext1, sizeof(plaintext1), key, sizeof(key), 1);
	plain_cipher_cmp(plaintext2, sizeof(plaintext2), key, sizeof(key), 2);
	plain_cipher_cmp(plaintext3, sizeof(plaintext3), key, sizeof(key), 3);
	plain_cipher_cmp(plaintext4, sizeof(plaintext4), key, sizeof(key), 4);
	plain_cipher_cmp(plaintext5, sizeof(plaintext5), key, sizeof(key), 5);


	return EXIT_SUCCESS;
}



/* Encrypts given plaintext with key, prints them and then compares decrypted
 * ciphertext with given plaintext
 *
 * Process:
 * 	[1] Define arrays for ciphertext and decryptedCiphertext
 *	[2] Encrypt and decrypt
 *	[3] Print results with a final comparison of encryption and decryption
 */
void plain_cipher_cmp(const uint8_t *plaintext, size_t plainSize,
	const uint8_t *key, size_t keySize, int nr)
{
	uint8_t ciphertext[plainSize];
	uint8_t decryptedCiphertext[sizeof(ciphertext)];
	int cmpCorrect = true;

	if (aes192_ecb_encrypt(plaintext, plainSize, key, keySize, ciphertext,
		sizeof(ciphertext)) < 0) {
		fprintf(stderr, "Error when calling aes192_ecb_encrypt()");
		exit(EXIT_FAILURE);
	}

	if (aes192_ecb_decrypt(ciphertext, sizeof(ciphertext), key, keySize,
		decryptedCiphertext, sizeof(decryptedCiphertext)) < 0) {
		fprintf(stderr, "Error when calling aes192_ecb_decrypt()");
		exit(EXIT_FAILURE);
	}

	printf("****************************************\n");
	printf("Key:\n");
	print_hex(key, sizeof(key));

	printf("\nPlaintext%d:\n", nr);
	print_hex(plaintext, plainSize);
	printf("\nCiphertext%d:\n", nr);
	print_hex(ciphertext, sizeof(ciphertext));
	printf("\nDecrypted Ciphertext%d:\n", nr);
	print_hex(decryptedCiphertext, sizeof(decryptedCiphertext));

	printf("\nPlaintext%d equals decrypt(Ciphertext%d): ", nr, nr);

	if (plainSize != sizeof(decryptedCiphertext))
		cmpCorrect = false;

	// traverse plaintext and decryptedCiphertext to check for differences
	for (int i = 0; i < plainSize; i++) {
		if(plaintext[i] != decryptedCiphertext[i])
			cmpCorrect = false;
	}

	if (cmpCorrect)
		printf("YES!\n");
	else
		printf("NO!\n");

	printf("****************************************\n");
}



/* Input:
 *	uint8_t *hex	byte-array consisting of hex-encoded numbers
 *	size_t size	the size of the given byte-array
 *
 * Output: Prints the hex encoded numbers with a line break each 8th number
 */
void print_hex(const uint8_t *hex, size_t size)
{
	for (int i = 0; i < size; i++) {
		printf("0x%.2x ", hex[i]);

		if ((i+1) % 8 == 0)
			printf("\n");
	}
}

