#include <stdio.h>  // printf()
#include <stdlib.h> // ERROR_SUCCESS
#include <stdint.h> // uint8_t

#include "aes256_ecb.h" // aes256_ecb_encrypt()



int main();
void print_hex(const uint8_t *hex, size_t size);



/* Demo of the aes256 ECB mode, which uses the key and the plaintexts defined
 * as test vectors in 'NIST SP 800-38A' document.
 *
 * Process: [1] Define key and plaintexts, declare ciphertexts
 *			[2] Encrypt all plaintexts with key to corresponding ciphertexts
 *			[3] Print key and all plaintexts with corresponding ciphertexts
 */
int main()
{
    uint8_t key[] 		 = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                     	    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                		    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
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
    uint8_t ciphertext1[16];
    uint8_t ciphertext2[16];
    uint8_t ciphertext3[16];
    uint8_t ciphertext4[16];
	uint8_t ciphertext5[64];


    aes256_ecb_encrypt(plaintext1, sizeof(plaintext1), key, sizeof(key), ciphertext1, sizeof(ciphertext1));
    aes256_ecb_encrypt(plaintext2, sizeof(plaintext2), key, sizeof(key), ciphertext2, sizeof(ciphertext2));
    aes256_ecb_encrypt(plaintext3, sizeof(plaintext3), key, sizeof(key), ciphertext3, sizeof(ciphertext3));
    aes256_ecb_encrypt(plaintext4, sizeof(plaintext4), key, sizeof(key), ciphertext4, sizeof(ciphertext4));
    aes256_ecb_encrypt(plaintext5, sizeof(plaintext5), key, sizeof(key), ciphertext5, sizeof(ciphertext5));
	

	printf("Key:\n");
	print_hex(key, sizeof(key));
	
	printf("\nPlaintext1:\n");
	print_hex(plaintext1, sizeof(plaintext1));
	printf("\nCiphertext1:\n");
	print_hex(ciphertext1, sizeof(ciphertext1));
	
	printf("\nPlaintext2:\n");
	print_hex(plaintext2, sizeof(plaintext2));
	printf("\nCiphertext2:\n");
	print_hex(ciphertext2, sizeof(ciphertext2));
	
	printf("\nPlaintext3:\n");
	print_hex(plaintext3, sizeof(plaintext3));
	printf("\nCiphertext3:\n");
	print_hex(ciphertext3, sizeof(ciphertext3));
	
	printf("\nPlaintext4:\n");
	print_hex(plaintext4, sizeof(plaintext4));
	printf("\nCiphertext4:\n");
	print_hex(ciphertext4, sizeof(ciphertext4));
	
	printf("\nPlaintext5:\n");
	print_hex(plaintext5, sizeof(plaintext5));
	printf("\nCiphertext5:\n");
	print_hex(ciphertext5, sizeof(ciphertext5));


    return EXIT_SUCCESS;
}



/* Input: uint8_t *hex		byte-array consisting of hex-encoded numbers
 *		  size_t size		the size of the given byte-array
 * Output: Prints the hex encoded numbers with a line break each 8th number
 */
void print_hex(const uint8_t *hex, size_t size)
{
	for(int i = 0; i < size; i++) {
		printf("0x%.2x ", hex[i]);

		if((i+1) % 8 == 0) {
			printf("\n");
		}
	}
}

