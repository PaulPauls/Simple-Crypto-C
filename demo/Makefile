CC = gcc
CFLAGS = -Wall -Werror -g
CFILES = demo_aes256_ecb.c ../aes/aes256_ecb.c ../aes/aes256_ecb.h
INCLUDE_DIR = '../aes'

demo_aes256_ecb:
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $(CFILES) -o demo_aes256_ecb

clean:
	rm -f demo_aes256_ecb
