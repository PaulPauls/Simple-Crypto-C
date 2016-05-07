.POSIX:
CFLAGS=-I../aes -O2

demo_aes256_ecb: demo_aes256_ecb.o ../aes/aes256_ecb.o

../aes/aes256_ecb.o: ../aes/aes256_ecb.h

clean:
	rm -f *.o ../aes/*.o demo_aes256_ecb
.PHONY: clean
