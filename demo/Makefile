CFLAGS = -Wall -Werror
OBJECTS = demo_aes256_ecb.o ../aes/aes256_ecb.o


demo_aes256_ecb: $(OBJECTS)
	cc $(CFLAGS) $(OBJECTS) -o demo_aes256_ecb

demo_aes256_ecb.o: demo_aes256_ecb.c ../aes/aes256_ecb.h
	cc -c demo_aes256_ecb.c -I../aes/
../aes/aes256_ecb.o: ../aes/aes256_ecb.c ../aes/aes256_ecb.h
	cc -c ../aes/aes256_ecb.c -o ../aes/aes256_ecb.o


.PHONY: clean
clean:
	rm -f demo_aes256_ecb $(OBJECTS)
