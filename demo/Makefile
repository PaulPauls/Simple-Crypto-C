.POSIX:
.PHONY: all clean

CFLAGS = -Wall -Werror
EXECUTABLES = demo_aes256_ecb demo_aes192_ecb demo_aes128_ecb
OBJECTS_256 = demo_aes256_ecb.o ../aes/aes256_ecb.o ../aes/aes_lib_ecb.o
OBJECTS_192 = demo_aes192_ecb.o ../aes/aes192_ecb.o ../aes/aes_lib_ecb.o
OBJECTS_128 = demo_aes128_ecb.o ../aes/aes128_ecb.o ../aes/aes_lib_ecb.o



all: $(EXECUTABLES)



demo_aes256_ecb: $(OBJECTS_256)
	cc $(CFLAGS) $(OBJECTS_256) -o demo_aes256_ecb
demo_aes256_ecb.o: demo_aes256_ecb.c
	cc $(CFLAGS) -c demo_aes256_ecb.c -I../aes/
../aes/aes256_ecb.o: ../aes/aes256_ecb.c
	cc $(CFLAGS) -c ../aes/aes256_ecb.c -o ../aes/aes256_ecb.o
../aes/aes_lib_ecb.o: ../aes/aes_lib_ecb.c
	cc $(CFLAGS) -c ../aes/aes_lib_ecb.c -o ../aes/aes_lib_ecb.o



demo_aes192_ecb: $(OBJECTS_192)
	cc $(CFLAGS) $(OBJECTS_192) -o demo_aes192_ecb
demo_aes192_ecb.o: demo_aes192_ecb.c
	cc $(CFLAGS) -c demo_aes192_ecb.c -I../aes/
../aes/aes192_ecb.o: ../aes/aes192_ecb.c
	cc $(CFLAGS) -c ../aes/aes192_ecb.c -o ../aes/aes192_ecb.o
../aes/aes_lib_ecb.o: ../aes/aes_lib_ecb.c
	cc $(CFLAGS) -c ../aes/aes_lib_ecb.c -o ../aes/aes_lib_ecb.o



demo_aes128_ecb: $(OBJECTS_128)
	cc $(CFLAGS) $(OBJECTS_128) -o demo_aes128_ecb
demo_aes128_ecb.o: demo_aes128_ecb.c
	cc $(CFLAGS) -c demo_aes128_ecb.c -I../aes/
../aes/aes128_ecb.o: ../aes/aes128_ecb.c
	cc $(CFLAGS) -c ../aes/aes128_ecb.c -o ../aes/aes128_ecb.o
../aes/aes_lib_ecb.o: ../aes/aes_lib_ecb.c
	cc $(CFLAGS) -c ../aes/aes_lib_ecb.c -o ../aes/aes_lib_ecb.o



clean:
	rm -f $(EXECUTABLES) $(OBJECTS_256) $(OBJECTS_192) $(OBJECTS_128)

