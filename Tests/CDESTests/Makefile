# DES unit tests, built with AddressSanitizer + UBSan. `make test`.
CFLAGS = -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=undefined

test: des_tests
	./des_tests

des_tests: des_tests.c ../../Sources/CDES/des.c ../../Sources/CDES/include/rvnc_des.h
	$(CC) $(CFLAGS) -I../../Sources/CDES/include -o $@ des_tests.c

clean:
	rm -rf des_tests des_tests.dSYM

.PHONY: test clean
