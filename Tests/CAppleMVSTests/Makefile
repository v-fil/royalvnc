# Decoder unit tests, built with AddressSanitizer + UBSan. `make test`.
CFLAGS = -O1 -g -Wall -Wextra -Wno-unused-parameter -fsanitize=address,undefined -fno-sanitize-recover=undefined

test: mvs_tests
	./mvs_tests

mvs_tests: mvs_tests.c ../../Sources/CAppleMVS/mvs.c ../../Sources/CAppleMVS/include/mvs.h
	$(CC) $(CFLAGS) -I../../Sources/CAppleMVS/include -o $@ mvs_tests.c

clean:
	rm -rf mvs_tests mvs_tests.dSYM

.PHONY: test clean
