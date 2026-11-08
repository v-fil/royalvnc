# Fuzz target for the 1011 decoder (fuzz_mvs.c), seeded with synthetic inputs (seeds.c).
#
#   make replay        any C compiler: runs the seeds, and the inputs in corpus/ if present,
#                      once each, with AddressSanitizer + UBSan. CORPUS=dir... adds directories.
#   make fuzz          libFuzzer, coverage guided: FUZZ_TIME seconds (default 300), new inputs
#                      in corpus/, crashes as crash-* here. Needs a clang that ships libFuzzer
#                      (Apple's does not): on macOS e.g. FUZZ_CC="$(brew --prefix llvm)/bin/clang";
#                      on Linux plain clang. FUZZ_FLAGS adds libFuzzer options.
#   make clean
#
# The seeds are written to seeds/ at build time; nothing in seeds/ or corpus/ is committed.
MVS = ../../Sources/CAppleMVS
SRC = fuzz_mvs.c $(MVS)/mvs.c
DEPS = $(SRC) $(MVS)/include/mvs.h
WARN = -Wall -Wextra -Wno-unused-parameter
SAN = -fsanitize=address,undefined -fno-sanitize-recover=undefined

CFLAGS = -O1 -g $(WARN) $(SAN)
FUZZ_CC = clang
FUZZ_CFLAGS = -O1 -g $(WARN) -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined
FUZZ_TIME = 300
FUZZ_FLAGS =
CORPUS =

replay: fuzz_mvs_replay seeds/.done
	./fuzz_mvs_replay seeds $(wildcard corpus) $(CORPUS)

fuzz: fuzz_mvs seeds/.done
	mkdir -p corpus
	./fuzz_mvs -max_total_time=$(FUZZ_TIME) -print_final_stats=1 $(FUZZ_FLAGS) corpus seeds

fuzz_mvs_replay: $(DEPS)
	$(CC) $(CFLAGS) -DMVS_FUZZ_REPLAY -I$(MVS)/include -o $@ $(SRC)

fuzz_mvs: $(DEPS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -I$(MVS)/include -o $@ $(SRC)

seeds_gen: seeds.c
	$(CC) $(CFLAGS) -o $@ seeds.c

seeds/.done: seeds_gen
	rm -rf seeds
	mkdir -p seeds
	./seeds_gen seeds
	touch $@

clean:
	rm -rf fuzz_mvs fuzz_mvs_replay seeds_gen *.dSYM seeds

.PHONY: replay fuzz clean
