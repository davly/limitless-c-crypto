# limitless-c-crypto -- header-only C-substrate shared crypto cohort
#
# `make test` builds the KAT-1 + macro-prefix verification test rig and
# runs it. `make clean` removes build artifacts.

CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude
LDFLAGS :=

TEST_BIN := test_session45_kat
TEST_SRC := test/test_session45_kat.c

.PHONY: all test clean

all: test

test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) include/limitless_session45_sha256.h include/limitless_session45_hmac_sha256.h include/limitless_session45_kat.h include/limitless_session45_mirror_mark.h
	$(CC) $(CFLAGS) -o $(TEST_BIN) $(TEST_SRC) $(LDFLAGS)

clean:
	rm -f $(TEST_BIN) $(TEST_BIN).exe
