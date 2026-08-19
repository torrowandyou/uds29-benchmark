TONGSUO_PREFIX ?= $(CURDIR)/build/tongsuo-install
CC ?= cc
CFLAGS ?= -O2 -g
CPPFLAGS += -I$(TONGSUO_PREFIX)/include
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wno-deprecated-declarations
LDFLAGS += -L$(TONGSUO_PREFIX)/lib64 -L$(TONGSUO_PREFIX)/lib
LDLIBS += -lcrypto -pthread -ldl -lm

.PHONY: all clean run

all: build/uds29_bench

build/uds29_bench: src/uds29_bench.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

build:
	mkdir -p $@

run: build/uds29_bench
	LD_LIBRARY_PATH=$(TONGSUO_PREFIX)/lib64:$(TONGSUO_PREFIX)/lib ./build/uds29_bench --iterations 2000 --warmup 200 --csv results.csv

clean:
	rm -f build/uds29_bench results.csv
