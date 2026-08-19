TONGSUO_PREFIX ?= $(CURDIR)/build/tongsuo-install
CC ?= cc
CFLAGS ?= -O2 -g
CPPFLAGS += -I$(TONGSUO_PREFIX)/include
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wno-deprecated-declarations
LDFLAGS += -L$(TONGSUO_PREFIX)/lib64 -L$(TONGSUO_PREFIX)/lib
LDLIBS += -lcrypto -pthread -ldl -lm

DEVICE ?=
ITERATIONS ?= 10000
WARMUP ?= 1000
CPU ?=

.PHONY: all clean run benchmark figures

all: build/uds29_bench

build/uds29_bench: src/uds29_bench.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

build:
	mkdir -p $@

run benchmark:
	@set -eu; if [ -n "$(DEVICE)" ]; then export DEVICE_ID="$(DEVICE)"; fi; export TONGSUO_PREFIX="$(TONGSUO_PREFIX)" CC="$(CC)" ITERATIONS="$(ITERATIONS)" WARMUP="$(WARMUP)"; if [ -n "$(CPU)" ]; then export BENCH_CPU="$(CPU)"; fi; ./run_benchmark.sh

figures:
	@set -eu; device_id="$(DEVICE)"; if [ -z "$$device_id" ]; then device_id=$$(./run_benchmark.sh --print-device-id); fi; csv="results/$$device_id/results.csv"; out="figures/$$device_id"; python3 scripts/make_paper_figures.py "$$csv" "$$out/latency_by_phase.svg" --figure latency; python3 scripts/make_paper_figures.py "$$csv" "$$out/payload_size.svg" --figure payload; python3 scripts/make_paper_figures.py "$$csv" "$$out/latency_payload_tradeoff.svg" --figure tradeoff; python3 scripts/make_paper_figures.py "$$csv" "$$out/isotp_frames.svg" --figure isotp

clean:
	$(RM) build/uds29_bench
