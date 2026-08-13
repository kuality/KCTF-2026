CC ?= gcc
CFLAGS ?= -std=c11 -O0 -Wall -Wextra -fno-stack-protector -fno-pie
LDFLAGS ?= -no-pie -Wl,--build-id=none -s
TARGET := ../for_user/taegeuk_relay

.PHONY: all generate verify clean

all: $(TARGET)

generate: generated_data.h

generated_data.h: generate.py
	python3 generate.py

$(TARGET): challenge.c crypto.c crypto.h generated_data.h
	$(CC) $(CFLAGS) challenge.c crypto.c -o $@ $(LDFLAGS)

verify: $(TARGET)
	python3 verify.py

clean:
	rm -f generated_data.h $(TARGET)
