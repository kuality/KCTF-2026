CC := gcc
STRIP := strip
TARGET := late_checkout
SOURCE := late_checkout.c
LISTENER := tcp_listener
LISTENER_SOURCE := tcp_listener.c
CONSTANTS := solve_constants.py
RUNTIME_DIR ?= ../../common/ubuntu_26_04
RUNTIME_LIBC := $(RUNTIME_DIR)/libc.so.6
RUNTIME_LOADER := $(RUNTIME_DIR)/ld-linux-x86-64.so.2

# Reproducible challenge profile:
#   NX + Full RELRO, no PIE, no stack canary, fixed frame pointer, no CET.
CFLAGS := -std=c11 -O0 -g0 -Wall -Wextra -Wpedantic \
	-fno-stack-protector -fno-pie -fno-omit-frame-pointer \
	-fno-optimize-sibling-calls -fno-asynchronous-unwind-tables \
	-fno-unwind-tables -fcf-protection=none -U_FORTIFY_SOURCE \
	-D_FORTIFY_SOURCE=0 -Wno-stringop-overflow
LDFLAGS := -no-pie -Wl,-z,relro,-z,now,-z,noexecstack \
	-Wl,-z,separate-code -Wl,--build-id=none
LISTENER_CFLAGS := -std=c11 -O2 -g0 -Wall -Wextra -Wpedantic \
	-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE
LISTENER_LDFLAGS := -static-pie -Wl,-z,relro,-z,now,-z,noexecstack \
	-Wl,--build-id=none

export LC_ALL := C
export TZ := UTC
export SOURCE_DATE_EPOCH := 1767225600

.PHONY: all clean package verify

all: $(TARGET) $(LISTENER)

$(TARGET): $(SOURCE) record_constants.sh
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	./record_constants.sh $@ $(CONSTANTS)
	$(STRIP) --strip-all --remove-section=.comment $@

$(LISTENER): $(LISTENER_SOURCE)
	$(CC) $(LISTENER_CFLAGS) $< -o $@ $(LISTENER_LDFLAGS)
	$(STRIP) --strip-all --remove-section=.comment $@

package: $(TARGET) $(LISTENER)
	test -f $(RUNTIME_LIBC)
	test -f $(RUNTIME_LOADER)
	install -m 0755 $(TARGET) ../for_user/$(TARGET)
	install -m 0755 $(TARGET) ../for_organizer/$(TARGET)
	install -m 0755 $(LISTENER) ../for_user/$(LISTENER)
	install -m 0755 $(LISTENER) ../for_organizer/$(LISTENER)
	install -m 0644 $(CONSTANTS) ../for_organizer/$(CONSTANTS)
	install -m 0644 $(RUNTIME_LIBC) ../for_user/libc.so.6
	install -m 0644 $(RUNTIME_LIBC) ../for_organizer/libc.so.6
	install -m 0755 $(RUNTIME_LOADER) ../for_user/ld-linux-x86-64.so.2
	install -m 0755 $(RUNTIME_LOADER) ../for_organizer/ld-linux-x86-64.so.2

verify: package
	./verify.sh

clean:
	rm -f $(TARGET) $(LISTENER) $(CONSTANTS)
