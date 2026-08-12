CC := gcc
STRIP := strip
TARGET := inkspill
LISTENER := listener
SOURCE := inkspill.c
LISTENER_SOURCE := listener.c

CPPFLAGS := -D_FORTIFY_SOURCE=0
CFLAGS := -std=c11 -O0 -g0 -Wall -Wextra -Wpedantic \
          -Wno-format-security -fno-pie -fno-omit-frame-pointer \
          -fstack-protector-all -fno-builtin-printf \
          -fno-asynchronous-unwind-tables -fcf-protection=none -fno-ident
LDFLAGS := -no-pie -Wl,-z,relro,-z,now,-z,noexecstack \
           -Wl,--build-id=none,--section-start=.approval=0x405000
LISTENER_CFLAGS := -std=c11 -O2 -g0 -Wall -Wextra -Wpedantic \
                   -fstack-protector-strong -fcf-protection=none -fno-ident
LISTENER_LDFLAGS := -static -Wl,-z,relro,-z,now,-z,noexecstack \
                    -Wl,--build-id=none

export LC_ALL := C
export SOURCE_DATE_EPOCH := 1767225600

.PHONY: all clean verify-toolchain

all: $(TARGET) $(LISTENER)

$(TARGET): $(SOURCE)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS)
	$(STRIP) --strip-all --remove-section=.comment $@
	chmod 0755 $@

$(LISTENER): $(LISTENER_SOURCE)
	$(CC) $(LISTENER_CFLAGS) $< -o $@ $(LISTENER_LDFLAGS)
	$(STRIP) --strip-all --remove-section=.comment $@
	chmod 0755 $@

verify-toolchain:
	@$(CC) --version | head -n 1
	@ld --version | head -n 1

clean:
	rm -f -- $(TARGET) $(LISTENER)
