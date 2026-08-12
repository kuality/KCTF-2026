CC = gcc
BUILD_DIR := build

CPPFLAGS := -D_FORTIFY_SOURCE=2
CFLAGS := -std=c11 -O1 -g0 -Wall -Wextra -Werror -fPIE -fstack-protector-all \
	-ffile-prefix-map=$(CURDIR)=. -fno-record-gcc-switches
HARDEN_LDFLAGS := -pie -Wl,-z,relro,-z,now,-z,noexecstack -Wl,--build-id=sha1

.PHONY: all clean verify

all: $(BUILD_DIR)/secondhand $(BUILD_DIR)/secondhand.debug $(BUILD_DIR)/tcp_runner

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/secondhand.unstripped: secondhand.c | $(BUILD_DIR)
	SOURCE_DATE_EPOCH=1772323200 $(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(HARDEN_LDFLAGS)

$(BUILD_DIR)/secondhand.debug: $(BUILD_DIR)/secondhand.unstripped
	cp $< $@

$(BUILD_DIR)/secondhand: $(BUILD_DIR)/secondhand.unstripped
	cp $< $@
	strip --strip-all $@

$(BUILD_DIR)/tcp_runner.unstripped: tcp_runner.c | $(BUILD_DIR)
	SOURCE_DATE_EPOCH=1772323200 $(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(HARDEN_LDFLAGS)

$(BUILD_DIR)/tcp_runner: $(BUILD_DIR)/tcp_runner.unstripped
	cp $< $@
	strip --strip-all $@

verify: all
	./verify_build.sh $(BUILD_DIR)/secondhand $(BUILD_DIR)/secondhand.debug

clean:
	rm -f $(BUILD_DIR)/secondhand $(BUILD_DIR)/secondhand.debug \
		$(BUILD_DIR)/secondhand.unstripped $(BUILD_DIR)/tcp_runner \
		$(BUILD_DIR)/tcp_runner.unstripped
