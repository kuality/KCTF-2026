CC := gcc
STRIP := strip
BUILD_DIR := build
CHALLENGE := $(BUILD_DIR)/rle_gallery
DEBUG := $(BUILD_DIR)/rle_gallery.debug
LISTENER := $(BUILD_DIR)/listener

CFLAGS := -std=c11 -O1 -g -Wall -Wextra -Werror -U_FORTIFY_SOURCE \
	-D_FORTIFY_SOURCE=0 -fPIE \
	-fstack-protector-all -fno-omit-frame-pointer -fcf-protection=none
LDFLAGS := -pie -Wl,-z,relro,-z,now,-z,noexecstack \
	-Wl,--build-id=sha1
LISTENER_CFLAGS := -std=c11 -Os -Wall -Wextra -Werror -static

.PHONY: all clean verify

all: $(CHALLENGE) $(LISTENER)

$(BUILD_DIR):
	mkdir -p $@

$(DEBUG): rle_gallery.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

$(CHALLENGE): $(DEBUG)
	cp $< $@
	$(STRIP) --strip-all $@

$(LISTENER): listener.c | $(BUILD_DIR)
	$(CC) $(LISTENER_CFLAGS) $< -o $@
	$(STRIP) --strip-all $@

verify: all
	@readelf -W -h $(CHALLENGE) | grep -q 'ELF64'
	@readelf -W -h $(LISTENER) | grep -q 'ELF64'
	@readelf -W -l $(CHALLENGE) | grep -E 'GNU_STACK|GNU_RELRO'
	@readelf -W -d $(CHALLENGE) | grep -q 'BIND_NOW'
	@readelf -W -h $(CHALLENGE) | grep -q 'DYN (Position-Independent Executable file)'
	@readelf -W -s $(CHALLENGE) | grep -q '__stack_chk_fail'

clean:
	rm -rf $(BUILD_DIR)
