CC := gcc
STRIP := strip
BUILD_DIR := build
SOURCE_DATE_EPOCH := 1776038400

COMMON_CFLAGS := -O2 -pipe -Wall -Wextra -Werror -fno-omit-frame-pointer \
	-fstack-protector-all -fcf-protection=none -D_FORTIFY_SOURCE=2 \
	-ffile-prefix-map=$(CURDIR)=. \
	-fdebug-prefix-map=$(CURDIR)=.
VM_CFLAGS := $(COMMON_CFLAGS) -fPIE
VM_LDFLAGS := -pie -Wl,-z,relro,-z,now,-z,noexecstack \
	-Wl,--build-id=sha1
LISTENER_CFLAGS := $(COMMON_CFLAGS) -static
LISTENER_LDFLAGS := -static -Wl,-z,relro,-z,now,-z,noexecstack \
	-Wl,--build-id=sha1

.PHONY: all clean verify toolchain

all: $(BUILD_DIR)/paperweight_vm $(BUILD_DIR)/listener $(BUILD_DIR)/offsets.json

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/paperweight_vm.unstripped: paperweight_vm.c | $(BUILD_DIR)
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) $(CC) $(VM_CFLAGS) $< \
		-o $@ $(VM_LDFLAGS)

$(BUILD_DIR)/paperweight_vm: $(BUILD_DIR)/paperweight_vm.unstripped
	$(STRIP) --strip-all --remove-section=.comment -o $@ $<

$(BUILD_DIR)/listener.unstripped: listener.c | $(BUILD_DIR)
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) $(CC) $(LISTENER_CFLAGS) $< \
		-o $@ $(LISTENER_LDFLAGS)

$(BUILD_DIR)/listener: $(BUILD_DIR)/listener.unstripped
	$(STRIP) --strip-all --remove-section=.comment -o $@ $<

$(BUILD_DIR)/offsets.json: $(BUILD_DIR)/paperweight_vm.unstripped generate_metadata.sh
	sh generate_metadata.sh $(BUILD_DIR)/paperweight_vm.unstripped $@

toolchain:
	@$(CC) --version | head -1
	@ld --version | head -1
	@$(STRIP) --version | head -1

verify: all
	@readelf -hW $(BUILD_DIR)/paperweight_vm | grep -q 'Type:.*DYN'
	@readelf -lW $(BUILD_DIR)/paperweight_vm | grep -q 'GNU_STACK.*RW '
	@readelf -lW $(BUILD_DIR)/paperweight_vm | grep -q 'GNU_RELRO'
	@readelf -dW $(BUILD_DIR)/paperweight_vm | grep -q 'BIND_NOW'
	@readelf -sW $(BUILD_DIR)/paperweight_vm | grep -q '__stack_chk_fail'
	@test "$$(readelf -lW $(BUILD_DIR)/paperweight_vm | \
		sed -n 's@.*Requesting program interpreter: \(.*\)]@\1@p')" = \
		'/lib64/ld-linux-x86-64.so.2'
	@! readelf -dW $(BUILD_DIR)/paperweight_vm | grep -qE 'RPATH|RUNPATH'
	@! readelf -nW $(BUILD_DIR)/paperweight_vm | grep -qE 'IBT|SHSTK'
	@echo 'ELF protections and interpreter: OK'

clean:
	rm -f $(BUILD_DIR)/paperweight_vm $(BUILD_DIR)/paperweight_vm.unstripped \
		$(BUILD_DIR)/listener $(BUILD_DIR)/listener.unstripped \
		$(BUILD_DIR)/offsets.json
