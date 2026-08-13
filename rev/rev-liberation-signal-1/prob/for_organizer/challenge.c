#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "generated_data.h"

typedef struct __attribute__((packed)) {
    uint8_t magic[8];
    uint32_t length;
    uint32_t note_length;
    uint8_t seed;
    uint8_t reserved[3];
    uint8_t target[FLAG_LEN];
    uint8_t encrypted_note[NOTE_LEN];
} rolling_blob_t;

__attribute__((used))
static const rolling_blob_t CHECK_DATA = {
    .magic = {'K', 'C', 'T', 'F', 'D', 'C', '0', '2'},
    .length = FLAG_LEN,
    .note_length = NOTE_LEN,
    .seed = ROLLING_SEED,
    .reserved = {0, 0, 0},
    .target = TARGET_BYTES,
    .encrypted_note = NOTE_BYTES,
};

static uint8_t rol8(uint8_t value, unsigned int shift) {
    shift &= 7U;
    return (uint8_t)((value << shift) | (value >> (8U - shift)));
}

int main(void) {
    char input[128] = {0};
    uint8_t state = CHECK_DATA.seed;
    uint8_t difference = 0;

    puts("== Liberation Signal -1 ==");
    printf("flag> ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 1;
    }

    size_t length = strcspn(input, "\r\n");
    input[length] = '\0';

    if (length != CHECK_DATA.length) {
        puts("The lock refuses that length.");
        return 1;
    }

    for (size_t i = 0; i < length; ++i) {
        uint8_t mixed = (uint8_t)input[i];
        mixed ^= state;
        mixed ^= (uint8_t)(0x31U + 0x17U * i);
        mixed = rol8(mixed, (unsigned int)(i % 7U) + 1U);
        mixed = (uint8_t)(mixed + (uint8_t)(7U + 13U * i));

        difference |= (uint8_t)(mixed ^ CHECK_DATA.target[i]);
        state = (uint8_t)(state + (uint8_t)input[i] + 0x3dU);
    }

    if (difference == 0) {
        char note[NOTE_LEN + 1U];
        for (size_t i = 0; i < CHECK_DATA.note_length; ++i) {
            note[i] = (char)(
                CHECK_DATA.encrypted_note[i]
                ^ (uint8_t)input[i % length]
                ^ (uint8_t)(0xa7U + 29U * i)
            );
        }
        note[CHECK_DATA.note_length] = '\0';

        puts("Courier record accepted.");
        printf("Dispatch code: %s\n", note);
        puts("Next route: 815-2 / Liberation Signal -2");
        return 0;
    }

    puts("Still locked.");
    return 1;
}
