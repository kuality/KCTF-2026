#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "generated_data.h"

#define MAX_INPUT 128U
#define PAYLOAD_HEADER_SIZE 20U

typedef struct __attribute__((packed)) {
    uint8_t magic[8];
    uint32_t encrypted_length;
    uint8_t encrypted_payload[ENCRYPTED_PAYLOAD_LEN];
} encrypted_blob_t;

__attribute__((used))
static const encrypted_blob_t CHECK_DATA = {
    .magic = {'K', 'C', 'T', 'F', 'S', '2', 'E', '1'},
    .encrypted_length = ENCRYPTED_PAYLOAD_LEN,
    .encrypted_payload = ENCRYPTED_PAYLOAD,
};

static uint32_t read_u32(const uint8_t *data) {
    return
        (uint32_t)data[0]
        | ((uint32_t)data[1] << 8U)
        | ((uint32_t)data[2] << 16U)
        | ((uint32_t)data[3] << 24U);
}

static uint8_t rol8(uint8_t value, unsigned int shift) {
    shift &= 7U;
    return (uint8_t)((value << shift) | (value >> (8U - shift)));
}

static uint8_t round_key(size_t index, uint32_t round) {
    return (uint8_t)(0x35U + 0x17U * index + 0x29U * round);
}

static size_t read_line(const char *prompt, char output[MAX_INPUT]) {
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(output, MAX_INPUT, stdin) == NULL) {
        return 0;
    }
    size_t length = strcspn(output, "\r\n");
    output[length] = '\0';
    return length;
}

int main(void) {
    char dispatch[MAX_INPUT] = {0};
    char input[MAX_INPUT] = {0};
    uint8_t payload[ENCRYPTED_PAYLOAD_LEN];
    uint8_t current[MAX_INPUT] = {0};
    uint8_t next[MAX_INPUT] = {0};
    uint8_t difference = 0;

    puts("== Liberation Signal -2 ==");
    size_t dispatch_length = read_line("dispatch> ", dispatch);
    if (dispatch_length == 0) {
        return 1;
    }

    stream_xor(
        (const uint8_t *)dispatch,
        dispatch_length,
        CHECK_DATA.encrypted_payload,
        payload,
        sizeof(payload)
    );

    if (memcmp(payload, "S2PLAIN1", 8U) != 0) {
        puts("No matching courier route.");
        return 1;
    }

    uint32_t flag_length = read_u32(payload + 8U);
    uint32_t rounds = read_u32(payload + 12U);
    uint32_t note_length = read_u32(payload + 16U);
    size_t expected_size =
        PAYLOAD_HEADER_SIZE + flag_length + 256U + flag_length + note_length;
    if (
        flag_length == 0U
        || flag_length >= MAX_INPUT
        || note_length >= MAX_INPUT
        || rounds == 0U
        || expected_size != sizeof(payload)
    ) {
        puts("Damaged relay packet.");
        return 1;
    }

    const uint8_t *permutation = payload + PAYLOAD_HEADER_SIZE;
    const uint8_t *sbox = permutation + flag_length;
    const uint8_t *target = sbox + 256U;
    const uint8_t *encrypted_note = target + flag_length;

    size_t input_length = read_line("flag> ", input);
    if (input_length != flag_length) {
        puts("The relay frame has the wrong length.");
        return 1;
    }

    memcpy(current, input, input_length);
    for (uint32_t round = 0; round < rounds; ++round) {
        memset(next, 0, sizeof(next));
        for (size_t index = 0; index < input_length; ++index) {
            if (permutation[index] >= input_length) {
                puts("Damaged permutation.");
                return 1;
            }
            uint8_t value = current[index] ^ round_key(index, round);
            value = sbox[value];
            value = rol8(value, (unsigned int)((index + 3U * round) % 7U) + 1U);
            next[permutation[index]] = value;
        }
        memcpy(current, next, input_length);
    }

    for (size_t index = 0; index < input_length; ++index) {
        difference |= (uint8_t)(current[index] ^ target[index]);
    }
    if (difference != 0) {
        puts("The relay rejects the message.");
        return 1;
    }

    char relay_note[MAX_INPUT] = {0};
    stream_xor(
        (const uint8_t *)input,
        input_length,
        encrypted_note,
        (uint8_t *)relay_note,
        note_length
    );
    relay_note[note_length] = '\0';

    puts("Relay sequence restored.");
    printf("Relay phrase: %s\n", relay_note);
    puts("Next route: 815-3 / Liberation Signal -3");
    return 0;
}
