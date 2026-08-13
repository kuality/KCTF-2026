#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "generated_data.h"

#define MAX_INPUT 128U
#define PAYLOAD_HEADER_SIZE 16U

enum opcode {
    OP_XOR = 0x10,
    OP_ADD = 0x11,
    OP_SUB = 0x12,
    OP_ROL = 0x13,
    OP_COMPARE = 0x20,
    OP_NEXT = 0x30,
};

typedef struct __attribute__((packed)) {
    uint8_t magic[8];
    uint32_t encrypted_length;
    uint8_t encrypted_payload[ENCRYPTED_PAYLOAD_LEN];
} encrypted_blob_t;

__attribute__((used))
static const encrypted_blob_t CHECK_DATA = {
    .magic = {'K', 'C', 'T', 'F', 'S', '3', 'E', '1'},
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
    char relay[MAX_INPUT] = {0};
    char input[MAX_INPUT] = {0};
    uint8_t credentials[2U * MAX_INPUT + 1U] = {0};
    uint8_t payload[ENCRYPTED_PAYLOAD_LEN];

    puts("== Liberation Signal -3 ==");
    size_t dispatch_length = read_line("dispatch> ", dispatch);
    size_t relay_length = read_line("relay> ", relay);
    if (dispatch_length == 0 || relay_length == 0) {
        return 1;
    }

    memcpy(credentials, dispatch, dispatch_length);
    credentials[dispatch_length] = (uint8_t)'|';
    memcpy(credentials + dispatch_length + 1U, relay, relay_length);
    size_t credential_length = dispatch_length + 1U + relay_length;

    stream_xor(
        credentials,
        credential_length,
        CHECK_DATA.encrypted_payload,
        payload,
        sizeof(payload)
    );
    if (memcmp(payload, "S3PLAIN1", 8U) != 0) {
        puts("The frequency remains silent.");
        return 1;
    }

    uint32_t flag_length = read_u32(payload + 8U);
    uint32_t program_length = read_u32(payload + 12U);
    if (
        flag_length == 0U
        || flag_length >= MAX_INPUT
        || PAYLOAD_HEADER_SIZE + program_length != sizeof(payload)
    ) {
        puts("Damaged broadcast program.");
        return 1;
    }
    const uint8_t *program = payload + PAYLOAD_HEADER_SIZE;

    size_t input_length = read_line("flag> ", input);
    if (input_length != flag_length) {
        puts("The VM rejects the input frame.");
        return 1;
    }

    size_t pc = 0;
    size_t input_index = 0;
    uint8_t accumulator = (uint8_t)input[0];
    uint8_t difference = 0;
    int compared = 0;

    while (pc < program_length && input_index < input_length) {
        uint8_t opcode = program[pc++];
        if (opcode == OP_NEXT) {
            if (!compared) {
                difference |= 1U;
            }
            ++input_index;
            compared = 0;
            if (input_index < input_length) {
                accumulator = (uint8_t)input[input_index];
            }
            continue;
        }

        if (pc >= program_length) {
            difference |= 1U;
            break;
        }

        uint8_t immediate = program[pc++];
        switch (opcode) {
            case OP_XOR:
                accumulator ^= immediate;
                break;
            case OP_ADD:
                accumulator = (uint8_t)(accumulator + immediate);
                break;
            case OP_SUB:
                accumulator = (uint8_t)(accumulator - immediate);
                break;
            case OP_ROL:
                accumulator = rol8(accumulator, immediate);
                break;
            case OP_COMPARE:
                difference |= (uint8_t)(accumulator ^ immediate);
                compared = 1;
                break;
            default:
                difference |= 1U;
                pc = program_length;
                break;
        }
    }

    if (input_index != input_length || pc != program_length) {
        difference |= 1U;
    }

    if (difference == 0) {
        puts("Broadcast restored: 1945-08-15");
        puts("The voice of liberation reaches the network.");
        return 0;
    }

    puts("Broadcast rejected.");
    return 1;
}
