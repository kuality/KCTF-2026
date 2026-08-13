#include "crypto.h"

#include <string.h>

typedef struct {
    uint8_t data[64];
    uint32_t data_length;
    uint64_t bit_length;
    uint32_t state[8];
} sha256_context_t;

static const uint32_t ROUND_CONSTANTS[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t rotate_right(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32U - count));
}

static void sha256_transform(sha256_context_t *context, const uint8_t data[64]) {
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (uint32_t i = 0; i < 16U; ++i) {
        words[i] =
            ((uint32_t)data[4U * i] << 24U)
            | ((uint32_t)data[4U * i + 1U] << 16U)
            | ((uint32_t)data[4U * i + 2U] << 8U)
            | (uint32_t)data[4U * i + 3U];
    }
    for (uint32_t i = 16U; i < 64U; ++i) {
        uint32_t s0 =
            rotate_right(words[i - 15U], 7U)
            ^ rotate_right(words[i - 15U], 18U)
            ^ (words[i - 15U] >> 3U);
        uint32_t s1 =
            rotate_right(words[i - 2U], 17U)
            ^ rotate_right(words[i - 2U], 19U)
            ^ (words[i - 2U] >> 10U);
        words[i] = words[i - 16U] + s0 + words[i - 7U] + s1;
    }

    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];

    for (uint32_t i = 0; i < 64U; ++i) {
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t sum0 =
            rotate_right(a, 2U) ^ rotate_right(a, 13U) ^ rotate_right(a, 22U);
        uint32_t sum1 =
            rotate_right(e, 6U) ^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
        uint32_t first = h + sum1 + choice + ROUND_CONSTANTS[i] + words[i];
        uint32_t second = sum0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + first;
        d = c;
        c = b;
        b = a;
        a = first + second;
    }

    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

static void sha256_init(sha256_context_t *context) {
    context->data_length = 0;
    context->bit_length = 0;
    context->state[0] = 0x6a09e667U;
    context->state[1] = 0xbb67ae85U;
    context->state[2] = 0x3c6ef372U;
    context->state[3] = 0xa54ff53aU;
    context->state[4] = 0x510e527fU;
    context->state[5] = 0x9b05688cU;
    context->state[6] = 0x1f83d9abU;
    context->state[7] = 0x5be0cd19U;
}

static void sha256_update(
    sha256_context_t *context,
    const uint8_t *data,
    size_t length
) {
    for (size_t i = 0; i < length; ++i) {
        context->data[context->data_length++] = data[i];
        if (context->data_length == 64U) {
            sha256_transform(context, context->data);
            context->bit_length += 512U;
            context->data_length = 0;
        }
    }
}

static void sha256_final(sha256_context_t *context, uint8_t digest[32]) {
    uint32_t index = context->data_length;

    context->data[index++] = 0x80U;
    if (index > 56U) {
        while (index < 64U) {
            context->data[index++] = 0;
        }
        sha256_transform(context, context->data);
        index = 0;
    }
    while (index < 56U) {
        context->data[index++] = 0;
    }

    context->bit_length += (uint64_t)context->data_length * 8U;
    for (uint32_t i = 0; i < 8U; ++i) {
        context->data[63U - i] =
            (uint8_t)(context->bit_length >> (8U * i));
    }
    sha256_transform(context, context->data);

    for (uint32_t i = 0; i < 8U; ++i) {
        digest[4U * i] = (uint8_t)(context->state[i] >> 24U);
        digest[4U * i + 1U] = (uint8_t)(context->state[i] >> 16U);
        digest[4U * i + 2U] = (uint8_t)(context->state[i] >> 8U);
        digest[4U * i + 3U] = (uint8_t)context->state[i];
    }
}

static void sha256(const uint8_t *data, size_t length, uint8_t digest[32]) {
    sha256_context_t context;
    sha256_init(&context);
    sha256_update(&context, data, length);
    sha256_final(&context, digest);
}

void stream_xor(
    const uint8_t *passphrase,
    size_t passphrase_length,
    const uint8_t *input,
    uint8_t *output,
    size_t length
) {
    uint8_t key[32];
    uint8_t block[32];
    uint32_t counter = 0;
    size_t offset = 0;

    sha256(passphrase, passphrase_length, key);
    while (offset < length) {
        uint8_t counter_bytes[4] = {
            (uint8_t)counter,
            (uint8_t)(counter >> 8U),
            (uint8_t)(counter >> 16U),
            (uint8_t)(counter >> 24U),
        };
        sha256_context_t context;
        sha256_init(&context);
        sha256_update(&context, key, sizeof(key));
        sha256_update(&context, counter_bytes, sizeof(counter_bytes));
        sha256_final(&context, block);

        size_t block_length = length - offset;
        if (block_length > sizeof(block)) {
            block_length = sizeof(block);
        }
        for (size_t i = 0; i < block_length; ++i) {
            output[offset + i] = input[offset + i] ^ block[i];
        }
        offset += block_length;
        ++counter;
    }

    memset(key, 0, sizeof(key));
    memset(block, 0, sizeof(block));
}
