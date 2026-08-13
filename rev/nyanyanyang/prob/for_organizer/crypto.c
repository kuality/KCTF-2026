#include "crypto.h"

#include <string.h>

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

static uint32_t rotate_right(uint32_t value, unsigned int shift) {
    return (value >> shift) | (value << (32U - shift));
}

static void compress_block(uint32_t state[8], const uint8_t block[64]) {
    uint32_t schedule[64];
    for (unsigned int i = 0U; i < 16U; i++) {
        schedule[i] =
            ((uint32_t)block[4U * i] << 24U)
            | ((uint32_t)block[4U * i + 1U] << 16U)
            | ((uint32_t)block[4U * i + 2U] << 8U)
            | (uint32_t)block[4U * i + 3U];
    }
    for (unsigned int i = 16U; i < 64U; i++) {
        uint32_t s0 = rotate_right(schedule[i - 15U], 7U)
            ^ rotate_right(schedule[i - 15U], 18U)
            ^ (schedule[i - 15U] >> 3U);
        uint32_t s1 = rotate_right(schedule[i - 2U], 17U)
            ^ rotate_right(schedule[i - 2U], 19U)
            ^ (schedule[i - 2U] >> 10U);
        schedule[i] = schedule[i - 16U] + s0 + schedule[i - 7U] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (unsigned int i = 0U; i < 64U; i++) {
        uint32_t s1 = rotate_right(e, 6U) ^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
        uint32_t choice = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + choice + ROUND_CONSTANTS[i] + schedule[i];
        uint32_t s0 = rotate_right(a, 2U) ^ rotate_right(a, 13U) ^ rotate_right(a, 22U);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + majority;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256(const uint8_t *data, size_t length, uint8_t output[32]) {
    uint32_t state[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };
    uint8_t block[64];
    size_t offset = 0U;

    while (length - offset >= 64U) {
        compress_block(state, data + offset);
        offset += 64U;
    }

    size_t remaining = length - offset;
    memset(block, 0, sizeof(block));
    memcpy(block, data + offset, remaining);
    block[remaining] = 0x80U;

    if (remaining >= 56U) {
        compress_block(state, block);
        memset(block, 0, sizeof(block));
    }

    uint64_t bit_length = (uint64_t)length * 8U;
    for (unsigned int i = 0U; i < 8U; i++) {
        block[63U - i] = (uint8_t)(bit_length >> (8U * i));
    }
    compress_block(state, block);

    for (unsigned int i = 0U; i < 8U; i++) {
        output[4U * i] = (uint8_t)(state[i] >> 24U);
        output[4U * i + 1U] = (uint8_t)(state[i] >> 16U);
        output[4U * i + 2U] = (uint8_t)(state[i] >> 8U);
        output[4U * i + 3U] = (uint8_t)state[i];
    }
}

void stream_xor(const uint8_t *passphrase, size_t passphrase_length,
                const uint8_t *data, size_t data_length, uint8_t *output) {
    uint8_t key[32];
    uint8_t seed[36];
    uint8_t block[32];

    sha256(passphrase, passphrase_length, key);
    memcpy(seed, key, 32U);

    for (size_t counter = 0U, offset = 0U; offset < data_length; counter++, offset += 32U) {
        for (unsigned int i = 0U; i < 4U; i++) {
            seed[32U + i] = (uint8_t)(counter >> (8U * i));
        }
        sha256(seed, sizeof(seed), block);
        size_t chunk = data_length - offset < 32U ? data_length - offset : 32U;
        for (size_t i = 0U; i < chunk; i++) {
            output[offset + i] = data[offset + i] ^ block[i];
        }
    }
}
