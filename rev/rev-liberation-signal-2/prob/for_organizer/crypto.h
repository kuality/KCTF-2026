#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

void stream_xor(
    const uint8_t *passphrase,
    size_t passphrase_length,
    const uint8_t *input,
    uint8_t *output,
    size_t length
);

#endif
