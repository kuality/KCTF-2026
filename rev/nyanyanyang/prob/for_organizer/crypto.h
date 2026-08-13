#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

void sha256(const uint8_t *data, size_t length, uint8_t output[32]);
void stream_xor(const uint8_t *passphrase, size_t passphrase_length,
                const uint8_t *data, size_t data_length, uint8_t *output);

#endif
