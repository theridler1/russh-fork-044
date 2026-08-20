/*
 * Optimization barriers used by sntrup761.c for constant-time arithmetic.
 * Original definitions live in OpenSSH's kexsntrup761x25519.c — we replicate
 * them here because we don't import the SSH kex wrapper.
 */
#include <stdint.h>

volatile int16_t crypto_int16_optblocker = 0;
volatile int32_t crypto_int32_optblocker = 0;
volatile int64_t crypto_int64_optblocker = 0;
