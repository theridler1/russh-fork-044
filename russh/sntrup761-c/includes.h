/*
 * Minimal stand-in for OpenSSH's portable includes.h.
 * We only need the bits sntrup761.c relies on indirectly via crypto_api.h.
 */
#ifndef INCLUDES_H
#define INCLUDES_H

#define HAVE_STDINT_H 1

/* MSVC doesn't understand GCC's __attribute__((...)). Drop it. */
#if defined(_MSC_VER) && !defined(__clang__)
#define __attribute__(x)
#include <malloc.h>          /* for _alloca */
#endif

#endif
