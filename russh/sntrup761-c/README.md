# sntrup761 KEM — vendored from OpenSSH

This directory bundles the OpenSSH reference implementation of the
`sntrup761` (Streamlined NTRU Prime, parameter set 761) Key Encapsulation
Mechanism, used by the `sntrup761x25519-sha512@openssh.com` SSH key
exchange algorithm.

## Sources

| File | Origin |
|---|---|
| `sntrup761.c` | OpenSSH portable v9.9p1 — `sntrup761.c` |
| `crypto_api.h` | OpenSSH portable v9.9p1 — `crypto_api.h` |
| `includes.h` | Local — minimal stand-in for OpenSSH's portable shim |
| `optblocker.c` | Local — extracted from OpenSSH's `kexsntrup761x25519.c` |

Authors of the algorithm and reference C code:
- Daniel J. Bernstein, Chitchanok Chuengsatiansup, Tanja Lange, Christine
  van Vredendaal (sntrup761).
- Code in the public domain (per OpenSSH headers).

## Patches applied for MSVC compatibility

OpenSSH targets POSIX C99 with GCC/Clang extensions. MSVC `cl.exe` lacks
two of those features, so we apply two minimal mechanical edits:

1. **`__attribute__((unused))` neutralized on MSVC** — defined as empty
   macro inside `includes.h`. Pure annotation, no runtime impact.

2. **C99 variable-length arrays converted to `_alloca`** in four sites of
   `sntrup761.c` (Encode/Decode codecs and `Hash_prefix`). On non-MSVC
   compilers, the original C99 VLAs are kept untouched via `#ifdef
   _MSC_VER` gates. Storage layout is identical (stack-allocated buffer
   of the same size); algorithmic behavior unchanged.

Each patched site is wrapped in `#ifdef _MSC_VER ... #else ... #endif`
to preserve the upstream code path on the platforms that already
support it.

## Symbols exposed

```c
int crypto_kem_sntrup761_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_sntrup761_enc(unsigned char *ct, unsigned char *k,
                             const unsigned char *pk);
int crypto_kem_sntrup761_dec(unsigned char *k,
                             const unsigned char *ct,
                             const unsigned char *sk);
```

Sizes: `pk = 1158`, `sk = 1763`, `ct = 1039`, `k = 32` bytes.

## Symbols required from the host

The C source calls two functions that we provide from Rust via
`#[no_mangle] extern "C"` in `src/kex/sntrup761_ffi.rs`:

- `arc4random_buf(buf, n)` — CSPRNG, backed by the `getrandom` crate.
- `crypto_hash_sha512(out, msg, mlen)` — SHA-512, backed by `sha2`.
