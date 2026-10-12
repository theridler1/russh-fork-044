//! Safe Rust wrapper around the OpenSSH-vendored sntrup761 KEM (see
//! `russh/sntrup761-c/`).
//!
//! The C source calls `arc4random_buf` for randomness and
//! `crypto_hash_sha512` for hashing. `build.rs` renames both, at compile
//! time, to `russh_sntrup_randombytes` and `russh_sntrup_sha512`, which we
//! provide here on top of `getrandom` and `sha2`.
//!
//! The rename matters: exporting global `arc4random_buf` /
//! `crypto_hash_sha512` symbols from the final binary would interpose libc's
//! `arc4random_buf` (macOS, the BSDs, glibc >= 2.36) for every library in the
//! process. `arc4random()` (`small_random32` in `crypto_api.h`) is not
//! referenced by the vendored sntrup761 code, so it needs no shim.

use sha2::{Digest, Sha512};

#[cfg(test)]
pub(crate) static RANDOMBYTES_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static SHA512_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub const PUBLICKEY_BYTES: usize = 1158;
pub const SECRETKEY_BYTES: usize = 1763;
pub const CIPHERTEXT_BYTES: usize = 1039;
pub const SHARED_SECRET_BYTES: usize = 32;

extern "C" {
    fn crypto_kem_sntrup761_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn crypto_kem_sntrup761_enc(ct: *mut u8, k: *mut u8, pk: *const u8) -> i32;
    fn crypto_kem_sntrup761_dec(k: *mut u8, ct: *const u8, sk: *const u8) -> i32;
}

/// `arc4random_buf` for the vendored C code (renamed by `build.rs`).
/// It cannot report failure, and continuing without randomness would be
/// worse than stopping, so a CSPRNG failure aborts (no unwind across FFI).
#[no_mangle]
pub extern "C" fn russh_sntrup_randombytes(buf: *mut u8, n: usize) {
    #[cfg(test)]
    RANDOMBYTES_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, n) };
    if getrandom::getrandom(slice).is_err() {
        std::process::abort();
    }
}

/// `crypto_hash_sha512` for the vendored C code (renamed by `build.rs`).
#[no_mangle]
pub extern "C" fn russh_sntrup_sha512(out: *mut u8, msg: *const u8, mlen: u64) -> i32 {
    #[cfg(test)]
    SHA512_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let input = unsafe { std::slice::from_raw_parts(msg, mlen as usize) };
    let digest = Sha512::digest(input);
    unsafe { std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 64) };
    0
}

pub struct PublicKey(pub [u8; PUBLICKEY_BYTES]);
pub struct SecretKey(pub Box<[u8; SECRETKEY_BYTES]>);
pub struct Ciphertext(pub [u8; CIPHERTEXT_BYTES]);
pub struct SharedSecret(pub [u8; SHARED_SECRET_BYTES]);

/// Reasons the sntrup761 KEM C functions might reject our inputs. The
/// reference implementation in OpenSSH always returns 0; a non-zero value
/// would indicate either a programming error in our wrapper (wrong-sized
/// buffer) or memory corruption. We surface it instead of asserting in
/// release builds (which would silently continue with garbage).
#[derive(Debug)]
pub struct KemError(pub i32);

impl std::fmt::Display for KemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sntrup761 KEM operation failed (rc={})", self.0)
    }
}

impl std::error::Error for KemError {}

pub fn generate_keypair() -> Result<(PublicKey, SecretKey), KemError> {
    let mut pk = [0u8; PUBLICKEY_BYTES];
    let mut sk = Box::new([0u8; SECRETKEY_BYTES]);
    let rc = unsafe { crypto_kem_sntrup761_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if rc != 0 { return Err(KemError(rc)); }
    Ok((PublicKey(pk), SecretKey(sk)))
}

pub fn encapsulate(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), KemError> {
    let mut ct = [0u8; CIPHERTEXT_BYTES];
    let mut k = [0u8; SHARED_SECRET_BYTES];
    let rc = unsafe { crypto_kem_sntrup761_enc(ct.as_mut_ptr(), k.as_mut_ptr(), pk.0.as_ptr()) };
    if rc != 0 { return Err(KemError(rc)); }
    Ok((Ciphertext(ct), SharedSecret(k)))
}

pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> Result<SharedSecret, KemError> {
    let mut k = [0u8; SHARED_SECRET_BYTES];
    let rc = unsafe { crypto_kem_sntrup761_dec(k.as_mut_ptr(), ct.0.as_ptr(), sk.0.as_ptr()) };
    if rc != 0 { return Err(KemError(rc)); }
    Ok(SharedSecret(k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let (pk, sk) = generate_keypair().expect("keypair");
        let (ct, k_enc) = encapsulate(&pk).expect("enc");
        let k_dec = decapsulate(&ct, &sk).expect("dec");
        assert_eq!(k_enc.0, k_dec.0, "sntrup761 KEM shared secrets must match");
    }

    /// The C code must reach our renamed shims, not a libc `arc4random_buf`
    /// (glibc >= 2.36, macOS and the BSDs all export one) or another
    /// library's `crypto_hash_sha512`.
    #[test]
    fn c_code_calls_renamed_shims() {
        use std::sync::atomic::Ordering;
        let rand_before = RANDOMBYTES_CALLS.load(Ordering::SeqCst);
        let hash_before = SHA512_CALLS.load(Ordering::SeqCst);
        let (pk, _sk) = generate_keypair().expect("keypair");
        let _ = encapsulate(&pk).expect("enc");
        assert!(RANDOMBYTES_CALLS.load(Ordering::SeqCst) > rand_before);
        assert!(SHA512_CALLS.load(Ordering::SeqCst) > hash_before);
    }
}
