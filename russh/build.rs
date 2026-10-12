fn main() {
    cc::Build::new()
        .file("sntrup761-c/sntrup761.c")
        .file("sntrup761-c/optblocker.c")
        .include("sntrup761-c")
        .define("USE_SNTRUP761X25519", None)
        // Rename the two libc-style hooks so this crate never exports global
        // `arc4random_buf` / `crypto_hash_sha512` symbols that would interpose
        // the system ones (see kex/sntrup761_ffi.rs).
        .define("arc4random_buf", "russh_sntrup_randombytes")
        .define("crypto_hash_sha512", "russh_sntrup_sha512")
        .warnings(false)
        .compile("russh_sntrup761");

    println!("cargo:rerun-if-changed=sntrup761-c/sntrup761.c");
    println!("cargo:rerun-if-changed=sntrup761-c/optblocker.c");
    println!("cargo:rerun-if-changed=sntrup761-c/crypto_api.h");
    println!("cargo:rerun-if-changed=sntrup761-c/includes.h");
}
