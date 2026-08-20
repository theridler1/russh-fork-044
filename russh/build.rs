fn main() {
    cc::Build::new()
        .file("sntrup761-c/sntrup761.c")
        .file("sntrup761-c/optblocker.c")
        .include("sntrup761-c")
        .define("USE_SNTRUP761X25519", None)
        .warnings(false)
        .compile("russh_sntrup761");

    println!("cargo:rerun-if-changed=sntrup761-c/sntrup761.c");
    println!("cargo:rerun-if-changed=sntrup761-c/optblocker.c");
    println!("cargo:rerun-if-changed=sntrup761-c/crypto_api.h");
    println!("cargo:rerun-if-changed=sntrup761-c/includes.h");
}
