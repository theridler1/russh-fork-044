//! `sntrup761x25519-sha512@openssh.com` — hybrid post-quantum SSH key
//! exchange combining SNTRU Prime 761 (KEM) with X25519 (DH), with SHA-512
//! as the transcript hash.
//!
//! Protocol (per OpenSSH's `kexsntrup761x25519.c`, reusing
//! SSH_MSG_KEX_ECDH_INIT / SSH_MSG_KEX_ECDH_REPLY message opcodes):
//!   C → S : msg 30 + ssh-string(sntrup761_pk || x25519_pk)
//!   S → C : msg 31 + host_key + ssh-string(sntrup761_ct || x25519_pk) + sig
//!   K = SHA-512(K_pq || K_cl)
//!   K is encoded as an `ssh-string` in the exchange transcript (deviation from
//!   classical DH which uses `mpint`).

use byteorder::{BigEndian, ByteOrder};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use log::debug;
use sha2::Digest;

use super::sntrup761_ffi::{
    self, CIPHERTEXT_BYTES as SNTRUP761_CIPHERTEXT_SIZE,
    PUBLICKEY_BYTES as SNTRUP761_PUBLIC_KEY_SIZE,
};
use super::{compute_keys_with_encoding, KexAlgorithm, KexType, SharedSecretEncoding};
use crate::keys::encoding::Encoding;
use crate::mac;
use crate::session::Exchange;
use crate::{cipher, msg, CryptoVec};

const X25519_PUBLIC_KEY_SIZE: usize = 32;

pub struct Sntrup761X25519KexType {}

impl KexType for Sntrup761X25519KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        Box::new(Sntrup761X25519Kex {
            sntrup_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
            shared_secret: None,
        }) as Box<dyn KexAlgorithm + Send>
    }
}

#[doc(hidden)]
pub struct Sntrup761X25519Kex {
    sntrup_secret: Option<sntrup761_ffi::SecretKey>,
    x25519_secret: Option<Scalar>,
    k_pq: Option<sntrup761_ffi::SharedSecret>,
    k_cl: Option<MontgomeryPoint>,
    /// Combined shared secret (SHA-512(K_pq || K_cl)) — 64 bytes once derived.
    shared_secret: Option<[u8; 64]>,
}

impl std::fmt::Debug for Sntrup761X25519Kex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Sntrup761X25519Kex {{ <hidden> }}")
    }
}

impl Sntrup761X25519Kex {
    fn finalize_combined_secret(&mut self) -> Result<(), crate::Error> {
        let k_pq = self.k_pq.as_ref().ok_or(crate::Error::KexInit)?;
        let k_cl = self.k_cl.as_ref().ok_or(crate::Error::KexInit)?;
        let mut hasher = sha2::Sha512::new();
        hasher.update(&k_pq.0);
        hasher.update(&k_cl.0);
        let digest = hasher.finalize();
        let mut k = [0u8; 64];
        k.copy_from_slice(&digest);
        self.shared_secret = Some(k);
        Ok(())
    }
}

impl KexAlgorithm for Sntrup761X25519Kex {
    fn skip_exchange(&self) -> bool {
        false
    }

    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), crate::Error> {
        debug!("server_dh (hybrid sntrup761x25519)");

        if payload.first() != Some(&msg::KEX_ECDH_INIT) {
            return Err(crate::Error::Inconsistent);
        }

        #[allow(clippy::indexing_slicing)]
        let c_init_len = BigEndian::read_u32(&payload[1..]) as usize;

        if payload.len() < 5 + c_init_len {
            return Err(crate::Error::Inconsistent);
        }

        if c_init_len != SNTRUP761_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE {
            return Err(crate::Error::Kex);
        }

        #[allow(clippy::indexing_slicing)]
        let c_init = &payload[5..5 + c_init_len];

        #[allow(clippy::indexing_slicing)]
        let c_pk_pq_bytes = &c_init[..SNTRUP761_PUBLIC_KEY_SIZE];
        #[allow(clippy::indexing_slicing)]
        let c_pk_cl_bytes = &c_init[SNTRUP761_PUBLIC_KEY_SIZE..];

        let mut c_pk_pq = sntrup761_ffi::PublicKey([0u8; SNTRUP761_PUBLIC_KEY_SIZE]);
        c_pk_pq.0.copy_from_slice(c_pk_pq_bytes);

        let mut c_pk_cl = MontgomeryPoint([0; 32]);
        c_pk_cl.0.copy_from_slice(c_pk_cl_bytes);

        let (s_ct_pq, k_pq) = sntrup761_ffi::encapsulate(&c_pk_pq).map_err(|_| crate::Error::Kex)?;

        let s_secret = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
        let s_pk_cl = (ED25519_BASEPOINT_TABLE * &s_secret).to_montgomery();

        let k_cl = s_secret * c_pk_cl;

        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend(&s_ct_pq.0);
        exchange.server_ephemeral.extend(&s_pk_cl.0);

        self.k_pq = Some(k_pq);
        self.k_cl = Some(k_cl);
        self.finalize_combined_secret()?;

        Ok(())
    }

    fn client_dh(
        &mut self,
        client_ephemeral: &mut CryptoVec,
        buf: &mut CryptoVec,
    ) -> Result<(), crate::Error> {
        let (sntrup_pk, sntrup_sk) = sntrup761_ffi::generate_keypair().map_err(|_| crate::Error::Kex)?;

        let x25519_secret = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
        let x25519_pk = (ED25519_BASEPOINT_TABLE * &x25519_secret).to_montgomery();

        client_ephemeral.clear();
        client_ephemeral.extend(&sntrup_pk.0);
        client_ephemeral.extend(&x25519_pk.0);

        buf.push(msg::KEX_ECDH_INIT);
        // Single ssh-string carrying the concatenated PQ+classical pubkeys.
        let mut concat = Vec::with_capacity(SNTRUP761_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE);
        concat.extend_from_slice(&sntrup_pk.0);
        concat.extend_from_slice(&x25519_pk.0);
        buf.extend_ssh_string(&concat);

        self.sntrup_secret = Some(sntrup_sk);
        self.x25519_secret = Some(x25519_secret);

        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        if remote_pubkey_.len() != SNTRUP761_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE {
            return Err(crate::Error::Kex);
        }

        #[allow(clippy::indexing_slicing)]
        let s_ct_pq_bytes = &remote_pubkey_[..SNTRUP761_CIPHERTEXT_SIZE];
        #[allow(clippy::indexing_slicing)]
        let s_pk_cl_bytes = &remote_pubkey_[SNTRUP761_CIPHERTEXT_SIZE..];

        let mut s_ct_pq = sntrup761_ffi::Ciphertext([0u8; SNTRUP761_CIPHERTEXT_SIZE]);
        s_ct_pq.0.copy_from_slice(s_ct_pq_bytes);

        let sntrup_secret = self.sntrup_secret.take().ok_or(crate::Error::KexInit)?;
        let k_pq = sntrup761_ffi::decapsulate(&s_ct_pq, &sntrup_secret).map_err(|_| crate::Error::Kex)?;

        let mut s_pk_cl = MontgomeryPoint([0; 32]);
        s_pk_cl.0.copy_from_slice(s_pk_cl_bytes);

        let x25519_secret = self.x25519_secret.take().ok_or(crate::Error::KexInit)?;
        let k_cl = x25519_secret * s_pk_cl;

        self.k_pq = Some(k_pq);
        self.k_cl = Some(k_cl);
        self.finalize_combined_secret()?;

        Ok(())
    }

    fn compute_exchange_hash(
        &self,
        key: &CryptoVec,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<CryptoVec, crate::Error> {
        buffer.clear();
        buffer.extend_ssh_string(&exchange.client_id);
        buffer.extend_ssh_string(&exchange.server_id);
        buffer.extend_ssh_string(&exchange.client_kex_init);
        buffer.extend_ssh_string(&exchange.server_kex_init);

        buffer.extend(key);
        buffer.extend_ssh_string(&exchange.client_ephemeral);
        buffer.extend_ssh_string(&exchange.server_ephemeral);

        // For sntrup761x25519-sha512@openssh.com, the shared secret K is the
        // SHA-512 hash of K_pq || K_cl, and is encoded as an `ssh-string`
        // (length-prefixed bytes) — not as `mpint` like classical DH.
        let k = self.shared_secret.as_ref().ok_or(crate::Error::KexInit)?;
        buffer.extend_ssh_string(k);

        let mut hasher = sha2::Sha512::new();
        hasher.update(&buffer);

        let mut res = CryptoVec::new();
        res.extend(hasher.finalize().as_slice());
        Ok(res)
    }

    fn compute_keys(
        &self,
        session_id: &CryptoVec,
        exchange_hash: &CryptoVec,
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, crate::Error> {
        // OpenSSH feeds K into key derivation exactly as it was hashed into
        // the exchange hash: as an SSH `string`, not an `mpint`. Encoding it
        // as an mpint here diverged whenever K[0] >= 0x80 (or K[0] == 0),
        // i.e. ~50% of handshakes died right after NEWKEYS.
        compute_keys_with_encoding::<sha2::Sha512>(
            self.shared_secret.as_ref().map(|k| &k[..]),
            SharedSecretEncoding::String,
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use byteorder::{BigEndian, ByteOrder};

    #[test]
    fn key_derivation_encodes_k_as_ssh_string() {
        use super::super::encode_shared_secret;
        // High bit set: an mpint would prepend 0x00 (length 65). OpenSSH
        // hashes the raw 64-byte string, so the encoding must stay length 64.
        let mut k = [0x11u8; 64];
        k[0] = 0x80;
        let mut buf = CryptoVec::new();
        encode_shared_secret(&mut buf, &k, SharedSecretEncoding::String);
        assert_eq!(&buf[..4], &[0, 0, 0, 64]);
        assert_eq!(&buf[4..], &k[..]);

        // Leading zero: an mpint would strip it; the string keeps it.
        k[0] = 0x00;
        let mut buf = CryptoVec::new();
        encode_shared_secret(&mut buf, &k, SharedSecretEncoding::String);
        assert_eq!(buf.len(), 68);

        // The classical path still uses mpint.
        k[0] = 0x80;
        let mut buf = CryptoVec::new();
        encode_shared_secret(&mut buf, &k, SharedSecretEncoding::Mpint);
        assert_eq!(&buf[..5], &[0, 0, 0, 65, 0]);
    }

    fn empty_kex() -> Sntrup761X25519Kex {
        Sntrup761X25519Kex {
            sntrup_secret: None,
            x25519_secret: None,
            k_pq: None,
            k_cl: None,
            shared_secret: None,
        }
    }

    #[test]
    fn key_exchange_round_trip() {
        let mut client_kex = empty_kex();
        let mut server_kex = empty_kex();

        let mut client_ephemeral = CryptoVec::new();
        let mut client_init_buf = CryptoVec::new();
        client_kex
            .client_dh(&mut client_ephemeral, &mut client_init_buf)
            .unwrap();

        assert_eq!(
            client_ephemeral.len(),
            SNTRUP761_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE
        );
        assert_eq!(
            client_init_buf[0],
            msg::KEX_ECDH_INIT,
            "init message must start with KEX_ECDH_INIT opcode"
        );
        // The ssh-string length prefix should equal the concatenated pubkey size.
        let declared = BigEndian::read_u32(&client_init_buf[1..5]) as usize;
        assert_eq!(declared, SNTRUP761_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE);

        let mut exchange = Exchange::new();
        server_kex
            .server_dh(&mut exchange, &client_init_buf)
            .unwrap();
        assert_eq!(
            exchange.server_ephemeral.len(),
            SNTRUP761_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE
        );

        // Server already has its combined K. Now drive client decapsulation.
        client_kex
            .compute_shared_secret(&exchange.server_ephemeral)
            .unwrap();

        let client_k = client_kex.shared_secret.unwrap();
        let server_k = server_kex.shared_secret.unwrap();
        assert_eq!(
            client_k, server_k,
            "client and server must derive the same combined shared secret"
        );
        assert_eq!(client_k.len(), 64, "SHA-512(K_pq || K_cl) must be 64 bytes");
    }

    #[test]
    fn exchange_hash_matches_between_peers() {
        let mut client_kex = empty_kex();
        let mut server_kex = empty_kex();

        let mut client_ephemeral = CryptoVec::new();
        let mut client_init_buf = CryptoVec::new();
        client_kex
            .client_dh(&mut client_ephemeral, &mut client_init_buf)
            .unwrap();

        let mut exchange = Exchange::new();
        exchange.client_id.extend(b"SSH-2.0-Test_Client");
        exchange.server_id.extend(b"SSH-2.0-Test_Server");
        exchange.client_kex_init.extend(b"client_kex_init");
        exchange.server_kex_init.extend(b"server_kex_init");
        exchange.client_ephemeral.extend(&client_ephemeral);

        server_kex
            .server_dh(&mut exchange, &client_init_buf)
            .unwrap();
        client_kex
            .compute_shared_secret(&exchange.server_ephemeral)
            .unwrap();

        let mut key = CryptoVec::new();
        key.extend(b"test_host_key");

        let mut buffer = CryptoVec::new();
        let client_hash = client_kex
            .compute_exchange_hash(&key, &exchange, &mut buffer)
            .unwrap();
        let server_hash = server_kex
            .compute_exchange_hash(&key, &exchange, &mut buffer)
            .unwrap();

        assert_eq!(
            client_hash.as_ref(),
            server_hash.as_ref(),
            "exchange hashes must match between peers"
        );
        assert_eq!(client_hash.len(), 64, "SHA-512 digest is 64 bytes");
    }

    #[test]
    fn rejects_invalid_ciphertext_length() {
        let mut client_kex = empty_kex();
        let mut client_ephemeral = CryptoVec::new();
        let mut client_init_buf = CryptoVec::new();
        client_kex
            .client_dh(&mut client_ephemeral, &mut client_init_buf)
            .unwrap();

        let invalid_reply = vec![0u8; 100];
        assert!(client_kex.compute_shared_secret(&invalid_reply).is_err());
    }
}
