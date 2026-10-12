use std::convert::TryInto;

use byteorder::{BigEndian, ByteOrder};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use log::debug;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{compute_keys, KexAlgorithm, KexType};
use crate::keys::encoding::Encoding;
use crate::mac::{self};
use crate::session::Exchange;
use crate::{cipher, msg, CryptoVec};

/// Length of an X25519 public share and of an X25519 secret scalar.
pub(crate) const X25519_LEN: usize = 32;

/// A fresh X25519 secret (32 random bytes). Clamping happens inside
/// `mul_clamped` / `mul_base_clamped`, exactly as RFC 7748 specifies.
pub(crate) fn x25519_secret() -> Zeroizing<[u8; X25519_LEN]> {
    Zeroizing::new(rand::random::<[u8; X25519_LEN]>())
}

/// RFC 7748 X25519 public value: `X25519(sk, 9)`.
pub(crate) fn x25519_public(sk: &[u8; X25519_LEN]) -> MontgomeryPoint {
    EdwardsPoint::mul_base_clamped(*sk).to_montgomery()
}

/// RFC 7748 X25519 with the checks OpenSSH applies (`kexc25519_shared_key_ext`):
///
/// * the peer share must be exactly 32 bytes (a wrong length used to panic in
///   `clone_from_slice`, GHSA-g9hv-x236-4qp3);
/// * the shared value must not be all-zero. Because the scalar is clamped (a
///   multiple of the cofactor 8), every low-order peer point maps to zero, so
///   this single constant-time comparison rejects the whole low-order class.
pub(crate) fn x25519_checked(
    peer: &[u8],
    sk: &[u8; X25519_LEN],
) -> Result<MontgomeryPoint, crate::Error> {
    let peer: [u8; X25519_LEN] = peer.try_into().map_err(|_| crate::Error::Kex)?;
    let shared = MontgomeryPoint(peer).mul_clamped(*sk);
    if bool::from(shared.0.ct_eq(&[0u8; X25519_LEN])) {
        return Err(crate::Error::Kex);
    }
    Ok(shared)
}

pub struct Curve25519KexType {}

impl KexType for Curve25519KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        Box::new(Curve25519Kex {
            local_secret: None,
            shared_secret: None,
        }) as Box<dyn KexAlgorithm + Send>
    }
}

#[doc(hidden)]
pub struct Curve25519Kex {
    local_secret: Option<Zeroizing<[u8; X25519_LEN]>>,
    shared_secret: Option<MontgomeryPoint>,
}

impl std::fmt::Debug for Curve25519Kex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
    }
}

// We used to support curve "NIST P-256" here, but the security of
// that curve is controversial, see
// http://safecurves.cr.yp.to/rigid.html
impl KexAlgorithm for Curve25519Kex {
    fn skip_exchange(&self) -> bool {
        false
    }

    #[doc(hidden)]
    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), crate::Error> {
        debug!("server_dh");

        let client_pubkey = {
            if payload.first() != Some(&msg::KEX_ECDH_INIT) {
                return Err(crate::Error::Inconsistent);
            }

            if payload.len() < 5 {
                return Err(crate::Error::Inconsistent);
            }

            #[allow(clippy::indexing_slicing)] // length checked
            let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;

            if pubkey_len != X25519_LEN {
                return Err(crate::Error::Kex);
            }

            if payload.len() < 5 + pubkey_len {
                return Err(crate::Error::Inconsistent);
            }

            #[allow(clippy::indexing_slicing)] // length checked
            &payload[5..5 + X25519_LEN]
        };

        let server_secret = x25519_secret();
        let server_pubkey = x25519_public(&server_secret);
        let shared = x25519_checked(client_pubkey, &server_secret)?;

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend(&server_pubkey.0);
        self.shared_secret = Some(shared);
        Ok(())
    }

    #[doc(hidden)]
    fn client_dh(
        &mut self,
        client_ephemeral: &mut CryptoVec,
        buf: &mut CryptoVec,
    ) -> Result<(), crate::Error> {
        let client_secret = x25519_secret();
        let client_pubkey = x25519_public(&client_secret);

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend(&client_pubkey.0);

        buf.push(msg::KEX_ECDH_INIT);
        buf.extend_ssh_string(&client_pubkey.0);

        self.local_secret = Some(client_secret);
        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        let local_secret = self.local_secret.take().ok_or(crate::Error::KexInit)?;
        let shared = x25519_checked(remote_pubkey_, &local_secret)?;
        self.shared_secret = Some(shared);
        Ok(())
    }

    fn compute_exchange_hash(
        &self,
        key: &CryptoVec,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<CryptoVec, crate::Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        buffer.extend_ssh_string(&exchange.client_id);
        buffer.extend_ssh_string(&exchange.server_id);
        buffer.extend_ssh_string(&exchange.client_kex_init);
        buffer.extend_ssh_string(&exchange.server_kex_init);

        buffer.extend(key);
        buffer.extend_ssh_string(&exchange.client_ephemeral);
        buffer.extend_ssh_string(&exchange.server_ephemeral);

        if let Some(ref shared) = self.shared_secret {
            buffer.extend_ssh_mpint(&shared.0);
        }

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
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
        compute_keys::<sha2::Sha256>(
            self.shared_secret.as_ref().map(|x| x.0.as_slice()),
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
pub(crate) mod tests {
    use super::*;

    pub(crate) fn hex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64);
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// libsodium's X25519 low-order blocklist (`crypto_scalarmult_curve25519_ref10`,
    /// `has_small_order`): 0, 1, the two order-8 points, p-1, p and p+1.
    /// Each is also listed with bit 255 set: RFC 7748 masks that bit, so a
    /// peer can send these encodings and must still be rejected.
    /// Shared with the hybrid tests.
    pub(crate) fn low_order_points() -> Vec<[u8; 32]> {
        let canonical: Vec<[u8; 32]> = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ]
        .iter()
        .map(|s| hex32(s))
        .collect();
        let mut all = canonical.clone();
        for mut p in canonical {
            p[31] |= 0x80;
            all.push(p);
        }
        all
    }

    fn empty_kex() -> Curve25519Kex {
        Curve25519Kex {
            local_secret: None,
            shared_secret: None,
        }
    }

    fn ecdh_init(share: &[u8]) -> Vec<u8> {
        let mut p = vec![msg::KEX_ECDH_INIT];
        p.extend_from_slice(&(share.len() as u32).to_be_bytes());
        p.extend_from_slice(share);
        p
    }

    #[test]
    fn rfc7748_x25519_vector() {
        // RFC 7748 §5.2, first test vector, through mul_clamped.
        let k = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let out = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(MontgomeryPoint(u).mul_clamped(k).0, out);
        assert_eq!(x25519_checked(&u, &k).unwrap().0, out);

        // RFC 7748 §6.1 Diffie-Hellman vector: public keys and shared secret.
        let a = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let a_pub = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let b = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let b_pub = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519_public(&a).0, a_pub);
        assert_eq!(x25519_public(&b).0, b_pub);
        assert_eq!(x25519_checked(&b_pub, &a).unwrap().0, shared);
        assert_eq!(x25519_checked(&a_pub, &b).unwrap().0, shared);
    }

    #[test]
    fn rejects_low_order_points() {
        for p in low_order_points() {
            // Client side: the server's ephemeral share is low order.
            let mut client = empty_kex();
            let mut eph = CryptoVec::new();
            let mut buf = CryptoVec::new();
            client.client_dh(&mut eph, &mut buf).unwrap();
            let res = client.compute_shared_secret(&p);
            assert!(
                matches!(res, Err(crate::Error::Kex)),
                "client accepted {:02x?}",
                p
            );
            assert!(client.shared_secret.is_none());

            // Server side: the client's ephemeral share is low order.
            let mut server = empty_kex();
            let mut exchange = Exchange::new();
            let res = server.server_dh(&mut exchange, &ecdh_init(&p));
            assert!(
                matches!(res, Err(crate::Error::Kex)),
                "server accepted {:02x?}",
                p
            );
            assert!(server.shared_secret.is_none());
        }
    }

    #[test]
    fn rejects_wrong_length_share() {
        for len in [0usize, 31, 33] {
            let share = vec![9u8; len];
            let mut client = empty_kex();
            let mut eph = CryptoVec::new();
            let mut buf = CryptoVec::new();
            client.client_dh(&mut eph, &mut buf).unwrap();
            assert!(matches!(
                client.compute_shared_secret(&share),
                Err(crate::Error::Kex)
            ));

            let mut server = empty_kex();
            assert!(server
                .server_dh(&mut Exchange::new(), &ecdh_init(&share))
                .is_err());
        }
        // Truncated KEX_ECDH_INIT (shorter than the length prefix) must not panic.
        for payload in [&[msg::KEX_ECDH_INIT][..], &[msg::KEX_ECDH_INIT, 0, 0][..]] {
            let mut server = empty_kex();
            assert!(server.server_dh(&mut Exchange::new(), payload).is_err());
        }
    }

    #[test]
    fn honest_round_trip_matches() {
        for _ in 0..32 {
            let mut client = empty_kex();
            let mut server = empty_kex();
            let mut eph = CryptoVec::new();
            let mut buf = CryptoVec::new();
            client.client_dh(&mut eph, &mut buf).unwrap();
            assert_eq!(eph.len(), 32);

            let mut exchange = Exchange::new();
            server.server_dh(&mut exchange, &buf).unwrap();
            client
                .compute_shared_secret(&exchange.server_ephemeral)
                .unwrap();
            let c = client.shared_secret.unwrap();
            let s = server.shared_secret.unwrap();
            assert_eq!(c.0, s.0);
            assert_ne!(c.0, [0u8; 32]);
        }
    }
}
