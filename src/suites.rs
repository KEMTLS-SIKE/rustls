use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{CipherSuite, HashAlgorithm, SignatureAlgorithm, SignatureScheme};
use crate::msgs::enums::{NamedGroup, ProtocolVersion};
use crate::msgs::handshake::DecomposedSignatureScheme;
use crate::msgs::handshake::KeyExchangeAlgorithm;
use crate::msgs::handshake::{ClientECDHParams, ServerECDHParams};
use lazy_static;
use std::collections::HashMap;

use std::sync::{Arc, Mutex};

use ring;
use untrusted;

lazy_static! {
    static ref KEYSHARE_CACHE: Arc<Mutex<HashMap<NamedGroup, KeyExchange>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

/// Bulk symmetric encryption scheme used by a cipher suite.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum BulkAlgorithm {
    /// AES with 128-bit keys in Galois counter mode.
    AES_128_GCM,

    /// AES with 256-bit keys in Galois counter mode.
    AES_256_GCM,

    /// Chacha20 for confidentiality with poly1305 for authenticity.
    CHACHA20_POLY1305,
}

/// The result of a key exchange.  This has our public key,
/// and the agreed premaster secret.
pub struct KeyExchangeResult {
    pub ciphertext: Option<ring::agreement::Ciphertext>,
    pub premaster_secret: Vec<u8>,
}

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
#[derive(Clone)]
pub struct KeyExchange {
    pub group: NamedGroup,
    alg: &'static ring::agreement::Algorithm,
    privkey: ring::agreement::EphemeralPrivateKey,
    pub pubkey: ring::agreement::PublicKey,
}

impl KeyExchange {
    pub fn named_group_to_ecdh_alg(
        group: NamedGroup,
    ) -> Option<&'static ring::agreement::Algorithm> {
        match group {
            NamedGroup::X25519 => Some(&ring::agreement::X25519),
            NamedGroup::secp256r1 => Some(&ring::agreement::ECDH_P256),
            NamedGroup::secp384r1 => Some(&ring::agreement::ECDH_P384),
            NamedGroup::CSIDH => Some(&ring::agreement::CSIDH),
            NamedGroup::KYBER512 => Some(&ring::agreement::KYBER512),
            NamedGroup::KYBER768 => Some(&ring::agreement::KYBER768),
            NamedGroup::KYBER1024 => Some(&ring::agreement::KYBER1024),
            NamedGroup::KYBER51290S => Some(&ring::agreement::KYBER51290S),
            NamedGroup::KYBER76890S => Some(&ring::agreement::KYBER76890S),
            NamedGroup::KYBER102490S => Some(&ring::agreement::KYBER102490S),
            NamedGroup::BABYBEAR => Some(&ring::agreement::BABYBEAR),
            NamedGroup::BABYBEAREPHEM => Some(&ring::agreement::BABYBEAREPHEM),
            NamedGroup::MAMABEAR => Some(&ring::agreement::MAMABEAR),
            NamedGroup::MAMABEAREPHEM => Some(&ring::agreement::MAMABEAREPHEM),
            NamedGroup::PAPABEAR => Some(&ring::agreement::PAPABEAR),
            NamedGroup::PAPABEAREPHEM => Some(&ring::agreement::PAPABEAREPHEM),
            NamedGroup::LIGHTSABER => Some(&ring::agreement::LIGHTSABER),
            NamedGroup::SABER => Some(&ring::agreement::SABER),
            NamedGroup::FIRESABER => Some(&ring::agreement::FIRESABER),
            NamedGroup::LEDAKEMLT12 => Some(&ring::agreement::LEDAKEMLT12),
            NamedGroup::LEDAKEMLT32 => Some(&ring::agreement::LEDAKEMLT32),
            NamedGroup::LEDAKEMLT52 => Some(&ring::agreement::LEDAKEMLT52),
            NamedGroup::NEWHOPE512CPA => Some(&ring::agreement::NEWHOPE512CPA),
            NamedGroup::NEWHOPE512CCA => Some(&ring::agreement::NEWHOPE512CCA),
            NamedGroup::NEWHOPE1024CPA => Some(&ring::agreement::NEWHOPE1024CPA),
            NamedGroup::NEWHOPE1024CCA => Some(&ring::agreement::NEWHOPE1024CCA),
            NamedGroup::NTRUHPS2048509 => Some(&ring::agreement::NTRUHPS2048509),
            NamedGroup::NTRUHPS2048677 => Some(&ring::agreement::NTRUHPS2048677),
            NamedGroup::NTRUHPS4096821 => Some(&ring::agreement::NTRUHPS4096821),
            NamedGroup::NTRUHRSS701 => Some(&ring::agreement::NTRUHRSS701),
            NamedGroup::FRODOKEM640AES => Some(&ring::agreement::FRODOKEM640AES),
            NamedGroup::FRODOKEM640SHAKE => Some(&ring::agreement::FRODOKEM640SHAKE),
            NamedGroup::FRODOKEM976AES => Some(&ring::agreement::FRODOKEM976AES),
            NamedGroup::FRODOKEM976SHAKE => Some(&ring::agreement::FRODOKEM976SHAKE),
            NamedGroup::FRODOKEM1344AES => Some(&ring::agreement::FRODOKEM1344AES),
            NamedGroup::FRODOKEM1344SHAKE => Some(&ring::agreement::FRODOKEM1344SHAKE),
            NamedGroup::MCELIECE348864 => Some(&ring::agreement::MCELIECE348864),
            NamedGroup::MCELIECE348864F => Some(&ring::agreement::MCELIECE348864F),
            NamedGroup::MCELIECE460896 => Some(&ring::agreement::MCELIECE460896),
            NamedGroup::MCELIECE460896F => Some(&ring::agreement::MCELIECE460896F),
            NamedGroup::MCELIECE6688128 => Some(&ring::agreement::MCELIECE6688128),
            NamedGroup::MCELIECE6688128F => Some(&ring::agreement::MCELIECE6688128F),
            NamedGroup::MCELIECE6960119 => Some(&ring::agreement::MCELIECE6960119),
            NamedGroup::MCELIECE6960119F => Some(&ring::agreement::MCELIECE6960119F),
            NamedGroup::MCELIECE8192128 => Some(&ring::agreement::MCELIECE8192128),
            NamedGroup::MCELIECE8192128F => Some(&ring::agreement::MCELIECE8192128F),
            NamedGroup::HQC1281CCA2 => Some(&ring::agreement::HQC1281CCA2),
            NamedGroup::HQC1921CCA2 => Some(&ring::agreement::HQC1921CCA2),
            NamedGroup::HQC1922CCA2 => Some(&ring::agreement::HQC1922CCA2),
            NamedGroup::HQC2561CCA2 => Some(&ring::agreement::HQC2561CCA2),
            NamedGroup::HQC2562CCA2 => Some(&ring::agreement::HQC2562CCA2),
            NamedGroup::HQC2563CCA2 => Some(&ring::agreement::HQC2563CCA2),
            NamedGroup::BIKEL1FO => Some(&ring::agreement::BIKEL1FO),
            NamedGroup::SIKEP434COMPRESSED => Some(&ring::agreement::SIKEP434COMPRESSED),
            _ => None,
        }
    }

    pub fn supported_groups() -> &'static [NamedGroup] {
        // in preference order
        &[
            NamedGroup::CSIDH,
            NamedGroup::X25519,
            NamedGroup::secp384r1,
            NamedGroup::secp256r1,
            NamedGroup::KYBER512,
            NamedGroup::KYBER768,
            NamedGroup::KYBER1024,
            NamedGroup::KYBER51290S,
            NamedGroup::KYBER76890S,
            NamedGroup::KYBER102490S,
            NamedGroup::BABYBEAR,
            NamedGroup::BABYBEAREPHEM,
            NamedGroup::MAMABEAR,
            NamedGroup::MAMABEAREPHEM,
            NamedGroup::PAPABEAR,
            NamedGroup::PAPABEAREPHEM,
            NamedGroup::LIGHTSABER,
            NamedGroup::SABER,
            NamedGroup::FIRESABER,
            NamedGroup::LEDAKEMLT12,
            NamedGroup::LEDAKEMLT32,
            NamedGroup::LEDAKEMLT52,
            NamedGroup::NEWHOPE512CPA,
            NamedGroup::NEWHOPE512CCA,
            NamedGroup::NEWHOPE1024CPA,
            NamedGroup::NEWHOPE1024CCA,
            NamedGroup::NTRUHPS2048509,
            NamedGroup::NTRUHPS2048677,
            NamedGroup::NTRUHPS4096821,
            NamedGroup::NTRUHRSS701,
            NamedGroup::FRODOKEM640AES,
            NamedGroup::FRODOKEM640SHAKE,
            NamedGroup::FRODOKEM976AES,
            NamedGroup::FRODOKEM976SHAKE,
            NamedGroup::FRODOKEM1344AES,
            NamedGroup::FRODOKEM1344SHAKE,
            NamedGroup::MCELIECE348864,
            NamedGroup::MCELIECE348864F,
            NamedGroup::MCELIECE460896,
            NamedGroup::MCELIECE460896F,
            NamedGroup::MCELIECE6688128,
            NamedGroup::MCELIECE6688128F,
            NamedGroup::MCELIECE6960119,
            NamedGroup::MCELIECE6960119F,
            NamedGroup::MCELIECE8192128,
            NamedGroup::MCELIECE8192128F,
            NamedGroup::HQC1281CCA2,
            NamedGroup::HQC1921CCA2,
            NamedGroup::HQC1922CCA2,
            NamedGroup::HQC2561CCA2,
            NamedGroup::HQC2562CCA2,
            NamedGroup::HQC2563CCA2,
            NamedGroup::BIKEL1FO,
            NamedGroup::SIKEP434COMPRESSED,
        ]
    }

    pub fn client_ecdhe(kx_params: &[u8]) -> Option<KeyExchangeResult> {
        let mut rd = Reader::init(kx_params);
        let ecdh_params = ServerECDHParams::read(&mut rd)?;

        KeyExchange::start_ecdhe(ecdh_params.curve_params.named_group)?
            .encapsulate(&ecdh_params.public.0)
    }

    pub fn start_ecdhe(named_group: NamedGroup) -> Option<KeyExchange> {
        let mut cache = KEYSHARE_CACHE.lock().unwrap();
        if let Some(keyexchange) = cache.get(&named_group) {
            Some(keyexchange.clone())
        } else {
            let alg = KeyExchange::named_group_to_ecdh_alg(named_group)?;
            let rng = ring::rand::SystemRandom::new();
            let ours = ring::agreement::EphemeralPrivateKey::generate(alg, &rng).unwrap();

            let pubkey = ours.compute_public_key().unwrap();

            let kx = KeyExchange {
                group: named_group,
                alg,
                privkey: ours,
                pubkey,
            };
            cache.insert(named_group, kx.clone());
            Some(kx)
        }
    }

    pub fn check_client_params(&self, kx_params: &[u8]) -> bool {
        self.decode_client_params(kx_params).is_some()
    }

    fn decode_client_params(&self, kx_params: &[u8]) -> Option<ClientECDHParams> {
        let mut rd = Reader::init(kx_params);
        let ecdh_params = ClientECDHParams::read(&mut rd).unwrap();
        if rd.any_left() {
            None
        } else {
            Some(ecdh_params)
        }
    }

    pub fn complete_server(self, kx_params: &[u8]) -> Option<KeyExchangeResult> {
        self.decode_client_params(kx_params)
            .and_then(|x| self.decapsulate(&x.public.0))
    }

    pub fn decapsulate(self, peer_key: &[u8]) -> Option<KeyExchangeResult> {
        let secret =
            ring::agreement::decapsulate(self.privkey, untrusted::Input::from(peer_key), (), |v| {
                let mut r = Vec::new();
                r.extend_from_slice(v);
                Ok(r)
            });
        if secret.is_err() {
            return None;
        }
        Some(KeyExchangeResult {
            ciphertext: None,
            premaster_secret: secret.unwrap(),
        })
    }

    pub fn encapsulate(self, peer: &[u8]) -> Option<KeyExchangeResult> {
        let rng = ring::rand::SystemRandom::new();
        let result =
            ring::agreement::encapsulate(&rng, self.alg, untrusted::Input::from(peer), (), |v| {
                let mut r = Vec::new();
                r.extend_from_slice(v);
                Ok(r)
            });

        if result.is_err() {
            return None;
        }
        let (ct, secret) = result.unwrap();

        Some(KeyExchangeResult {
            ciphertext: Some(ct),
            premaster_secret: secret,
        })
    }
}

/// A cipher suite supported by rustls.
///
/// All possible instances of this class are provided by the library in
/// the `ALL_CIPHERSUITES` array.
#[derive(Debug)]
pub struct SupportedCipherSuite {
    /// The TLS enumeration naming this cipher suite.
    pub suite: CipherSuite,

    /// How to exchange/agree keys.
    pub kx: KeyExchangeAlgorithm,

    /// How to do bulk encryption.
    pub bulk: BulkAlgorithm,

    /// How to do hashing.
    pub hash: HashAlgorithm,

    /// How to sign messages.
    pub sign: SignatureAlgorithm,

    /// Encryption key length, for the bulk algorithm.
    pub enc_key_len: usize,

    /// How long the fixed part of the 'IV' is.
    ///
    /// This isn't usually an IV, but we continue the
    /// terminology misuse to match the standard.
    pub fixed_iv_len: usize,

    /// This is a non-standard extension which extends the
    /// key block to provide an initial explicit nonce offset,
    /// in a deterministic and safe way.  GCM needs this,
    /// chacha20poly1305 works this way by design.
    pub explicit_nonce_len: usize,
}

impl PartialEq for SupportedCipherSuite {
    fn eq(&self, other: &SupportedCipherSuite) -> bool {
        self.suite == other.suite
    }
}

impl SupportedCipherSuite {
    /// Which hash function to use with this suite.
    pub fn get_hash(&self) -> &'static ring::digest::Algorithm {
        match self.hash {
            HashAlgorithm::SHA1 => &ring::digest::SHA1,
            HashAlgorithm::SHA256 => &ring::digest::SHA256,
            HashAlgorithm::SHA384 => &ring::digest::SHA384,
            HashAlgorithm::SHA512 => &ring::digest::SHA512,
            _ => unreachable!(),
        }
    }

    /// We have parameters and a verified public key in `kx_params`.
    /// Generate an ephemeral key, generate the shared secret, and
    /// return it and the public half in a `KeyExchangeResult`.
    pub fn do_client_kx(&self, kx_params: &[u8]) -> Option<KeyExchangeResult> {
        match self.kx {
            KeyExchangeAlgorithm::ECDHE => KeyExchange::client_ecdhe(kx_params),
            _ => None,
        }
    }

    /// Start the KX process with the given group.  This generates
    /// the server's share, but we don't yet have the client's share.
    pub fn start_server_kx(&self, named_group: NamedGroup) -> Option<KeyExchange> {
        match self.kx {
            KeyExchangeAlgorithm::ECDHE => KeyExchange::start_ecdhe(named_group),
            _ => None,
        }
    }

    /// Resolve the set of supported `SignatureScheme`s from the
    /// offered `SupportedSignatureSchemes`.  If we return an empty
    /// set, the handshake terminates.
    pub fn resolve_sig_schemes(&self, offered: &[SignatureScheme]) -> Vec<SignatureScheme> {
        let mut our_preference = vec![
            // Prefer the designated hash algorithm of this suite, for
            // security level consistency.
            SignatureScheme::make(self.sign, self.hash),
            // Then prefer the right sign algorithm, with the best hashes
            // first.
            SignatureScheme::make(self.sign, HashAlgorithm::SHA512),
            SignatureScheme::make(self.sign, HashAlgorithm::SHA384),
            SignatureScheme::make(self.sign, HashAlgorithm::SHA256),
        ];

        // For RSA, support PSS too
        if self.sign == SignatureAlgorithm::RSA {
            our_preference.push(SignatureScheme::RSA_PSS_SHA512);
            our_preference.push(SignatureScheme::RSA_PSS_SHA384);
            our_preference.push(SignatureScheme::RSA_PSS_SHA256);
        }

        our_preference.retain(|pref| offered.contains(pref));
        our_preference
    }

    /// Which AEAD algorithm to use for this suite.
    pub fn get_aead_alg(&self) -> &'static ring::aead::Algorithm {
        match self.bulk {
            BulkAlgorithm::AES_128_GCM => &ring::aead::AES_128_GCM,
            BulkAlgorithm::AES_256_GCM => &ring::aead::AES_256_GCM,
            BulkAlgorithm::CHACHA20_POLY1305 => &ring::aead::CHACHA20_POLY1305,
        }
    }

    /// Length of key block that needs to be output by the key
    /// derivation phase for this suite.
    pub fn key_block_len(&self) -> usize {
        (self.enc_key_len + self.fixed_iv_len) * 2 + self.explicit_nonce_len
    }

    /// Return true if this suite is usable for TLS `version`.
    pub fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        match version {
            ProtocolVersion::TLSv1_3 => self.sign == SignatureAlgorithm::Anonymous,
            ProtocolVersion::TLSv1_2 => self.sign != SignatureAlgorithm::Anonymous,
            _ => false,
        }
    }

    /// Can a session using suite self resume using suite new_suite?
    pub fn can_resume_to(&self, new_suite: &SupportedCipherSuite) -> bool {
        if self.usable_for_version(ProtocolVersion::TLSv1_3)
            && new_suite.usable_for_version(ProtocolVersion::TLSv1_3)
        {
            // TLS1.3 actually specifies requirements here: suites are compatible
            // for resumption if they have the same KDF hash
            self.hash == new_suite.hash
        } else if self.usable_for_version(ProtocolVersion::TLSv1_2)
            && new_suite.usable_for_version(ProtocolVersion::TLSv1_2)
        {
            // Previous versions don't specify any constraint, so we don't
            // resume between suites to avoid bad interactions.
            self.suite == new_suite.suite
        } else {
            // Suites for different versions definitely can't resume!
            false
        }
    }
}

pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: SignatureAlgorithm::ECDSA,
        bulk: BulkAlgorithm::CHACHA20_POLY1305,
        hash: HashAlgorithm::SHA256,
        enc_key_len: 32,
        fixed_iv_len: 12,
        explicit_nonce_len: 0,
    };

pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: SignatureAlgorithm::RSA,
        bulk: BulkAlgorithm::CHACHA20_POLY1305,
        hash: HashAlgorithm::SHA256,
        enc_key_len: 32,
        fixed_iv_len: 12,
        explicit_nonce_len: 0,
    };

pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: SignatureAlgorithm::RSA,
    bulk: BulkAlgorithm::AES_128_GCM,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 16,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
};

pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: SignatureAlgorithm::RSA,
    bulk: BulkAlgorithm::AES_256_GCM,
    hash: HashAlgorithm::SHA384,
    enc_key_len: 32,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
};

pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: SignatureAlgorithm::ECDSA,
    bulk: BulkAlgorithm::AES_128_GCM,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 16,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
};

pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: SignatureAlgorithm::ECDSA,
    bulk: BulkAlgorithm::AES_256_GCM,
    hash: HashAlgorithm::SHA384,
    enc_key_len: 32,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
};

pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    kx: KeyExchangeAlgorithm::BulkOnly,
    sign: SignatureAlgorithm::Anonymous,
    bulk: BulkAlgorithm::CHACHA20_POLY1305,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 32,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
};

pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
    kx: KeyExchangeAlgorithm::BulkOnly,
    sign: SignatureAlgorithm::Anonymous,
    bulk: BulkAlgorithm::AES_256_GCM,
    hash: HashAlgorithm::SHA384,
    enc_key_len: 32,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
};

pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
    kx: KeyExchangeAlgorithm::BulkOnly,
    sign: SignatureAlgorithm::Anonymous,
    bulk: BulkAlgorithm::AES_128_GCM,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 16,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
};

/// A list of all the cipher suites supported by rustls.
pub static ALL_CIPHERSUITES: [&'static SupportedCipherSuite; 9] = [
    // TLS1.3 suites
    &TLS13_CHACHA20_POLY1305_SHA256,
    &TLS13_AES_256_GCM_SHA384,
    &TLS13_AES_128_GCM_SHA256,
    // TLS1.2 suites
    &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

// These both O(N^2)!
pub fn choose_ciphersuite_preferring_client(
    client_suites: &[CipherSuite],
    server_suites: &[&'static SupportedCipherSuite],
) -> Option<&'static SupportedCipherSuite> {
    for client_suite in client_suites {
        if let Some(selected) = server_suites.iter().find(|x| *client_suite == x.suite) {
            return Some(*selected);
        }
    }

    None
}

pub fn choose_ciphersuite_preferring_server(
    client_suites: &[CipherSuite],
    server_suites: &[&'static SupportedCipherSuite],
) -> Option<&'static SupportedCipherSuite> {
    if let Some(selected) = server_suites
        .iter()
        .find(|x| client_suites.contains(&x.suite))
    {
        return Some(*selected);
    }

    None
}

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with `SignatureAlgorithm` `sigalg` removed.
pub fn reduce_given_sigalg(
    all: &[&'static SupportedCipherSuite],
    sigalg: &SignatureAlgorithm,
) -> Vec<&'static SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.sign == SignatureAlgorithm::Anonymous || &suite.sign == sigalg)
        .cloned()
        .collect()
}

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with the chosen `version` removed.
pub fn reduce_given_version(
    all: &[&'static SupportedCipherSuite],
    version: ProtocolVersion,
) -> Vec<&'static SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.usable_for_version(version))
        .cloned()
        .collect()
}

#[cfg(test)]
mod test {
    use crate::msgs::enums::CipherSuite;

    #[test]
    fn test_client_pref() {
        let client = vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];
        let server = vec![
            &super::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ];
        let chosen = super::choose_ciphersuite_preferring_client(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(
            chosen.unwrap(),
            &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        );
    }

    #[test]
    fn test_server_pref() {
        let client = vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];
        let server = vec![
            &super::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ];
        let chosen = super::choose_ciphersuite_preferring_server(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(
            chosen.unwrap(),
            &super::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        );
    }
}
