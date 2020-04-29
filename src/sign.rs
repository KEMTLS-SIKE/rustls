use crate::error::TLSError;
use crate::key;
use crate::msgs::enums::{SignatureAlgorithm, SignatureScheme};
use crate::util;
use crate::log::debug;

use untrusted;

use ring::{
    self,
    signature::{self, EcdsaKeyPair, PQSecretKey, RsaKeyPair},
};
use webpki;

use std::mem;
use std::sync::Arc;

/// An abstract signing key.
pub trait SigningKey: Send + Sync {
    /// Choose a `SignatureScheme` from those offered.
    ///
    /// Expresses the choice something that implements `Signer`,
    /// using the chosen scheme.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>>;

    /// What kind of key we have.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// Gets the key, hack for kems
    fn get_key(&self) -> &[u8] {
        panic!("not implemented SigningKey::get_key");
    }
}

/// A thing that can sign a message.
pub trait Signer: Send + Sync {
    /// Signs `message` using the selected scheme.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TLSError>;

    /// Reveals which scheme will be used when you call `sign()`.
    fn get_scheme(&self) -> SignatureScheme;
}

/// A packaged-together certificate chain, matching `SigningKey` and
/// optional stapled OCSP response and/or SCT.
#[derive(Clone)]
pub struct CertifiedKey {
    /// The certificate chain.
    pub cert: Vec<key::Certificate>,

    /// The certified key.
    pub key: Arc<Box<dyn SigningKey>>,

    /// An optional OCSP response from the certificate issuer,
    /// attesting to its continued validity.
    pub ocsp: Option<Vec<u8>>,

    /// An optional collection of SCTs from CT logs, proving the
    /// certificate is included on those logs.  This must be
    /// a `SignedCertificateTimestampList` encoding; see RFC6962.
    pub sct_list: Option<Vec<u8>>,
}

impl CertifiedKey {
    /// Make a new CertifiedKey, with the given chain and key.
    ///
    /// The cert chain must not be empty. The first certificate in the chain
    /// must be the end-entity certificate.
    pub fn new(cert: Vec<key::Certificate>, key: Arc<Box<dyn SigningKey>>) -> CertifiedKey {
        CertifiedKey {
            cert,
            key,
            ocsp: None,
            sct_list: None,
        }
    }

    /// The end-entity certificate.
    pub fn end_entity_cert(&self) -> Result<&key::Certificate, ()> {
        self.cert.get(0).ok_or(())
    }

    /// Steal ownership of the certificate chain.
    pub fn take_cert(&mut self) -> Vec<key::Certificate> {
        mem::replace(&mut self.cert, Vec::new())
    }

    /// Return true if there's an OCSP response.
    pub fn has_ocsp(&self) -> bool {
        self.ocsp.is_some()
    }

    /// Steal ownership of the OCSP response.
    pub fn take_ocsp(&mut self) -> Option<Vec<u8>> {
        mem::replace(&mut self.ocsp, None)
    }

    /// Return true if there's an SCT list.
    pub fn has_sct_list(&self) -> bool {
        self.sct_list.is_some()
    }

    /// Steal ownership of the SCT list.
    pub fn take_sct_list(&mut self) -> Option<Vec<u8>> {
        mem::replace(&mut self.sct_list, None)
    }

    /// Check the certificate chain for validity:
    /// - it should be non-empty list
    /// - the first certificate should be parsable as a x509v3,
    /// - the first certificate should quote the given server name
    ///   (if provided)
    ///
    /// These checks are not security-sensitive.  They are the
    /// *server* attempting to detect accidental misconfiguration.
    pub fn cross_check_end_entity_cert(
        &self,
        name: Option<webpki::DNSNameRef>,
    ) -> Result<(), TLSError> {
        // Always reject an empty certificate chain.
        let end_entity_cert = self.end_entity_cert().map_err(|()| {
            TLSError::General("No end-entity certificate in certificate chain".to_string())
        })?;

        // Reject syntactically-invalid end-entity certificates.
        let end_entity_cert = webpki::EndEntityCert::from(untrusted::Input::from(
            end_entity_cert.as_ref(),
        ))
        .map_err(|_| {
            TLSError::General(
                "End-entity certificate in certificate \
                                  chain is syntactically invalid"
                    .to_string(),
            )
        })?;

        if let Some(name) = name {
            // If SNI was offered then the certificate must be valid for
            // that hostname. Note that this doesn't fully validate that the
            // certificate is valid; it only validates that the name is one
            // that the certificate is valid for, if the certificate is
            // valid.
            if end_entity_cert.verify_is_valid_for_dns_name(name).is_err() {
                return Err(TLSError::General(
                    "The server certificate is not \
                                             valid for the given name"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }

    /// fetch it as webpki cert
    pub fn get_as_webpki_cert(&self) -> Result<webpki::EndEntityCert, TLSError> {
        // Always reject an empty certificate chain.
        let end_entity_cert = self.end_entity_cert().map_err(|()| {
            TLSError::General("No end-entity certificate in certificate chain".to_string())
        })?;

        // Reject syntactically-invalid end-entity certificates.
        Ok(
            webpki::EndEntityCert::from(untrusted::Input::from(end_entity_cert.as_ref())).map_err(
                |_| {
                    TLSError::General(
                        "End-entity certificate in certificate \
                                  chain is syntactically invalid"
                            .to_string(),
                    )
                },
            )?,
        )
    }
}

/// Parse `der` as any supported key encoding/type, returning
/// the first which works.
pub fn any_supported_type(der: &key::PrivateKey) -> Result<Box<dyn SigningKey>, ()> {
    if let Ok(rsa) = RSASigningKey::new(der) {
        return Ok(Box::new(rsa));
    }

    any_ecdsa_type(der).or_else(|_| any_pq_type(der))
}

/// Parse `der` as any ECDSA key type, returning the first which works.
pub fn any_ecdsa_type(der: &key::PrivateKey) -> Result<Box<dyn SigningKey>, ()> {
    if let Ok(ecdsa_p256) = SingleSchemeSigningKey::new(
        der,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
    ) {
        return Ok(Box::new(ecdsa_p256));
    }

    if let Ok(ecdsa_p384) = SingleSchemeSigningKey::new(
        der,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
    ) {
        return Ok(Box::new(ecdsa_p384));
    }

    Err(())
}

/// Parse `der` as any PQ signature scheme
pub fn any_pq_type(der: &key::PrivateKey) -> Result<Box<dyn SigningKey>, ()> {
    let options = [
        (SignatureScheme::DILITHIUM2, &signature::DILITHIUM2),
        (SignatureScheme::FALCON512, &signature::FALCON512),
        (SignatureScheme::RAINBOW_IA_CYCLIC, &signature::RAINBOW_IA_CYCLIC),
        (SignatureScheme::XMSS, &signature::XMSS),
        (SignatureScheme::GEMSS128, &signature::GEMSS128),
        (SignatureScheme::DILITHIUM3, &signature::DILITHIUM3),
        (SignatureScheme::DILITHIUM4, &signature::DILITHIUM4),
        (SignatureScheme::FALCON1024, &signature::FALCON1024),
        (SignatureScheme::MQDSS3148, &signature::MQDSS3148),
        (SignatureScheme::MQDSS3164, &signature::MQDSS3164),
        (SignatureScheme::RAINBOW_IA_CLASSIC, &signature::RAINBOW_IA_CLASSIC),
        (SignatureScheme::RAINBOW_IA_CYCLIC_COMPRESSED, &signature::RAINBOW_IA_CYCLIC_COMPRESSED),
        (SignatureScheme::RAINBOW_II_ICCLASSIC, &signature::RAINBOW_II_ICCLASSIC),
        (SignatureScheme::RAINBOW_II_IC_CYCLIC, &signature::RAINBOW_II_IC_CYCLIC),
        (SignatureScheme::RAINBOW_II_IC_CYCLIC_COMPRESSED, &signature::RAINBOW_II_IC_CYCLIC_COMPRESSED),
        (SignatureScheme::RAINBOW_VC_CLASSIC, &signature::RAINBOW_VC_CLASSIC),
        (SignatureScheme::RAINBOW_VC_CYCLIC, &signature::RAINBOW_VC_CYCLIC),
        (SignatureScheme::RAINBOW_VC_CYCLIC_COMPRESSED, &signature::RAINBOW_VC_CYCLIC_COMPRESSED),
        (SignatureScheme::SPHINCS_HARAKA128F_ROBUST, &signature::SPHINCS_HARAKA128F_ROBUST),
        (SignatureScheme::SPHINCS_HARAKA128F_SIMPLE, &signature::SPHINCS_HARAKA128F_SIMPLE),
        (SignatureScheme::SPHINCS_HARAKA128S_ROBUST, &signature::SPHINCS_HARAKA128S_ROBUST),
        (SignatureScheme::SPHINCS_HARAKA128S_SIMPLE, &signature::SPHINCS_HARAKA128S_SIMPLE),
        (SignatureScheme::SPHINCS_HARAKA192F_ROBUST, &signature::SPHINCS_HARAKA192F_ROBUST),
        (SignatureScheme::SPHINCS_HARAKA192F_SIMPLE, &signature::SPHINCS_HARAKA192F_SIMPLE),
        (SignatureScheme::SPHINCS_HARAKA192S_ROBUST, &signature::SPHINCS_HARAKA192S_ROBUST),
        (SignatureScheme::SPHINCS_HARAKA192S_SIMPLE, &signature::SPHINCS_HARAKA192S_SIMPLE),
        (SignatureScheme::SPHINCS_HARAKA256F_ROBUST, &signature::SPHINCS_HARAKA256F_ROBUST),
        (SignatureScheme::SPHINCS_HARAKA256F_SIMPLE, &signature::SPHINCS_HARAKA256F_SIMPLE),
        (SignatureScheme::SPHINCS_HARAKA256S_ROBUST, &signature::SPHINCS_HARAKA256S_ROBUST),
        (SignatureScheme::SPHINCS_HARAKA256S_SIMPLE, &signature::SPHINCS_HARAKA256S_SIMPLE),
        (SignatureScheme::SPHINCS_SHA256128F_ROBUST, &signature::SPHINCS_SHA256128F_ROBUST),
        (SignatureScheme::SPHINCS_SHA256128F_SIMPLE, &signature::SPHINCS_SHA256128F_SIMPLE),
        (SignatureScheme::SPHINCS_SHA256128S_ROBUST, &signature::SPHINCS_SHA256128S_ROBUST),
        (SignatureScheme::SPHINCS_SHA256128S_SIMPLE, &signature::SPHINCS_SHA256128S_SIMPLE),
        (SignatureScheme::SPHINCS_SHA256192F_ROBUST, &signature::SPHINCS_SHA256192F_ROBUST),
        (SignatureScheme::SPHINCS_SHA256192F_SIMPLE, &signature::SPHINCS_SHA256192F_SIMPLE),
        (SignatureScheme::SPHINCS_SHA256192S_ROBUST, &signature::SPHINCS_SHA256192S_ROBUST),
        (SignatureScheme::SPHINCS_SHA256192S_SIMPLE, &signature::SPHINCS_SHA256192S_SIMPLE),
        (SignatureScheme::SPHINCS_SHA256256F_ROBUST, &signature::SPHINCS_SHA256256F_ROBUST),
        (SignatureScheme::SPHINCS_SHA256256F_SIMPLE, &signature::SPHINCS_SHA256256F_SIMPLE),
        (SignatureScheme::SPHINCS_SHA256256S_ROBUST, &signature::SPHINCS_SHA256256S_ROBUST),
        (SignatureScheme::SPHINCS_SHA256256S_SIMPLE, &signature::SPHINCS_SHA256256S_SIMPLE),
        (SignatureScheme::SPHINCS_SHAKE256128F_ROBUST, &signature::SPHINCS_SHAKE256128F_ROBUST),
        (SignatureScheme::SPHINCS_SHAKE256128F_SIMPLE, &signature::SPHINCS_SHAKE256128F_SIMPLE),
        (SignatureScheme::SPHINCS_SHAKE256128S_ROBUST, &signature::SPHINCS_SHAKE256128S_ROBUST),
        (SignatureScheme::SPHINCS_SHAKE256128S_SIMPLE, &signature::SPHINCS_SHAKE256128S_SIMPLE),
        (SignatureScheme::SPHINCS_SHAKE256192F_ROBUST, &signature::SPHINCS_SHAKE256192F_ROBUST),
        (SignatureScheme::SPHINCS_SHAKE256192F_SIMPLE, &signature::SPHINCS_SHAKE256192F_SIMPLE),
        (SignatureScheme::SPHINCS_SHAKE256192S_ROBUST, &signature::SPHINCS_SHAKE256192S_ROBUST),
        (SignatureScheme::SPHINCS_SHAKE256192S_SIMPLE, &signature::SPHINCS_SHAKE256192S_SIMPLE),
        (SignatureScheme::SPHINCS_SHAKE256256F_ROBUST, &signature::SPHINCS_SHAKE256256F_ROBUST),
        (SignatureScheme::SPHINCS_SHAKE256256F_SIMPLE, &signature::SPHINCS_SHAKE256256F_SIMPLE),
        (SignatureScheme::SPHINCS_SHAKE256256S_ROBUST, &signature::SPHINCS_SHAKE256256S_ROBUST),
        (SignatureScheme::SPHINCS_SHAKE256256S_SIMPLE, &signature::SPHINCS_SHAKE256256S_SIMPLE),
        (SignatureScheme::PICNIC_L1_FS, &signature::PICNIC_L1_FS),
        (SignatureScheme::PICNIC_L1_UR, &signature::PICNIC_L1_UR),
        (SignatureScheme::PICNIC_L3_FS, &signature::PICNIC_L3_FS),
        (SignatureScheme::PICNIC_L3_UR, &signature::PICNIC_L3_UR),
        (SignatureScheme::PICNIC_L5_FS, &signature::PICNIC_L5_FS),
        (SignatureScheme::PICNIC_L5_UR, &signature::PICNIC_L5_UR),
        (SignatureScheme::PICNIC2_L1_FS, &signature::PICNIC2_L1_FS),
        (SignatureScheme::PICNIC2_L3_FS, &signature::PICNIC2_L3_FS),
        (SignatureScheme::PICNIC2_L5_FS, &signature::PICNIC2_L5_FS),
        (SignatureScheme::Q_TESLA_PI, &signature::Q_TESLA_PI),
        (SignatureScheme::Q_TESLA_PIII, &signature::Q_TESLA_PIII),
        ];
    for (scheme, alg) in options.iter() {
        if let Ok(scheme) = PQSchemeSigner::new(der, *scheme, alg) {
            debug!("Found {:?}", alg);
            return Ok(Box::new(scheme));
        }
    }

    Ok(Box::new(PQKemSigner::new(der).unwrap()))

    //Err(())
}

/// A `SigningKey` for RSA-PKCS1 or RSA-PSS
pub struct RSASigningKey {
    key: Arc<RsaKeyPair>,
}

static ALL_RSA_SCHEMES: &'static [SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

impl RSASigningKey {
    /// Make a new `RSASigningKey` from a DER encoding, in either
    /// PKCS#1 or PKCS#8 format.
    pub fn new(der: &key::PrivateKey) -> Result<RSASigningKey, ()> {
        RsaKeyPair::from_der(untrusted::Input::from(&der.0))
            .or_else(|_| RsaKeyPair::from_pkcs8(untrusted::Input::from(&der.0)))
            .map(|s| RSASigningKey { key: Arc::new(s) })
            .map_err(|_| ())
    }
}

impl SigningKey for RSASigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        util::first_in_both(ALL_RSA_SCHEMES, offered)
            .map(|scheme| RSASigner::new(self.key.clone(), scheme))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

struct RSASigner {
    key: Arc<RsaKeyPair>,
    scheme: SignatureScheme,
    encoding: &'static dyn signature::RsaEncoding,
}

impl RSASigner {
    fn new(key: Arc<RsaKeyPair>, scheme: SignatureScheme) -> Box<dyn Signer> {
        let encoding: &dyn signature::RsaEncoding = match scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => &signature::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => &signature::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => &signature::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256 => &signature::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => &signature::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => &signature::RSA_PSS_SHA512,
            _ => unreachable!(),
        };

        Box::new(RSASigner {
            key,
            scheme,
            encoding,
        })
    }
}

impl Signer for RSASigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TLSError> {
        let mut sig = vec![0; self.key.public_modulus_len()];

        let rng = ring::rand::SystemRandom::new();
        self.key
            .sign(self.encoding, &rng, message, &mut sig)
            .map(|_| sig)
            .map_err(|_| TLSError::General("signing failed".to_string()))
    }

    fn get_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// A SigningKey that uses exactly one TLS-level SignatureScheme
/// and one ring-level signature::SigningAlgorithm.
///
/// Compare this to RSASigningKey, which for a particular key is
/// willing to sign with several algorithms.  This is quite poor
/// cryptography practice, but is necessary because a given RSA key
/// is expected to work in TLS1.2 (PKCS#1 signatures) and TLS1.3
/// (PSS signatures) -- nobody is willing to obtain certificates for
/// different protocol versions.
///
/// Currently this is only implemented for ECDSA keys.
struct SingleSchemeSigningKey {
    key: Arc<EcdsaKeyPair>,
    scheme: SignatureScheme,
}

impl SingleSchemeSigningKey {
    /// Make a new `ECDSASigningKey` from a DER encoding in PKCS#8 format,
    /// expecting a key usable with precisely the given signature scheme.
    pub fn new(
        der: &key::PrivateKey,
        scheme: SignatureScheme,
        sigalg: &'static signature::EcdsaSigningAlgorithm,
    ) -> Result<SingleSchemeSigningKey, ()> {
        EcdsaKeyPair::from_pkcs8(sigalg, untrusted::Input::from(&der.0))
            .map(|kp| SingleSchemeSigningKey {
                key: Arc::new(kp),
                scheme,
            })
            .map_err(|_| ())
    }
}

impl SigningKey for SingleSchemeSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(SingleSchemeSigner {
                key: self.key.clone(),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        use crate::msgs::handshake::DecomposedSignatureScheme;
        self.scheme.sign()
    }
}

struct SingleSchemeSigner {
    key: Arc<EcdsaKeyPair>,
    scheme: SignatureScheme,
}

impl Signer for SingleSchemeSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TLSError> {
        let rng = ring::rand::SystemRandom::new();
        self.key
            .sign(&rng, untrusted::Input::from(message))
            .map_err(|_| TLSError::General("signing failed".into()))
            .map(|sig| sig.as_ref().into())
    }

    fn get_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Clone)]
struct PQSchemeSigner {
    key: Arc<PQSecretKey>,
    scheme: SignatureScheme,
}

impl PQSchemeSigner {
    fn new(
        der: &key::PrivateKey,
        scheme: SignatureScheme,
        sigalg: &'static signature::PQSignatureScheme,
    ) -> Result<PQSchemeSigner, ()> {
        PQSecretKey::from_pkcs8(sigalg, untrusted::Input::from(&der.0))
            .map(|kp| PQSchemeSigner {
                key: Arc::new(kp),
                scheme,
            })
            .map_err(|_| ())
    }
}

impl SigningKey for PQSchemeSigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        use crate::msgs::handshake::DecomposedSignatureScheme;
        self.scheme.sign()
    }
}

impl Signer for PQSchemeSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TLSError> {
        self.key
            .sign(untrusted::Input::from(message))
            .map_err(|_| TLSError::General("signing failed".into()))
            .map(|sig| sig.as_ref().into())
    }

    fn get_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Clone)]
struct PQKemSigner {
    key: Arc<Vec<u8>>,
}

impl PQKemSigner {
    fn new(der: &key::PrivateKey) -> Result<Self, ()> {
        Ok(PQKemSigner {
            key: Arc::new(der.0.to_vec()),
        })
    }
}

impl SigningKey for PQKemSigner {
    fn choose_scheme(&self, _: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        panic!("Not implemented");
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }

    fn get_key(&self) -> &[u8] {
        &self.key
    }
}

/// The set of schemes we support for signatures and
/// that are allowed for TLS1.3.
pub fn supported_sign_tls13() -> &'static [SignatureScheme] {
    &[
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::DILITHIUM2,
        SignatureScheme::DILITHIUM3,
        SignatureScheme::DILITHIUM4,
        SignatureScheme::FALCON512,
        SignatureScheme::FALCON1024,
        SignatureScheme::MQDSS3148,
        SignatureScheme::MQDSS3164,
        SignatureScheme::RAINBOW_IA_CLASSIC,
        SignatureScheme::RAINBOW_IA_CYCLIC,
        SignatureScheme::RAINBOW_IA_CYCLIC_COMPRESSED,
        SignatureScheme::RAINBOW_II_ICCLASSIC,
        SignatureScheme::RAINBOW_II_IC_CYCLIC,
        SignatureScheme::RAINBOW_II_IC_CYCLIC_COMPRESSED,
        SignatureScheme::RAINBOW_VC_CLASSIC,
        SignatureScheme::RAINBOW_VC_CYCLIC,
        SignatureScheme::RAINBOW_VC_CYCLIC_COMPRESSED,
        SignatureScheme::SPHINCS_HARAKA128F_ROBUST,
        SignatureScheme::SPHINCS_HARAKA128F_SIMPLE,
        SignatureScheme::SPHINCS_HARAKA128S_ROBUST,
        SignatureScheme::SPHINCS_HARAKA128S_SIMPLE,
        SignatureScheme::SPHINCS_HARAKA192F_ROBUST,
        SignatureScheme::SPHINCS_HARAKA192F_SIMPLE,
        SignatureScheme::SPHINCS_HARAKA192S_ROBUST,
        SignatureScheme::SPHINCS_HARAKA192S_SIMPLE,
        SignatureScheme::SPHINCS_HARAKA256F_ROBUST,
        SignatureScheme::SPHINCS_HARAKA256F_SIMPLE,
        SignatureScheme::SPHINCS_HARAKA256S_ROBUST,
        SignatureScheme::SPHINCS_HARAKA256S_SIMPLE,
        SignatureScheme::SPHINCS_SHA256128F_ROBUST,
        SignatureScheme::SPHINCS_SHA256128F_SIMPLE,
        SignatureScheme::SPHINCS_SHA256128S_ROBUST,
        SignatureScheme::SPHINCS_SHA256128S_SIMPLE,
        SignatureScheme::SPHINCS_SHA256192F_ROBUST,
        SignatureScheme::SPHINCS_SHA256192F_SIMPLE,
        SignatureScheme::SPHINCS_SHA256192S_ROBUST,
        SignatureScheme::SPHINCS_SHA256192S_SIMPLE,
        SignatureScheme::SPHINCS_SHA256256F_ROBUST,
        SignatureScheme::SPHINCS_SHA256256F_SIMPLE,
        SignatureScheme::SPHINCS_SHA256256S_ROBUST,
        SignatureScheme::SPHINCS_SHA256256S_SIMPLE,
        SignatureScheme::SPHINCS_SHAKE256128F_ROBUST,
        SignatureScheme::SPHINCS_SHAKE256128F_SIMPLE,
        SignatureScheme::SPHINCS_SHAKE256128S_ROBUST,
        SignatureScheme::SPHINCS_SHAKE256128S_SIMPLE,
        SignatureScheme::SPHINCS_SHAKE256192F_ROBUST,
        SignatureScheme::SPHINCS_SHAKE256192F_SIMPLE,
        SignatureScheme::SPHINCS_SHAKE256192S_ROBUST,
        SignatureScheme::SPHINCS_SHAKE256192S_SIMPLE,
        SignatureScheme::SPHINCS_SHAKE256256F_ROBUST,
        SignatureScheme::SPHINCS_SHAKE256256F_SIMPLE,
        SignatureScheme::SPHINCS_SHAKE256256S_ROBUST,
        SignatureScheme::SPHINCS_SHAKE256256S_SIMPLE,
        SignatureScheme::PICNIC_L1_FS,
        SignatureScheme::PICNIC_L1_UR,
        SignatureScheme::PICNIC_L3_FS,
        SignatureScheme::PICNIC_L3_UR,
        SignatureScheme::PICNIC_L5_FS,
        SignatureScheme::PICNIC_L5_UR,
        SignatureScheme::PICNIC2_L1_FS,
        SignatureScheme::PICNIC2_L3_FS,
        SignatureScheme::PICNIC2_L5_FS,
        SignatureScheme::Q_TESLA_PI,
        SignatureScheme::Q_TESLA_PIII,
        SignatureScheme::XMSS,
        SignatureScheme::GEMSS128,
    ]
}
