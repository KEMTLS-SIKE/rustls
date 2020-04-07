use sct;
use std;
use std::sync::Arc;
use untrusted;
use webpki;

use crate::anchors::{DistinguishedNames, RootCertStore};
use crate::error::TLSError;
use crate::key::Certificate;
#[cfg(feature = "logging")]
use crate::log::{debug, warn};
use crate::msgs::enums::SignatureScheme;
use crate::msgs::handshake::DigitallySignedStruct;
use crate::msgs::handshake::SCTList;
use crate::suites;

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

/// Which signature verification mechanisms we support.  No particular
/// order.
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::DILITHIUM2,
    &webpki::DILITHIUM3,
    &webpki::DILITHIUM4,
    &webpki::FALCON512,
    &webpki::FALCON1024,
    &webpki::MQDSS3148,
    &webpki::MQDSS3164,
    &webpki::RAINBOW_IA_CLASSIC,
    &webpki::RAINBOW_IA_CYCLIC,
    &webpki::RAINBOW_IA_CYCLIC_COMPRESSED,
    &webpki::RAINBOW_II_ICCLASSIC,
    &webpki::RAINBOW_II_IC_CYCLIC,
    &webpki::RAINBOW_II_IC_CYCLIC_COMPRESSED,
    &webpki::RAINBOW_VC_CLASSIC,
    &webpki::RAINBOW_VC_CYCLIC,
    &webpki::RAINBOW_VC_CYCLIC_COMPRESSED,
    &webpki::SPHINCS_HARAKA128F_ROBUST,
    &webpki::SPHINCS_HARAKA128F_SIMPLE,
    &webpki::SPHINCS_HARAKA128S_ROBUST,
    &webpki::SPHINCS_HARAKA128S_SIMPLE,
    &webpki::SPHINCS_HARAKA192F_ROBUST,
    &webpki::SPHINCS_HARAKA192F_SIMPLE,
    &webpki::SPHINCS_HARAKA192S_ROBUST,
    &webpki::SPHINCS_HARAKA192S_SIMPLE,
    &webpki::SPHINCS_HARAKA256F_ROBUST,
    &webpki::SPHINCS_HARAKA256F_SIMPLE,
    &webpki::SPHINCS_HARAKA256S_ROBUST,
    &webpki::SPHINCS_HARAKA256S_SIMPLE,
    &webpki::SPHINCS_SHA256128F_ROBUST,
    &webpki::SPHINCS_SHA256128F_SIMPLE,
    &webpki::SPHINCS_SHA256128S_ROBUST,
    &webpki::SPHINCS_SHA256128S_SIMPLE,
    &webpki::SPHINCS_SHA256192F_ROBUST,
    &webpki::SPHINCS_SHA256192F_SIMPLE,
    &webpki::SPHINCS_SHA256192S_ROBUST,
    &webpki::SPHINCS_SHA256192S_SIMPLE,
    &webpki::SPHINCS_SHA256256F_ROBUST,
    &webpki::SPHINCS_SHA256256F_SIMPLE,
    &webpki::SPHINCS_SHA256256S_ROBUST,
    &webpki::SPHINCS_SHA256256S_SIMPLE,
    &webpki::SPHINCS_SHAKE256128F_ROBUST,
    &webpki::SPHINCS_SHAKE256128F_SIMPLE,
    &webpki::SPHINCS_SHAKE256128S_ROBUST,
    &webpki::SPHINCS_SHAKE256128S_SIMPLE,
    &webpki::SPHINCS_SHAKE256192F_ROBUST,
    &webpki::SPHINCS_SHAKE256192F_SIMPLE,
    &webpki::SPHINCS_SHAKE256192S_ROBUST,
    &webpki::SPHINCS_SHAKE256192S_SIMPLE,
    &webpki::SPHINCS_SHAKE256256F_ROBUST,
    &webpki::SPHINCS_SHAKE256256F_SIMPLE,
    &webpki::SPHINCS_SHAKE256256S_ROBUST,
    &webpki::SPHINCS_SHAKE256256S_SIMPLE,
    &webpki::PICNIC_L1_FS,
    &webpki::PICNIC_L1_UR,
    &webpki::PICNIC_L3_FS,
    &webpki::PICNIC_L3_UR,
    &webpki::PICNIC_L5_FS,
    &webpki::PICNIC_L5_UR,
    &webpki::PICNIC2_L1_FS,
    &webpki::PICNIC2_L3_FS,
    &webpki::PICNIC2_L5_FS,
    &webpki::Q_TESLA_PI,
    &webpki::Q_TESLA_PIII,
];

/// Marker types.  These are used to bind the fact some verification
/// (certificate chain or handshake signature) has taken place into
/// protocol states.  We use this to have the compiler check that there
/// are no 'goto fail'-style elisions of important checks before we
/// reach the traffic stage.
///
/// These types are public, but cannot be directly constructed.  This
/// means their origins can be precisely determined by looking
/// for their `assertion` constructors.
pub struct HandshakeSignatureValid(());
impl HandshakeSignatureValid {
    pub fn assertion() -> Self {
        Self { 0: () }
    }
}

pub struct FinishedMessageVerified(());
impl FinishedMessageVerified {
    pub fn assertion() -> Self {
        Self { 0: () }
    }
}

/// Zero-sized marker type representing verification of a server cert chain.
pub struct ServerCertVerified(());
impl ServerCertVerified {
    /// Make a `ServerCertVerified`
    pub fn assertion() -> Self {
        Self { 0: () }
    }
}

/// Zero-sized marker type representing verification of a client cert chain.
pub struct ClientCertVerified(());
impl ClientCertVerified {
    /// Make a `ClientCertVerified`
    pub fn assertion() -> Self {
        Self { 0: () }
    }
}

/// Something that can verify a server certificate chain
pub trait ServerCertVerifier: Send + Sync {
    /// Verify a the certificate chain `presented_certs` against the roots
    /// configured in `roots`.  Make sure that `dns_name` is quoted by
    /// the top certificate in the chain.
    fn verify_server_cert(
        &self,
        roots: &RootCertStore,
        presented_certs: &[Certificate],
        dns_name: webpki::DNSNameRef,
        ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError>;
}

/// Something that can verify a client certificate chain
pub trait ClientCertVerifier: Send + Sync {
    /// Returns `true` to enable the server to request a client certificate and
    /// `false` to skip requesting a client certificate. Defaults to `true`.
    fn offer_client_auth(&self) -> bool {
        true
    }

    /// Returns `true` to require a client certificate and `false` to make client
    /// authentication optional. Defaults to `self.offer_client_auth()`.
    fn client_auth_mandatory(&self) -> bool {
        self.offer_client_auth()
    }

    /// Returns the subject names of the client authentication trust anchors to
    /// share with the client when requesting client authentication.
    fn client_auth_root_subjects(&self) -> DistinguishedNames;

    /// Verify a certificate chain `presented_certs` is rooted in `roots`.
    /// Does no further checking of the certificate.
    fn verify_client_cert(
        &self,
        presented_certs: &[Certificate],
    ) -> Result<ClientCertVerified, TLSError>;
}

pub struct WebPKIVerifier {
    pub time: fn() -> Result<webpki::Time, TLSError>,
}

impl ServerCertVerifier for WebPKIVerifier {
    fn verify_server_cert(
        &self,
        roots: &RootCertStore,
        presented_certs: &[Certificate],
        dns_name: webpki::DNSNameRef,
        ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        let (cert, chain, trustroots) = prepare(roots, presented_certs)?;
        let now = (self.time)()?;
        let cert = cert
            .verify_is_valid_tls_server_cert(
                SUPPORTED_SIG_ALGS,
                &webpki::TLSServerTrustAnchors(&trustroots),
                &chain,
                now,
            )
            .map_err(TLSError::WebPKIError)
            .map(|_| cert)?;

        if !ocsp_response.is_empty() {
            debug!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        cert.verify_is_valid_for_dns_name(dns_name)
            .map_err(TLSError::WebPKIError)
            .map(|_| ServerCertVerified::assertion())
    }
}

impl WebPKIVerifier {
    pub fn new() -> WebPKIVerifier {
        WebPKIVerifier { time: try_now }
    }
}

fn prepare<'a, 'b>(
    roots: &'b RootCertStore,
    presented_certs: &'a [Certificate],
) -> Result<
    (
        webpki::EndEntityCert<'a>,
        Vec<untrusted::Input<'a>>,
        Vec<webpki::TrustAnchor<'b>>,
    ),
    TLSError,
> {
    if presented_certs.is_empty() {
        return Err(TLSError::NoCertificatesPresented);
    }

    // EE cert must appear first.
    let cert_der = untrusted::Input::from(&presented_certs[0].0);
    let cert = webpki::EndEntityCert::from(cert_der).map_err(TLSError::WebPKIError)?;

    let chain: Vec<untrusted::Input> = presented_certs
        .iter()
        .skip(1)
        .map(|cert| untrusted::Input::from(&cert.0))
        .collect();

    let trustroots: Vec<webpki::TrustAnchor> =
        roots.roots.iter().map(|x| x.to_trust_anchor()).collect();

    Ok((cert, chain, trustroots))
}

fn try_now() -> Result<webpki::Time, TLSError> {
    webpki::Time::try_from(std::time::SystemTime::now())
        .map_err(|_| TLSError::FailedToGetCurrentTime)
}

/// A `ClientCertVerifier` that will ensure that every client provides a trusted
/// certificate, without any name checking.
pub struct AllowAnyAuthenticatedClient {
    roots: RootCertStore,
}

impl AllowAnyAuthenticatedClient {
    /// Construct a new `AllowAnyAuthenticatedClient`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    pub fn new(roots: RootCertStore) -> Arc<dyn ClientCertVerifier> {
        Arc::new(AllowAnyAuthenticatedClient { roots })
    }
}

impl ClientCertVerifier for AllowAnyAuthenticatedClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn client_auth_root_subjects(&self) -> DistinguishedNames {
        self.roots.get_subjects()
    }

    fn verify_client_cert(
        &self,
        presented_certs: &[Certificate],
    ) -> Result<ClientCertVerified, TLSError> {
        let (cert, chain, trustroots) = prepare(&self.roots, presented_certs)?;
        let now = try_now()?;
        cert.verify_is_valid_tls_client_cert(
            SUPPORTED_SIG_ALGS,
            &webpki::TLSClientTrustAnchors(&trustroots),
            &chain,
            now,
        )
        .map_err(TLSError::WebPKIError)
        .map(|_| ClientCertVerified::assertion())
    }
}

/// A `ClientCertVerifier` that will allow both anonymous and authenticated
/// clients, without any name checking.
///
/// Client authentication will be requested during the TLS handshake. If the
/// client offers a certificate then this acts like
/// `AllowAnyAuthenticatedClient`, otherwise this acts like `NoClientAuth`.
pub struct AllowAnyAnonymousOrAuthenticatedClient {
    inner: AllowAnyAuthenticatedClient,
}

impl AllowAnyAnonymousOrAuthenticatedClient {
    /// Construct a new `AllowAnyAnonymousOrAuthenticatedClient`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    pub fn new(roots: RootCertStore) -> Arc<dyn ClientCertVerifier> {
        Arc::new(AllowAnyAnonymousOrAuthenticatedClient {
            inner: AllowAnyAuthenticatedClient { roots },
        })
    }
}

impl ClientCertVerifier for AllowAnyAnonymousOrAuthenticatedClient {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn client_auth_root_subjects(&self) -> DistinguishedNames {
        self.inner.client_auth_root_subjects()
    }

    fn verify_client_cert(
        &self,
        presented_certs: &[Certificate],
    ) -> Result<ClientCertVerified, TLSError> {
        self.inner.verify_client_cert(presented_certs)
    }
}

/// Turns off client authentication.
pub struct NoClientAuth;

impl NoClientAuth {
    /// Constructs a `NoClientAuth` and wraps it in an `Arc`.
    pub fn new() -> Arc<dyn ClientCertVerifier> {
        Arc::new(NoClientAuth)
    }
}

impl ClientCertVerifier for NoClientAuth {
    fn offer_client_auth(&self) -> bool {
        false
    }

    fn client_auth_root_subjects(&self) -> DistinguishedNames {
        unimplemented!();
    }

    fn verify_client_cert(
        &self,
        _presented_certs: &[Certificate],
    ) -> Result<ClientCertVerified, TLSError> {
        unimplemented!();
    }
}

static ECDSA_SHA256: SignatureAlgorithms =
    &[&webpki::ECDSA_P256_SHA256, &webpki::ECDSA_P384_SHA256];
static ECDSA_SHA384: SignatureAlgorithms =
    &[&webpki::ECDSA_P256_SHA384, &webpki::ECDSA_P384_SHA384];

static RSA_SHA256: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA256];
static RSA_SHA384: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA384];
static RSA_SHA512: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA512];
static RSA_PSS_SHA256: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY];
static RSA_PSS_SHA384: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY];
static RSA_PSS_SHA512: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY];

fn convert_scheme(scheme: SignatureScheme) -> Result<SignatureAlgorithms, TLSError> {
    match scheme {
        // nb. for TLS1.2 the curve is not fixed by SignatureScheme.
        SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(ECDSA_SHA256),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(ECDSA_SHA384),

        SignatureScheme::RSA_PKCS1_SHA256 => Ok(RSA_SHA256),
        SignatureScheme::RSA_PKCS1_SHA384 => Ok(RSA_SHA384),
        SignatureScheme::RSA_PKCS1_SHA512 => Ok(RSA_SHA512),

        SignatureScheme::RSA_PSS_SHA256 => Ok(RSA_PSS_SHA256),
        SignatureScheme::RSA_PSS_SHA384 => Ok(RSA_PSS_SHA384),
        SignatureScheme::RSA_PSS_SHA512 => Ok(RSA_PSS_SHA512),

        _ => {
            let error_msg = format!("received unadvertised sig scheme {:?}", scheme);
            Err(TLSError::PeerMisbehavedError(error_msg))
        }
    }
}

fn verify_sig_using_any_alg(
    cert: &webpki::EndEntityCert,
    algs: SignatureAlgorithms,
    message: &[u8],
    sig: &[u8],
) -> Result<(), webpki::Error> {
    // TLS doesn't itself give us enough info to map to a single webpki::SignatureAlgorithm.
    // Therefore, convert_algs maps to several and we try them all.
    for alg in algs {
        match cert.verify_signature(
            alg,
            untrusted::Input::from(message),
            untrusted::Input::from(sig),
        ) {
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey) => continue,
            res => return res,
        }
    }

    Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey)
}

/// Verify the signed `message` using the public key quoted in
/// `cert` and algorithm and signature in `dss`.
///
/// `cert` MUST have been authenticated before using this function,
/// typically using `verify_cert`.
pub fn verify_signed_struct(
    message: &[u8],
    cert: &Certificate,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, TLSError> {
    let possible_algs = convert_scheme(dss.scheme)?;
    let cert_in = untrusted::Input::from(&cert.0);
    let cert = webpki::EndEntityCert::from(cert_in).map_err(TLSError::WebPKIError)?;

    verify_sig_using_any_alg(&cert, possible_algs, message, &dss.sig.0)
        .map_err(TLSError::WebPKIError)
        .map(|_| HandshakeSignatureValid::assertion())
}

fn convert_alg_tls13(
    scheme: SignatureScheme,
) -> Result<&'static webpki::SignatureAlgorithm, TLSError> {
    use crate::msgs::enums::SignatureScheme::*;

    match scheme {
        ECDSA_NISTP256_SHA256 => Ok(&webpki::ECDSA_P256_SHA256),
        ECDSA_NISTP384_SHA384 => Ok(&webpki::ECDSA_P384_SHA384),
        RSA_PSS_SHA256 => Ok(&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
        RSA_PSS_SHA384 => Ok(&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
        RSA_PSS_SHA512 => Ok(&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),

        // oqs types
        DILITHIUM2 => Ok(&webpki::DILITHIUM2),
        DILITHIUM3 => Ok(&webpki::DILITHIUM3),
        DILITHIUM4 => Ok(&webpki::DILITHIUM4),
        FALCON512 => Ok(&webpki::FALCON512),
        FALCON1024 => Ok(&webpki::FALCON1024),
        MQDSS3148 => Ok(&webpki::MQDSS3148),
        MQDSS3164 => Ok(&webpki::MQDSS3164),
        RAINBOW_IA_CLASSIC => Ok(&webpki::RAINBOW_IA_CLASSIC),
        RAINBOW_IA_CYCLIC => Ok(&webpki::RAINBOW_IA_CYCLIC),
        RAINBOW_IA_CYCLIC_COMPRESSED => Ok(&webpki::RAINBOW_IA_CYCLIC_COMPRESSED),
        RAINBOW_II_ICCLASSIC => Ok(&webpki::RAINBOW_II_ICCLASSIC),
        RAINBOW_II_IC_CYCLIC => Ok(&webpki::RAINBOW_II_IC_CYCLIC),
        RAINBOW_II_IC_CYCLIC_COMPRESSED => Ok(&webpki::RAINBOW_II_IC_CYCLIC_COMPRESSED),
        RAINBOW_VC_CLASSIC => Ok(&webpki::RAINBOW_VC_CLASSIC),
        RAINBOW_VC_CYCLIC => Ok(&webpki::RAINBOW_VC_CYCLIC),
        RAINBOW_VC_CYCLIC_COMPRESSED => Ok(&webpki::RAINBOW_VC_CYCLIC_COMPRESSED),
        SPHINCS_HARAKA128F_ROBUST => Ok(&webpki::SPHINCS_HARAKA128F_ROBUST),
        SPHINCS_HARAKA128F_SIMPLE => Ok(&webpki::SPHINCS_HARAKA128F_SIMPLE),
        SPHINCS_HARAKA128S_ROBUST => Ok(&webpki::SPHINCS_HARAKA128S_ROBUST),
        SPHINCS_HARAKA128S_SIMPLE => Ok(&webpki::SPHINCS_HARAKA128S_SIMPLE),
        SPHINCS_HARAKA192F_ROBUST => Ok(&webpki::SPHINCS_HARAKA192F_ROBUST),
        SPHINCS_HARAKA192F_SIMPLE => Ok(&webpki::SPHINCS_HARAKA192F_SIMPLE),
        SPHINCS_HARAKA192S_ROBUST => Ok(&webpki::SPHINCS_HARAKA192S_ROBUST),
        SPHINCS_HARAKA192S_SIMPLE => Ok(&webpki::SPHINCS_HARAKA192S_SIMPLE),
        SPHINCS_HARAKA256F_ROBUST => Ok(&webpki::SPHINCS_HARAKA256F_ROBUST),
        SPHINCS_HARAKA256F_SIMPLE => Ok(&webpki::SPHINCS_HARAKA256F_SIMPLE),
        SPHINCS_HARAKA256S_ROBUST => Ok(&webpki::SPHINCS_HARAKA256S_ROBUST),
        SPHINCS_HARAKA256S_SIMPLE => Ok(&webpki::SPHINCS_HARAKA256S_SIMPLE),
        SPHINCS_SHA256128F_ROBUST => Ok(&webpki::SPHINCS_SHA256128F_ROBUST),
        SPHINCS_SHA256128F_SIMPLE => Ok(&webpki::SPHINCS_SHA256128F_SIMPLE),
        SPHINCS_SHA256128S_ROBUST => Ok(&webpki::SPHINCS_SHA256128S_ROBUST),
        SPHINCS_SHA256128S_SIMPLE => Ok(&webpki::SPHINCS_SHA256128S_SIMPLE),
        SPHINCS_SHA256192F_ROBUST => Ok(&webpki::SPHINCS_SHA256192F_ROBUST),
        SPHINCS_SHA256192F_SIMPLE => Ok(&webpki::SPHINCS_SHA256192F_SIMPLE),
        SPHINCS_SHA256192S_ROBUST => Ok(&webpki::SPHINCS_SHA256192S_ROBUST),
        SPHINCS_SHA256192S_SIMPLE => Ok(&webpki::SPHINCS_SHA256192S_SIMPLE),
        SPHINCS_SHA256256F_ROBUST => Ok(&webpki::SPHINCS_SHA256256F_ROBUST),
        SPHINCS_SHA256256F_SIMPLE => Ok(&webpki::SPHINCS_SHA256256F_SIMPLE),
        SPHINCS_SHA256256S_ROBUST => Ok(&webpki::SPHINCS_SHA256256S_ROBUST),
        SPHINCS_SHA256256S_SIMPLE => Ok(&webpki::SPHINCS_SHA256256S_SIMPLE),
        SPHINCS_SHAKE256128F_ROBUST => Ok(&webpki::SPHINCS_SHAKE256128F_ROBUST),
        SPHINCS_SHAKE256128F_SIMPLE => Ok(&webpki::SPHINCS_SHAKE256128F_SIMPLE),
        SPHINCS_SHAKE256128S_ROBUST => Ok(&webpki::SPHINCS_SHAKE256128S_ROBUST),
        SPHINCS_SHAKE256128S_SIMPLE => Ok(&webpki::SPHINCS_SHAKE256128S_SIMPLE),
        SPHINCS_SHAKE256192F_ROBUST => Ok(&webpki::SPHINCS_SHAKE256192F_ROBUST),
        SPHINCS_SHAKE256192F_SIMPLE => Ok(&webpki::SPHINCS_SHAKE256192F_SIMPLE),
        SPHINCS_SHAKE256192S_ROBUST => Ok(&webpki::SPHINCS_SHAKE256192S_ROBUST),
        SPHINCS_SHAKE256192S_SIMPLE => Ok(&webpki::SPHINCS_SHAKE256192S_SIMPLE),
        SPHINCS_SHAKE256256F_ROBUST => Ok(&webpki::SPHINCS_SHAKE256256F_ROBUST),
        SPHINCS_SHAKE256256F_SIMPLE => Ok(&webpki::SPHINCS_SHAKE256256F_SIMPLE),
        SPHINCS_SHAKE256256S_ROBUST => Ok(&webpki::SPHINCS_SHAKE256256S_ROBUST),
        SPHINCS_SHAKE256256S_SIMPLE => Ok(&webpki::SPHINCS_SHAKE256256S_SIMPLE),
        PICNIC_L1_FS => Ok(&webpki::PICNIC_L1_FS),
        PICNIC_L1_UR => Ok(&webpki::PICNIC_L1_UR),
        PICNIC_L3_FS => Ok(&webpki::PICNIC_L3_FS),
        PICNIC_L3_UR => Ok(&webpki::PICNIC_L3_UR),
        PICNIC_L5_FS => Ok(&webpki::PICNIC_L5_FS),
        PICNIC_L5_UR => Ok(&webpki::PICNIC_L5_UR),
        PICNIC2_L1_FS => Ok(&webpki::PICNIC2_L1_FS),
        PICNIC2_L3_FS => Ok(&webpki::PICNIC2_L3_FS),
        PICNIC2_L5_FS => Ok(&webpki::PICNIC2_L5_FS),
        Q_TESLA_PI => Ok(&webpki::Q_TESLA_PI),
        Q_TESLA_PIII => Ok(&webpki::Q_TESLA_PIII),
        _ => {
            let error_msg = format!("received unsupported sig scheme {:?}", scheme);
            Err(TLSError::PeerMisbehavedError(error_msg))
        }
    }
}

pub fn verify_tls13(
    cert: &Certificate,
    our_key_share: &suites::KeyExchange,
    dss: &DigitallySignedStruct,
    handshake_hash: &[u8],
    context_string_with_0: &[u8],
) -> Result<HandshakeSignatureValid, TLSError> {
    let _alg = convert_alg_tls13(dss.scheme)?;

    let mut msg = Vec::new();
    msg.resize(64, 0x20u8);
    msg.extend_from_slice(context_string_with_0);
    msg.extend_from_slice(handshake_hash);

    let cert_in = untrusted::Input::from(&cert.0);
    let cert = webpki::EndEntityCert::from(cert_in).map_err(TLSError::WebPKIError)?;

    let (_, cert_pk) = cert
        .public_key()
        .map_err(|_| TLSError::General("cert pk failed?".to_owned()))?;

    // XXX derive shared secret
    let kexresult = our_key_share
        .clone()
        .decapsulate(cert_pk.as_slice_less_safe())
        .unwrap();

    // Compute and verify MAC
    let mac_key =
        ring::hmac::VerificationKey::new(&ring::digest::SHA384, &kexresult.premaster_secret);
    ring::hmac::verify(&mac_key, &msg, &dss.sig.0)
        .map(|_| HandshakeSignatureValid::assertion())
        .map_err(|_| TLSError::General("MAC verification failed".to_owned()))

    // cert.verify_signature(alg,
    //                       untrusted::Input::from(&msg),
    //                       untrusted::Input::from(&dss.sig.0))
    //     .map_err(TLSError::WebPKIError)
    //     .map(|_| HandshakeSignatureValid::assertion())
}

fn unix_time_millis() -> Result<u64, TLSError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .map_err(|_| TLSError::FailedToGetCurrentTime)
        .and_then(|secs| {
            secs.checked_mul(1000)
                .ok_or(TLSError::FailedToGetCurrentTime)
        })
}

pub fn verify_scts(cert: &Certificate, scts: &SCTList, logs: &[&sct::Log]) -> Result<(), TLSError> {
    let mut valid_scts = 0;
    let now = unix_time_millis()?;
    let mut last_sct_error = None;

    for sct in scts {
        #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
        match sct::verify_sct(&cert.0, &sct.0, now, logs) {
            Ok(index) => {
                debug!(
                    "Valid SCT signed by {} on {}",
                    logs[index].operated_by, logs[index].description
                );
                valid_scts += 1;
            }
            Err(e) => {
                if e.should_be_fatal() {
                    return Err(TLSError::InvalidSCT(e));
                }
                debug!("SCT ignored because {:?}", e);
                last_sct_error = Some(e);
            }
        }
    }

    /* If we were supplied with some logs, and some SCTs,
     * but couldn't verify any of them, fail the handshake. */
    if !logs.is_empty() && !scts.is_empty() && valid_scts == 0 {
        warn!("No valid SCTs provided");
        return Err(TLSError::InvalidSCT(last_sct_error.unwrap()));
    }

    Ok(())
}

pub fn supported_verify_schemes() -> &'static [SignatureScheme] {
    &[
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA256,
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
    ]
}
