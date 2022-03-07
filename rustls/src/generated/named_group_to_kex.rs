match group {

        NamedGroup::KYBER512 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::KYBER768 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber768).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::KYBER1024 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber1024).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::CLASSICMCELIECE348864 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece348864).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::CLASSICMCELIECE348864F => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece348864f).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::CLASSICMCELIECE460896 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece460896).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::CLASSICMCELIECE460896F => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece460896f).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::CLASSICMCELIECE6688128 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece6688128).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::CLASSICMCELIECE6688128F => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece6688128f).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::CLASSICMCELIECE6960119 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece6960119).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::CLASSICMCELIECE6960119F => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece6960119f).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::CLASSICMCELIECE8192128 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece8192128).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::CLASSICMCELIECE8192128F => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece8192128f).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::LIGHTSABER => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Lightsaber).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SABER => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Saber).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FIRESABER => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Firesaber).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NTRUHPS2048509 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruHps2048509).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NTRUHPS2048677 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruHps2048677).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NTRUHPS4096821 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruHps4096821).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NTRUHRSS701 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruHrss701).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NTRUPRIMENTRULPR653 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeNtrulpr653).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NTRUPRIMENTRULPR761 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeNtrulpr761).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NTRUPRIMENTRULPR857 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeNtrulpr857).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NTRUPRIMESNTRUP653 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeSntrup653).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NTRUPRIMESNTRUP761 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeSntrup761).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NTRUPRIMESNTRUP857 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::NtruPrimeSntrup857).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FRODOKEM640AES => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem640Aes).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FRODOKEM640SHAKE => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem640Shake).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FRODOKEM976AES => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem976Aes).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FRODOKEM976SHAKE => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem976Shake).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FRODOKEM1344AES => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem1344Aes).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FRODOKEM1344SHAKE => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem1344Shake).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SIKEP434 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP434).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SIKEP434COMPRESSED => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP434Compressed).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SIKEP434COMPRESSEDASYNC => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP434Compressed).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SIKEP503 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP503).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SIKEP503COMPRESSED => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP503Compressed).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SIKEP503COMPRESSEDASYNC => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP503Compressed).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SIKEP610 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP610).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SIKEP610COMPRESSED => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP610Compressed).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SIKEP610COMPRESSEDASYNC => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP610Compressed).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SIKEP751 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP751).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SIKEP751COMPRESSED => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP751Compressed).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SIKEP751COMPRESSEDASYNC => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::SikeP751Compressed).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::BIKEL1 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::BikeL1).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::BIKEL3 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::BikeL3).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::HQC128 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Hqc128).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::HQC192 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Hqc192).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::HQC256 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Hqc256).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },
_ => None,
}