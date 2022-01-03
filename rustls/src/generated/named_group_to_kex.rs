match group {

        NamedGroup::Kyber512 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Kyber768 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Kyber1024 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece348864 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece348864f => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece460896 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece460896f => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece6688128 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece6688128f => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece6960119 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece6960119f => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece8192128 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::ClassicMcEliece8192128f => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Lightsaber => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Saber => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Firesaber => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruHps2048509 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruHps2048677 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruHps4096821 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruHrss701 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruPrimeNtrulpr653 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruPrimeNtrulpr761 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruPrimeNtrulpr857 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruPrimeSntrup653 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruPrimeSntrup761 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::NtruPrimeSntrup857 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FrodoKem640Aes => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FrodoKem640Shake => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FrodoKem976Aes => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FrodoKem976Shake => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FrodoKem1344Aes => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::FrodoKem1344Shake => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP434 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP434Compressed => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP503 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP503Compressed => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP610 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP610Compressed => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP751 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SikeP751Compressed => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::BikeL1 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::BikeL3 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Hqc128 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Hqc192 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::Hqc256 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::CSIDH2047K221 => {
            Some(KexAlgorithm::CSIDH(secsidh::Algorithm::CSIDH2047k221))
        },

        NamedGroup::CSIDH4095K256 => {
            Some(KexAlgorithm::CSIDH(secsidh::Algorithm::CSIDH4095k256))
        },

        NamedGroup::CSIDH5119K234 => {
            Some(KexAlgorithm::CSIDH(secsidh::Algorithm::CSIDH5119k234))
        },

        NamedGroup::CSIDH6143K256 => {
            Some(KexAlgorithm::CSIDH(secsidh::Algorithm::CSIDH6143k256))
        },

        NamedGroup::CSIDH8191K332 => {
            Some(KexAlgorithm::CSIDH(secsidh::Algorithm::CSIDH8191k332))
        },

        NamedGroup::CSIDH9215K384 => {
            Some(KexAlgorithm::CSIDH(secsidh::Algorithm::CSIDH9215k384))
        },

        NamedGroup::CTIDH2047K221 => {
            Some(KexAlgorithm::CSIDH(secsidh::Algorithm::CTIDH2047k221))
        },

        NamedGroup::CTIDH4095K256 => {
            Some(KexAlgorithm::CSIDH(secsidh::Algorithm::CTIDH4095k256))
        },

        NamedGroup::CTIDH5119K234 => {
            Some(KexAlgorithm::CSIDH(secsidh::Algorithm::CTIDH5119k234))
        },

        NamedGroup::CTIDH6143K256 => {
            Some(KexAlgorithm::CSIDH(secsidh::Algorithm::CTIDH6143k256))
        },

        NamedGroup::CTIDH8191K332 => {
            Some(KexAlgorithm::CSIDH(secsidh::Algorithm::CTIDH8191k332))
        },

        NamedGroup::CTIDH9215K384 => {
            Some(KexAlgorithm::CSIDH(secsidh::Algorithm::CTIDH9215k384))
        },
_ => None,
}