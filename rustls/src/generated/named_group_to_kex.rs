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

        NamedGroup::Saber => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },

        NamedGroup::SidhP434 => {
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        },
_ => None,
}