
enum_builder! {
    /// The `NamedGroup` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    EnumName: NamedGroup;
    EnumVal{
        secp256r1 => 0x0017,
        secp384r1 => 0x0018,
        secp521r1 => 0x0019,
        X25519 => 0x001d,
        X448 => 0x001e,
        FFDHE2048 => 0x0100,
        FFDHE3072 => 0x0101,
        FFDHE4096 => 0x0102,
        FFDHE6144 => 0x0103,
        FFDHE8192 => 0x0104,
        Kyber512 => 0x01fc,
        Kyber768 => 0x01fd,
        Kyber1024 => 0x01fe,
        ClassicMcEliece348864 => 0x01ff,
        ClassicMcEliece348864f => 0x0200,
        ClassicMcEliece460896 => 0x0201,
        ClassicMcEliece460896f => 0x0202,
        ClassicMcEliece6688128 => 0x0203,
        ClassicMcEliece6688128f => 0x0204,
        ClassicMcEliece6960119 => 0x0205,
        ClassicMcEliece6960119f => 0x0206,
        ClassicMcEliece8192128 => 0x0207,
        ClassicMcEliece8192128f => 0x0208,
        Lightsaber => 0x0209,
        Saber => 0x020a,
        Firesaber => 0x020b,
        NtruHps2048509 => 0x020c,
        SidhP434 => 0x020d,
    }
}
