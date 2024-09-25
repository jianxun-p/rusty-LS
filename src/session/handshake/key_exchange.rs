use cryptrust::ecc::FromBytes;

rfc_enum_no_err! {
    [Clone, Copy, Debug, PartialEq, Eq] (pub) NamedGroup: u16;

    /* Reserved Code Points */
    // FfdhePrivateUse(0x01FC..0x01FF),
    // EcdhePrivateUse(0xFE00..0xFEFF),
    [Reserved],

    /* Elliptic Curve Groups (ECDHE) */
    Secp256r1(0x0017),
    Secp384r1(0x0018),
    Secp521r1(0x0019),
    X25519(0x001D),
    X448(0x001E),

    /* Finite Field Groups (DHE) */
    Ffdhe2048(0x0100),
    Ffdhe3072(0x0101),
    Ffdhe4096(0x0102),
    Ffdhe6144(0x0103),
    Ffdhe8192(0x0104),
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(super) struct KeyShare {
    pub group: NamedGroup,
    pub key_exchange: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(super) struct KeyExchange {
    pub group: NamedGroup,
    pub host_pub_key: Vec<u8>, // public key of the opposite end
    pub self_private_key: Vec<u8>,
    pub self_pub_key: Vec<u8>,
    pub shared_key: Vec<u8>,
}

impl NamedGroup {
    pub fn to_be_bytes(&self) -> [u8; 2] {
        let num = self.clone() as u16;
        [((num >> 8) & 0xff) as u8, (num & 0xff) as u8]
    }
}

pub fn choose_key_exchange<'a>(key_shares: &'a Vec<KeyShare>) -> Option<&'a KeyShare> {
    use NamedGroup::*;
    const GROUP_PREFERENCES: [NamedGroup; 2] = [
        // in the order of preference
        X448, X25519, 
        // Secp521r1, Secp384r1, Secp256r1, 
        // Ffdhe8192, Ffdhe6144, Ffdhe4096, Ffdhe3072, Ffdhe2048,
    ];
    for preference in GROUP_PREFERENCES {
        if let Some(key_exchange) = key_shares.iter().find(|&key| key.group == preference) {
            return Some(key_exchange);
        }
    }
    None
}


impl From<KeyShare> for KeyExchange {
    fn from(value: KeyShare) -> Self {
        use cryptrust::num_traits::ToBytes;
        use cryptrust::key_exchange::*;

        let pri_key;

        fn vec2arr<const SIZE: usize>(vec: &Vec<u8>) -> [u8; SIZE] {
            let mut arr: [u8; SIZE] = [0; SIZE];
            (0..SIZE).for_each(|i| arr[i] = vec[i]);
            arr
        }

        let pub_key;
        let shared_key;
        match value.group {
            NamedGroup::X448 => {
                let (private, public) = X448::key_pair();
                pri_key = Vec::from(private.to_le_bytes());
                pub_key = Vec::from(public.to_le_bytes());
                let shared = X448::shared_secret(private, X448PubKey::from_le_bytes(&vec2arr(&value.key_exchange)));
                shared_key = Vec::from(shared.to_le_bytes());
            }
            NamedGroup::X25519 => {
                let (private, public) = X25519::key_pair();
                pri_key = Vec::from(private.to_le_bytes());
                pub_key = Vec::from(public.to_le_bytes());
                let shared = X25519::shared_secret(private, X25519PubKey::from_le_bytes(&vec2arr(&value.key_exchange)));
                shared_key = Vec::from(shared.to_le_bytes());
            }
            _ => unimplemented!(),
        };
        Self {
            group: value.group,
            host_pub_key: value.key_exchange,
            self_private_key: pri_key,
            self_pub_key: pub_key,
            shared_key: shared_key,
        }
    }
}
