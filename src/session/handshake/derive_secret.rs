use digest::{Digest, Mac};
use hmac::Hmac;
use sha2::{Sha224, Sha256, Sha384, Sha512};

// See rfc5869 for information of HKDF-Extract, HKDF-Expand
//     at https://www.rfc-editor.org/rfc/rfc5869

/*
HKDF-Extract(salt, IKM) -> PRK
    Options:
        Hash     a hash function; HashLen denotes the length of the hash function output in octets
    Inputs:
        salt     optional salt value (a non-secret random value); if not provided, it is set to a string of HashLen zeros.
        IKM      input keying material

    Output:
        PRK      a pseudorandom key (of HashLen octets)

    The output PRK is calculated as follows:

    PRK = HMAC-Hash(salt, IKM)
*/
macro_rules! hkdf_extract_builder {
    ($hash:ty, $fn_name:ident) => {
        pub(crate) fn $fn_name(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
            fn hmac_hash(key: &[u8], val: &[u8]) -> Vec<u8> {
                let mut mac = Hmac::<$hash>::new_from_slice(key).expect("HMAC key length");
                mac.update(val);
                mac.finalize().into_bytes().to_vec()
            }
            // Note that in the extract step,
            // 'IKM' is used as the HMAC input, not as the HMAC key.
            hmac_hash(salt, ikm)
        }
    };
}
hkdf_extract_builder!(Sha224, hkdf_extract_sha224);
hkdf_extract_builder!(Sha256, hkdf_extract_sha256);
hkdf_extract_builder!(Sha384, hkdf_extract_sha384);
hkdf_extract_builder!(Sha512, hkdf_extract_sha512);

/*
HKDF-Expand(PRK, info, L) -> OKM
    Options:
        Hash    a hash function; HashLen denotes the length of the
                hash function output in octets
    Inputs:
        PRK     a pseudorandom key of at least HashLen octets
                (usually, the output from the extract step)
        info    optional context and application specific information
                (can be a zero-length string)
        L       length of output keying material in octets
                (<= 255*HashLen)
    Output:
        OKM     output keying material (of L octets)

    The output OKM is calculated as follows:
    N = ceil(L/HashLen)
    T = T(1) | T(2) | T(3) | ... | T(N)         concatenation (denoted |)
    OKM = first L octets of T
    where:
    T(0) = empty string (zero length)
    T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
    T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
    ...
    (where the constant concatenated to the end of each T(n) is a
    single octet.)
*/
macro_rules! hkdf_expand_builder {
    ($hash:ty, $fn_name:ident) => {
        pub(crate) fn $fn_name(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
            fn hmac_hash(key: &[u8], val: Vec<u8>) -> Vec<u8> {
                let mut mac = Hmac::<$hash>::new_from_slice(key).expect("HMAC key length");
                mac.update(&val);
                mac.finalize().into_bytes().to_vec()
            }
            let hash_output_size = <$hash as Digest>::output_size();
            assert!(len <= 255 * hash_output_size);
            let n: usize = len.div_ceil(hash_output_size);
            type HashMac = Hmac<$hash>;
            let mut t: Vec<u8> = Vec::with_capacity(n * hash_output_size);
            let mut current_t: Vec<u8> = Vec::with_capacity(hash_output_size + info.len() + 1);
            for i in 1..n {
                current_t.extend(info);
                current_t.push(i as u8);
                current_t = hmac_hash(prk, current_t);
                t.extend(&current_t);
            }
            t[..len].to_vec()
        }
    };
}
hkdf_expand_builder!(Sha224, hkdf_expand_sha224);
hkdf_expand_builder!(Sha256, hkdf_expand_sha256);
hkdf_expand_builder!(Sha384, hkdf_expand_sha384);
hkdf_expand_builder!(Sha512, hkdf_expand_sha512);

/*
HKDF-Expand-Label(Secret, Label, Context, Length) =
            HKDF-Expand(Secret, HkdfLabel, Length)

Where HkdfLabel is specified as:

struct {
    uint16 length = Length;
    opaque label<7..255> = "tls13 " + Label;
    opaque context<0..255> = Context;
} HkdfLabel;

Derive-Secret(Secret, Label, Messages) =
    HKDF-Expand-Label(Secret, Label,
                         Transcript-Hash(Messages), Hash.length)
*/
macro_rules! derive_secret_builder {
    ($hash:ty, $fn_name:ident, $expand_fn:ident) => {
        pub(crate) fn $fn_name(secret: &[u8], label: &[u8], msg: &[u8]) -> Vec<u8> {
            let hash_output_size = <$hash as Digest>::output_size();
            let mut hkdf_label: Vec<u8> = Vec::with_capacity(9 + label.len() + hash_output_size);
            let hashed_msg = <$hash as Digest>::digest(msg).to_vec();
            hkdf_label.extend((hash_output_size as u16).to_be_bytes());
            hkdf_label.extend([
                't' as u8, 'l' as u8, 's' as u8, '1' as u8, '3' as u8, ' ' as u8,
            ]);
            hkdf_label.extend(label);
            hkdf_label.extend(hashed_msg);
            $expand_fn(secret, &hkdf_label, hash_output_size)
        }
    };
}
derive_secret_builder!(Sha224, derive_secret_sha224, hkdf_expand_sha224);
derive_secret_builder!(Sha256, derive_secret_sha256, hkdf_expand_sha256);
derive_secret_builder!(Sha384, derive_secret_sha384, hkdf_expand_sha384);
derive_secret_builder!(Sha512, derive_secret_sha512, hkdf_expand_sha512);
