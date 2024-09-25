// mod key_exchange;
pub(crate) mod cipher;
use cipher::TlsCipher;
use cryptrust::{hash::*, num_traits::ToBytes};

use crate::error::TlsError;

#[allow(unused)]
#[derive(Debug)]
pub struct CipherSuite {
    pub(crate) value: u16,
    pub(super) cipher: TlsCipher, 
    hash: CryptoHash,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) struct CipherSuiteValue(u16);


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum CipherSuiteV13 {
    #[default]
    Null,
    Aes128GcmSha256,
    Aes256GcmSha384,
    // Chacha20Poly1305Sha256,
    // Aes128CcmSha256,
    // Aes128Ccm8Sha256,
}

macro_rules! impl_cipher_suite_conversion {
    (
        [$type:ty] $($name:ident($val:expr, $ciph:expr, $hash:expr),)* $(,)?
    ) => {

        impl $type {
            fn new_cipher_suite(self) -> CipherSuite {
                match self {
                    $(Self::$name => CipherSuite {
                        value: $val,
                        cipher: TlsCipher::new(),
                        hash: CryptoHash::new($hash),
                    },)*
                }
            }
        }

        impl TryFrom<u16> for $type {
            type Error = ();
            fn try_from(value: u16) -> Result<Self, ()> {
                match value {
                    $($val => Ok(Self::$name),)*
                    _ => Err(())
                }
            }
        }

        impl Into<u16> for $type {
            fn into(self) -> u16 {
                match self {
                    $(Self::$name => $val,)*
                }
            }
        }

    };
}


impl_cipher_suite_conversion!(
    [CipherSuiteV13] 
    Null(0x0000,  TlsCipherType::Null, CryptoHashType::Null),
    Aes128GcmSha256(0x1301, TlsCipherType::Aes128Gcm, CryptoHashType::Sha256),
    Aes256GcmSha384(0x1302, TlsCipherType::Aes256Gcm, CryptoHashType::Sha384),
    // Chacha20Poly1305Sha256(0x1303, None, CryptoHashType::Sha256),
    // Aes128CcmSha256(0x1304, None, CryptoHashType::Sha256),
    // Aes128Ccm8Sha256(0x1305, None, CryptoHashType::Sha256),
);


pub const CIPHER_SUITE_VALUE_SIZE: usize = 2;

const NULL_CIPHER_SUITE_VAL: u16 = 0x0000;

/// supported cipher suites in preferred ordering
const SUPPORTED_CIPHER_SUITES: [u16; 3] = [
    0x1302, 0x1301, 0x0000,
];

impl CipherSuiteV13 {
    #[allow(unused)]
    pub fn new() -> Self {
        Self::Null
    }
}


const NULL_CIPHER_SUITE: CipherSuite = CipherSuite {
    value: NULL_CIPHER_SUITE_VAL,
    cipher: TlsCipher::new(), 
    hash: CryptoHash::const_new(CryptoHashType::Null),
};

impl CipherSuite {
    pub const fn new() -> Self {
        NULL_CIPHER_SUITE
    }

    pub fn choose(choices: &[CipherSuiteValue]) -> Result<Self, TlsError> {
        for val in SUPPORTED_CIPHER_SUITES {
            for choice in choices {
                if choice.0 == val {
                    return CipherSuiteValue::new_cipher_suite(val);
                }
            }
        }
        Err(TlsError { code: crate::error::TlsErrorCode::ParseError, msg: String::from("unrecognized cipher suite values") })
    }
}


impl CipherSuiteValue {

    #[allow(unused)]
    pub fn new() -> Self {
        Self(0x0000)
    }

    pub fn new_cipher_suite(value: u16) -> Result<CipherSuite, TlsError> {
        if let Ok(val) = CipherSuiteV13::try_from(value) {
            Ok(val.new_cipher_suite())
        } else {
            Err(TlsError { code: crate::error::TlsErrorCode::ParseError, msg: format!("unrecognized cipher suite value: {}", value) })
        }
    }
}

impl From<u16> for CipherSuiteValue {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl ToBytes for CipherSuiteValue {
    type Bytes = <u16 as ToBytes>::Bytes;

    fn to_be_bytes(&self) -> Self::Bytes {
        self.0.to_be_bytes()
    }

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}
