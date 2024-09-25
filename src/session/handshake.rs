use rand::random;

use self::{extensions::*, key_exchange::KeyExchange};

use super::ProtocolVersion;

#[allow(unused)]
pub(super) mod derive_secret;

pub(super) mod extensions;
pub(super) mod key_exchange;
pub(super) mod client_hello;
pub(super) mod server_hello;


#[derive(Clone, Debug)]
pub(super) struct HandshakeInfo {
    pub client_random: [u8; RANDOM_SIZE],
    pub server_random: [u8; RANDOM_SIZE],
    pub version: ProtocolVersion,
    extended_master_secret: bool,
    pub _handshake_msg: Vec<u8>,
    key_exchange: KeyExchange,
}


rfc_enum!(
    [Clone, Copy, Debug]
    (pub) HandshakeType: u8;
    ClientHello(1),
    ServerHello(2),
    NewSessionTicket(4),
    EndOfEarlyData(5),
    EncryptedExtensions(8),
    Certificate(11),
    CertificateRequest(13),
    CertificateVerify(15),
    Finished(20),
    KeyUpdate(24),
    MessageHash(254),
);

pub(crate) const HANDSHAKE_LENGTH_SIZE: usize = 3;

pub(crate) const HANDSHAKE_HEADER_SIZE: usize = 4;

pub(super) const SESSION_ID_LEN_SIZE: usize = 1;

pub(super) const RANDOM_SIZE: usize = 32;

pub(super) const CIPHER_SUITE_LEN_SIZE: usize = 2;

pub(super) const COMPRESSION_METHOD_LEN_SIZE: usize = 1;

pub(super) const EXTENSION_LEN_SIZE: usize = 2;

pub(super) const SESSION_ID_LEN: usize = 32;

#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct HandshakeLength([u8; HANDSHAKE_LENGTH_SIZE]);

#[derive(Clone, Copy, Debug)]
pub struct HandshakeHeader {
    pub handshake_type: HandshakeType,
    pub length: HandshakeLength,
}

impl From<u32> for HandshakeLength {
    fn from(value: u32) -> Self {
        Self::from(value as usize)
    }
}

impl From<usize> for HandshakeLength {
    fn from(value: usize) -> Self {
        let arr = value.to_le_bytes();
        let mut l = Self([0; HANDSHAKE_LENGTH_SIZE]);
        for i in 0..HANDSHAKE_LENGTH_SIZE {
            l.0[HANDSHAKE_LENGTH_SIZE - i - 1] = arr[i];
        }
        l
    }
}

impl Into<u32> for HandshakeLength {
    fn into(self) -> u32 {
        const U32_SIZE: usize = (u32::BITS / u8::BITS) as usize;
        let mut arr = [0u8; U32_SIZE];
        for i in 0..HANDSHAKE_LENGTH_SIZE {
            arr[i] = self.0[HANDSHAKE_LENGTH_SIZE - i - 1];
        }
        u32::from_le_bytes(arr)
    }
}

impl Into<usize> for HandshakeLength {
    fn into(self) -> usize {
        Into::<u32>::into(self) as usize
    }
}

impl HandshakeHeader {
    pub fn to_bytes(self) -> [u8; HANDSHAKE_HEADER_SIZE] {
        let len: u32 = self.length.into();
        let len_arr = len.to_be_bytes();
        [
            self.handshake_type as u8,
            len_arr[1],
            len_arr[2],
            len_arr[3],
        ]
    }
}

impl TryFrom<[u8; HANDSHAKE_HEADER_SIZE]> for HandshakeHeader {
    type Error = TlsError;
    fn try_from(mut bytes: [u8; HANDSHAKE_HEADER_SIZE]) -> Result<Self, Self::Error> {
        let handshake_type = HandshakeType::try_from(bytes[0])?;
        bytes[0] = 0;
        Ok(Self {
            handshake_type: handshake_type,
            length: HandshakeLength::from(u32::from_be_bytes(bytes)),
        })
    }
}

impl TryFrom<&[u8]> for HandshakeHeader {
    type Error = TlsError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < HANDSHAKE_HEADER_SIZE {
            return Err(TlsError {
                code: TlsErrorCode::ParseError,
                msg: format!(
                    "failed to parse HandshakeHeader from a slice of length {}, required {} bytes",
                    bytes.len(),
                    HANDSHAKE_HEADER_SIZE
                ),
            });
        }
        let mut tmp = [0u8; HANDSHAKE_HEADER_SIZE];
        tmp.copy_from_slice(&bytes[..HANDSHAKE_HEADER_SIZE]);
        Self::try_from(tmp)
    }
}

impl Default for HandshakeInfo {
    fn default() -> Self {
        Self {
            client_random: random(),
            server_random: random(),
            // cipher_suite: CipherSuite::default(),
            extended_master_secret: false,
            _handshake_msg: Vec::new(),
            key_exchange: KeyExchange::default(),
            version: ProtocolVersion::default(),
        }
    }
}
