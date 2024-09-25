use crate::error::{TlsError, TlsErrorCode};

use super::{key_exchange::KeyExchange, HandshakeInfo};

pub const EXTENSION_TYPE_SIZE: usize = 2;

rfc_enum_no_err! {
    [Clone, Copy, Debug, PartialEq, Eq]
    (pub) ExtensionType: u16;
    [Reserved(40)],
    ServerName(0),                           /* RFC 6066 */
    MaxFragmentLength(1),                    /* RFC 6066 */
    StatusRequest(5),                        /* RFC 6066 */
    SupportedGroups(10),                     /* RFC 8422, 7919 */
    EcPointFormats(11),                      /* RFC 8422 */
    SignatureAlgorithms(13),                 /* RFC 8446 */
    UseSrtp(14),                             /* RFC 5764 */
    Heartbeat(15),                           /* RFC 6520 */
    ApplicationLayerProtocolNegotiation(16), /* RFC 7301 */
    SignedCertificateTimestampamp(18),       /* RFC 6962 */
    ClientCertificateType(19),               /* RFC 7250 */
    ServerCertificateType(20),               /* RFC 7250 */
    Padding(21),                             /* RFC 7685 */
    EncryptThenMac(22),                      /* RFC 7366 */
    ExtendedMasterSecret(23),                /* RFC 7627 */
    PreSharedKey(41),                        /* RFC 8446 */
    EarlyData(42),                           /* RFC 8446 */
    SupportedVersions(43),                   /* RFC 8446 */
    Cookie(44),                              /* RFC 8446 */
    PskKeyExchangeModes(45),                 /* RFC 8446 */
    CertificateAuthorities(47),              /* RFC 8446 */
    OidFilters(48),                          /* RFC 8446 */
    PostHandshakeAuth(49),                   /* RFC 8446 */
    SignatureAlgorithmsCert(50),             /* RFC 8446 */
    KeyShare(51),                            /* RFC 8446 */
    RenegotiationInfo(65281),                /* RFC 5746 */
}

#[derive(Clone, Debug, PartialEq)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub length: u16,
    pub data: Vec<u8>,
}

impl Extension {
    pub fn parse(bytes: &[u8]) -> Result<Vec<Self>, TlsError> {
        let mut offset: usize = 0;
        let mut extensions = vec![];
        while offset < bytes.len() {
            let extension_type = ExtensionType::from({
                let mut type_bytes = [0u8; EXTENSION_TYPE_SIZE];
                type_bytes.copy_from_slice(&bytes[offset..offset + EXTENSION_TYPE_SIZE]);
                offset += EXTENSION_TYPE_SIZE;
                u16::from_be_bytes(type_bytes)
            });

            let extension_length = {
                let mut len_bytes = [0u8; 2];
                len_bytes.copy_from_slice(&bytes[offset..offset + 2]);
                offset += 2;
                u16::from_be_bytes(len_bytes)
            };

            let extension_data = {
                let mut data = Vec::with_capacity(extension_length as usize);
                data.extend_from_slice(&bytes[offset..offset + extension_length as usize]);
                data
            };

            offset += extension_length as usize;
            extensions.push(Self {
                extension_type: extension_type,
                length: extension_length,
                data: extension_data,
            });
        } // end of while
        match offset == bytes.len() {
            true => Ok(extensions),
            false => Err(TlsError {
                code: TlsErrorCode::ParseError,
                msg: String::from("failed to parse extensions"),
            }),
        }
    }
}

impl ExtensionType {
    pub fn to_be_bytes(&self) -> [u8; 2] {
        (*self as u16).to_be_bytes()
    }
}

impl Extension {
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.data.len() + 4);
        bytes.extend_from_slice(self.extension_type.to_be_bytes().as_slice());
        bytes.extend_from_slice(self.length.to_be_bytes().as_slice());
        bytes.extend_from_slice(self.data.as_slice());
        bytes
    }
}

impl HandshakeInfo {
    fn parse_extension(&mut self, extension: &Extension) -> Result<(), TlsError> {
        let data = &extension.data;
        match extension.extension_type {
            ExtensionType::ExtendedMasterSecret => {
                self.extended_master_secret = true;
            }
            ExtensionType::RenegotiationInfo => {}
            ExtensionType::KeyShare => {
                let key_share_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                let key_share = parser::key_share(&data[2..(2 + key_share_len)])?;
                self.key_exchange = KeyExchange::from(key_share);
                println!("{:02x?}", self.key_exchange);
            }
            ExtensionType::SupportedVersions => {
                let supported_versions_len = data[0] as usize;
                self.version = parser::supported_versions(&data[1..1 + supported_versions_len])?;
            }
            _ => {
                // println!("extension {:?}: {:02x?}", extension_type, data);
            }
        };
        Ok(())
    }

    pub fn build_extensions(&self) -> Result<Vec<Extension>, TlsError> {
        let mut extensions = vec![];

        extensions.push({
            let supported_versions_bytes = builder::supported_versions(self)?;
            Extension {
                extension_type: ExtensionType::SupportedVersions,
                length: supported_versions_bytes.len() as u16,
                data: supported_versions_bytes,
            }
        });

        extensions.push({
            let key_share_bytes = builder::key_share(self)?;
            Extension {
                extension_type: ExtensionType::KeyShare,
                length: key_share_bytes.len() as u16,
                data: key_share_bytes,
            }
        });

        Ok(extensions)
    }

    pub fn parse_extensions(&mut self, extensions: &Vec<Extension>) -> Result<(), TlsError> {
        for extension in extensions {
            self.parse_extension(extension)?;
        }
        Ok(())
    }
}

mod parser {

    use super::super::key_exchange;
    use crate::error::{TlsError, TlsErrorCode};
    use crate::session::handshake::key_exchange::{choose_key_exchange, KeyShare};
    use crate::session::{ProtocolVersion, PROTOCOL_VERSION_SIZE};

    pub(super) fn key_share(data: &[u8]) -> Result<KeyShare, TlsError> {
        let mut offset = 0;
        let mut key_shares: Vec<KeyShare> = vec![];

        const KEY_SHARE_ENTRY_HEADER_SIZE: usize = 4;

        while data.len() >= offset + KEY_SHARE_ENTRY_HEADER_SIZE {
            let key_exchange_len =
                u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            key_shares.push(KeyShare {
                group: key_exchange::NamedGroup::from(u16::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                ])),
                key_exchange: Vec::from(
                    &data[offset + KEY_SHARE_ENTRY_HEADER_SIZE
                        ..offset + KEY_SHARE_ENTRY_HEADER_SIZE + key_exchange_len],
                ),
            });
            // println!("key exchange: {:?}", key_shares.last().unwrap());
            offset += 4 + key_exchange_len;
        }

        match choose_key_exchange(&key_shares) {
            Some(key_share) => {
                let _group = key_share.group;
                let _key = key_share.key_exchange.as_slice();
                // println!(
                //     "chosen key exchange {:?} (len: {:?}) {:02x?}", group, key.len(), key
                // );
                Ok(key_share.clone())
            }
            None => {
                return Err(TlsError {
                    code: TlsErrorCode::ParseError,
                    msg: format!("failed to choose key share entry from {:?}", key_shares),
                })
            }
        }
    }

    pub(super) fn supported_versions(data: &[u8]) -> Result<ProtocolVersion, TlsError> {
        let mut offset = 0;
        let mut supported_versions = Vec::with_capacity(data.len());
        while data.len() >= offset + PROTOCOL_VERSION_SIZE {
            if let Ok(version) =
                { ProtocolVersion::try_from(u16::from_be_bytes([data[offset], data[offset + 1]])) }
            {
                supported_versions.push(version);
            } else {
                // println!("unknown supported version: {:04x?}", &data[offset..PROTOCOL_VERSION_SIZE]);
            }
            offset += PROTOCOL_VERSION_SIZE;
        }
        println!("supported versions: {:04x?}", supported_versions);

        const VERSION_PEREFERENCE: [ProtocolVersion; 3] = [
            ProtocolVersion::TlsV13,
            ProtocolVersion::TlsV12,
            ProtocolVersion::TlsV11,
        ];

        for pereference in VERSION_PEREFERENCE.iter() {
            if let Some(version) = { supported_versions.iter().find(|&v| pereference == v) } {
                return Ok(version.clone());
            }
        }
        Ok(ProtocolVersion::TlsV12)
    }
}

mod builder {

    use super::super::HandshakeInfo;
    use crate::{error::TlsError, session::PROTOCOL_VERSION_SIZE};

    #[allow(unused)]
    pub(super) fn key_share(handshake: &HandshakeInfo) -> Result<Vec<u8>, TlsError> {
        let key = &handshake.key_exchange;
        let bytes_size = 4 + key.self_pub_key.len();
        let mut bytes: Vec<u8> = Vec::with_capacity(bytes_size);
        bytes.extend_from_slice(key.group.to_be_bytes().as_slice());
        bytes.extend_from_slice((key.self_pub_key.len() as u16).to_be_bytes().as_slice());
        bytes.extend_from_slice(key.self_pub_key.as_slice());
        Ok(bytes)
    }

    #[allow(unused)]
    pub(super) fn supported_versions(handshake: &HandshakeInfo) -> Result<Vec<u8>, TlsError> {
        let mut bytes: Vec<u8> = Vec::with_capacity(PROTOCOL_VERSION_SIZE);
        bytes.extend_from_slice(handshake.version.to_be_bytes().as_slice());
        Ok(bytes)
    }
}
