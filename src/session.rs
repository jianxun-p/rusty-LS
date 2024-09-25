use crate::cipher_suite::*;
use crate::error::{TlsError, TlsErrorCode};
use bufstream::BufStream;
pub(crate) use version::{ProtocolVersion, PROTOCOL_VERSION_SIZE};
use std::io::{Read, Write};
use std::net::TcpStream;

use self::handshake::HandshakeInfo;

mod handshake;
mod server_end;
mod version;


pub(crate) const DEFAULT_SESSION_ID_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionEnd {
    Client,
    Server,
}

#[derive(Debug)]
pub struct TlsSession {

    connection_end: ConnectionEnd,

    tls_version: ProtocolVersion,
    
    session_id: Vec<u8>,

    io_stream: BufStream<TcpStream>,

    pub(super) cipher_suite: CipherSuite,

    handshake_info: Option<Box<HandshakeInfo>>,

    /// sequence number for read and writes (see section 6.1 of RFC5246)
    pub(super) io_sequence_num: (u64, u64),

    /// data waiting to be read / sent
    _io_buf: (Vec<u8>, Vec<u8>),

}

pub const CONTENT_TYPE_SIZE: usize = 1;

rfc_enum_no_err! {
    [Clone, Copy, Debug]
    (pub) ContentType: u8;
    [Invalid(0)],
    ChangeCipherSpec(20),
    Alert(21),
    Handshake(22),
    ApplicationData(23),
}

pub const TLS_PLAINTEXT_HEADER_SIZE: usize = 5;

#[derive(Clone, Copy, Debug)]
pub struct TlsPlaintextHeader {
    pub content_type: ContentType,
    pub legacy_record_version: ProtocolVersion,
    pub length: u16,
}

impl ToString for ProtocolVersion {
    fn to_string(&self) -> String {
        match self {
            Self::TlsV10 => format!("TLS 1.0"),
            Self::TlsV11 => format!("TLS 1.1"),
            Self::TlsV12 => format!("TLS 1.2"),
            Self::TlsV13 => format!("TLS 1.3"),
        }
    }
}

impl ProtocolVersion {
    pub fn to_be_bytes(&self) -> [u8; PROTOCOL_VERSION_SIZE] {
        (self.clone() as u16).to_be_bytes()
    }
}

impl TryFrom<&[u8; TLS_PLAINTEXT_HEADER_SIZE]> for TlsPlaintextHeader {
    type Error = TlsError;

    fn try_from(value: &[u8; TLS_PLAINTEXT_HEADER_SIZE]) -> Result<Self, Self::Error> {
        let mut version_bytes = [0u8; PROTOCOL_VERSION_SIZE];
        version_bytes.copy_from_slice(&value[1..(1 + PROTOCOL_VERSION_SIZE)]);
        let version = ProtocolVersion::try_from(u16::from_be_bytes(version_bytes))?;
        Ok(Self {
            content_type: ContentType::from(value[0]),
            legacy_record_version: version,
            length: u16::from_be_bytes([
                value[1 + PROTOCOL_VERSION_SIZE],
                value[2 + PROTOCOL_VERSION_SIZE],
            ]),
        })
    }
}

impl TlsPlaintextHeader {
    pub fn to_bytes(self) -> [u8; TLS_PLAINTEXT_HEADER_SIZE] {
        let version = self.legacy_record_version.to_be_bytes();
        let length = self.length.to_be_bytes();
        [
            self.content_type as u8,
            version[0],
            version[1],
            length[0],
            length[1],
        ]
    }
}

impl Read for TlsSession {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // println!("in TlsSession::read");
        let mut header_buf = [0; TLS_PLAINTEXT_HEADER_SIZE];
        self.io_stream.read_exact(header_buf.as_mut_slice())?;
        let try_header_result = TlsPlaintextHeader::try_from(&header_buf);
        if let Err(err) = try_header_result {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err.to_string(),
            ));
        }
        let header = try_header_result.unwrap();
        // dbg!(header);

        let mut cipher_fragment = Vec::with_capacity(header.length as usize);
        cipher_fragment.resize(header.length as usize, 0);
        self.io_stream.read_exact(cipher_fragment.as_mut_slice())?;
        let decrypted_text; 
        if let Some(compressed) = self.decrypt(cipher_fragment.as_slice(), header) {
            decrypted_text = compressed;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Failed to decrypt TLS record",
            ));
        }
        // eprintln!("read from TCP stream: \n{:?}", decrypted_text);

        match self.msg_handler(decrypted_text.as_slice()) {
            Ok(handled_len) => match handled_len == decrypted_text.len() {
                true => Ok(decrypted_text.len() + TLS_PLAINTEXT_HEADER_SIZE),
                false => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "msg_handler no good",
                )),
            },
            Err(err) => panic!("{}", err.to_string()),
        }
    }
}

impl Write for TlsSession {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {

        let header = TlsPlaintextHeader {
            content_type: ContentType::ApplicationData,
            legacy_record_version: self.tls_version,
            length: buf.len() as u16,
        };
        let encrypted_text = self.encrypt(buf, header);
        self.io_stream.write(header.to_bytes().as_slice())?;
        self.io_stream.write(encrypted_text.as_slice())?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io_stream.flush()
    }
}

impl TlsSession {
    pub fn client_from_tcp(tcp_stream: TcpStream) -> Self {
        Self {
            connection_end: ConnectionEnd::Client,
            tls_version: ProtocolVersion::default(),
            session_id: {
                let bytes: [u8; DEFAULT_SESSION_ID_LEN] = rand::random();
                Vec::from(bytes)
            },
            io_stream: BufStream::new(tcp_stream),
            io_sequence_num: (0, 0),
            cipher_suite: CipherSuite::new(),
            handshake_info: Some(Box::new(HandshakeInfo::default())),
            _io_buf: (Vec::new(), Vec::new()),
        }
    }

    pub fn server_from_tcp(tcp_stream: TcpStream) -> Self {
        Self {
            connection_end: ConnectionEnd::Server,
            tls_version: ProtocolVersion::default(),
            session_id: Vec::from(rand::random::<[u8; DEFAULT_SESSION_ID_LEN]>()),
            io_stream: BufStream::new(tcp_stream),
            io_sequence_num: (0, 0),
            cipher_suite: CipherSuite::new(),
            handshake_info: Some(Box::new(HandshakeInfo::default())),
            _io_buf: (Vec::new(), Vec::new()),
        }
    }

    fn write_record(
        &mut self,
        header: TlsPlaintextHeader,
        fragment: &[u8],
    ) -> Result<usize, TlsError> {
        let header_size: usize;
        match self.io_stream.write(header.to_bytes().as_slice()) {
            Ok(wrote_size) => {
                header_size = wrote_size;
            }
            Err(err) => {
                return Err(TlsError {
                    code: TlsErrorCode::IoError(err),
                    msg: format!("Failed to write TLS fragment ({} bytes)", fragment.len()),
                });
            }
        };
        match self.io_stream.write(fragment) {
            Ok(fragment_size) => {
                // println!(
                //     "in TlsSession::write_record wrote {} bytes",
                //     header_size + fragment_size
                // );
                Ok(header_size + fragment_size)
            }
            Err(err) => Err(TlsError {
                code: TlsErrorCode::IoError(err),
                msg: format!("Failed to write TLS fragment ({} bytes)", fragment.len()),
            }),
        }
    }

    pub fn msg_handler(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        println!("---------------------------------");
        let mut header_bytes = [0u8; TLS_PLAINTEXT_HEADER_SIZE];
        header_bytes.copy_from_slice(&buf[..TLS_PLAINTEXT_HEADER_SIZE]);
        let header = TlsPlaintextHeader::try_from(&header_bytes)?;
        const HEADER_LEN: usize = TLS_PLAINTEXT_HEADER_SIZE;
        let fragment_len = header.length as usize;
        let record_len = HEADER_LEN + fragment_len;
        if buf.len() < record_len {
            return Err(TlsError {
                code: TlsErrorCode::ParseError,
                msg: format!(
                    "invalid record length of {} bytes, rquired {} bytes",
                    record_len,
                    buf.len()
                ),
            });
        }
        match header.legacy_record_version {
            ProtocolVersion::TlsV10 => self.msg_handler_v10(buf),
            ProtocolVersion::TlsV11 => self.msg_handler_v11(buf),
            ProtocolVersion::TlsV12 => self.msg_handler_v12(buf),
            ProtocolVersion::TlsV13 => self.msg_handler_v13(buf),
        }
    }

    fn msg_handler_v10(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        // println!("in TlsSession::msg_handler_v10");

        let mut header_bytes = [0u8; TLS_PLAINTEXT_HEADER_SIZE];
        header_bytes.copy_from_slice(&buf[..TLS_PLAINTEXT_HEADER_SIZE]);
        let header = TlsPlaintextHeader::try_from(&header_bytes)?;
        const HEADER_LEN: usize = TLS_PLAINTEXT_HEADER_SIZE;
        let fragment_len = header.length as usize;
        let record_len = HEADER_LEN + fragment_len;
        let fragment_buf = &buf[HEADER_LEN..record_len];
        dbg!(header.content_type);
        let _handled_len = match header.content_type {
            ContentType::Alert => self.alert_handler(fragment_buf)?,
            ContentType::ApplicationData => self.application_data_handler(fragment_buf)?,
            ContentType::ChangeCipherSpec => self.change_cipher_spec_parser(fragment_buf)?,
            ContentType::Handshake => match self.connection_end {
                ConnectionEnd::Client => todo!(),
                ConnectionEnd::Server => self.serverend_handshake_handler(fragment_buf)?,
            },
            ContentType::Invalid => self.invalid_handler(fragment_buf)?,
        };
        Ok(record_len)
    }

    fn msg_handler_v11(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        // println!("in TlsSession::msg_handler_v11");

        let mut header_bytes = [0u8; TLS_PLAINTEXT_HEADER_SIZE];
        header_bytes.copy_from_slice(&buf[..TLS_PLAINTEXT_HEADER_SIZE]);
        let header = TlsPlaintextHeader::try_from(&header_bytes)?;
        const HEADER_LEN: usize = TLS_PLAINTEXT_HEADER_SIZE;
        let fragment_len = header.length as usize;
        let record_len = HEADER_LEN + fragment_len;
        let fragment_buf = &buf[HEADER_LEN..record_len];
        dbg!(header.content_type);
        let _handled_len = match header.content_type {
            ContentType::Alert => self.alert_handler(fragment_buf)?,
            ContentType::ApplicationData => self.application_data_handler(fragment_buf)?,
            ContentType::ChangeCipherSpec => self.change_cipher_spec_parser(fragment_buf)?,
            ContentType::Handshake => self.serverend_handshake_handler(fragment_buf)?,
            ContentType::Invalid => self.invalid_handler(fragment_buf)?,
        };
        Ok(record_len)
    }

    fn msg_handler_v12(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        // println!("in TlsSession::msg_handler_v12");

        let mut header_bytes = [0u8; TLS_PLAINTEXT_HEADER_SIZE];
        header_bytes.copy_from_slice(&buf[..TLS_PLAINTEXT_HEADER_SIZE]);
        let header = TlsPlaintextHeader::try_from(&header_bytes)?;
        const HEADER_LEN: usize = TLS_PLAINTEXT_HEADER_SIZE;
        let fragment_len = header.length as usize;
        let record_len = HEADER_LEN + fragment_len;
        let fragment_buf = &buf[HEADER_LEN..record_len];
        dbg!(header.content_type);
        let _handled_len = match header.content_type {
            ContentType::Alert => self.alert_handler(fragment_buf)?,
            ContentType::ApplicationData => self.application_data_handler(fragment_buf)?,
            ContentType::ChangeCipherSpec => self.change_cipher_spec_parser(fragment_buf)?,
            ContentType::Handshake => self.serverend_handshake_handler(fragment_buf)?,
            ContentType::Invalid => self.invalid_handler(fragment_buf)?,
        };
        Ok(record_len)
    }

    fn msg_handler_v13(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        // println!("in TlsSession::msg_handler_v13");

        let mut header_bytes = [0u8; TLS_PLAINTEXT_HEADER_SIZE];
        header_bytes.copy_from_slice(&buf[..TLS_PLAINTEXT_HEADER_SIZE]);
        let header = TlsPlaintextHeader::try_from(&header_bytes)?;
        const HEADER_LEN: usize = TLS_PLAINTEXT_HEADER_SIZE;
        let fragment_len = header.length as usize;
        let record_len = HEADER_LEN + fragment_len;
        let fragment_buf = &buf[HEADER_LEN..record_len];
        dbg!(header.content_type);
        let _handled_len = match header.content_type {
            ContentType::Alert => self.alert_handler(fragment_buf)?,
            ContentType::ApplicationData => self.application_data_handler(fragment_buf)?,
            ContentType::ChangeCipherSpec => self.change_cipher_spec_parser(fragment_buf)?,
            ContentType::Handshake => self.serverend_handshake_handler(fragment_buf)?,
            ContentType::Invalid => self.invalid_handler(fragment_buf)?,
        };
        Ok(record_len)
    }

    fn invalid_handler(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        println!("Invalid record received, length {}", buf.len());
        Ok(buf.len())
    }

    fn alert_handler(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        println!("Alert record received, length {}", buf.len());
        Ok(buf.len())
    }

    fn application_data_handler(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        println!("Application Data record received, length {}", buf.len());
        Ok(buf.len())
    }

    fn change_cipher_spec_parser(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        println!("Change Cipher Spec record received, length {}", buf.len());
        self.cipher_suite.cipher.ctx = self.cipher_suite.cipher.cipher_type.new_cipher_ctx(todo!("key_block"));
        Ok(buf.len())
    }
}
