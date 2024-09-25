use std::io::Write;


use server_hello::ServerHello;

use crate::{
    cipher_suite::*,
    error::{TlsError, TlsErrorCode},
    session::{
        handshake::{client_hello::ClientHello, *}, ContentType, ProtocolVersion, TlsPlaintextHeader, TlsSession,
        PROTOCOL_VERSION_SIZE,
    },
};

impl TlsSession {
    pub(crate) fn serverend_handshake_handler(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        eprintln!("Handshake record received, length {:?}", buf.len());

        let header = HandshakeHeader::try_from(&buf[0..HANDSHAKE_HEADER_SIZE])?;
        let fragment_len: usize = header.length.into();
        let serverend_handshake_len = HANDSHAKE_HEADER_SIZE + fragment_len;

        match header.handshake_type {
            HandshakeType::ClientHello => self.serverend_handshake_client_hello_handler(
                &buf[HANDSHAKE_HEADER_SIZE..serverend_handshake_len],
            ),
            _ => Err(TlsError {
                code: TlsErrorCode::ParseError,
                msg: format!(
                    "invalid handshake type({:02x})",
                    header.handshake_type as u8
                ),
            }),
        }
    }

    fn serverend_handshake_client_hello_handler(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        let version = ProtocolVersion::try_from({
            let mut bytes = [0u8; PROTOCOL_VERSION_SIZE];
            bytes.copy_from_slice(&buf[..PROTOCOL_VERSION_SIZE]);
            u16::from_be_bytes(bytes)
        })?;
        match version {
            ProtocolVersion::TlsV10 => self.serverend_handshake_client_hello_handler_v10(buf),
            ProtocolVersion::TlsV11 => self.serverend_handshake_client_hello_handler_v10(buf),
            ProtocolVersion::TlsV12 => self.serverend_handshake_client_hello_handler_v12(buf),
            _ => Err(TlsError {
                code: TlsErrorCode::ParseError,
                msg: format!("Invalid protocol version ({:?}) in Client Hello", version),
            }),
        }
    }

    fn serverend_handshake_client_hello_parser(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        let client_hello = ClientHello::try_from(buf)?;

        let handshake_info = self.handshake_info.as_mut().unwrap().as_mut();
        handshake_info.version = client_hello.version;
        self.cipher_suite = CipherSuite::choose(&client_hello.cipher_suites_values)?;
        handshake_info.client_random = client_hello.random;
        handshake_info.parse_extensions(&client_hello.extensions)?;

        self.tls_version = client_hello.version;
        // self.session_id = client_hello.session_id;

        Ok(buf.len())
    }

    fn serverend_handshake_client_hello_handler_v10(
        &mut self,
        buf: &[u8],
    ) -> Result<usize, TlsError> {
        println!("serverend_handshake_client_hello_handler_v10");

        let handled = self.serverend_handshake_client_hello_parser(buf)?;

        match self.serverend_handshake_server_hello_handler() {
            Ok(_) => {}
            Err(err) => panic!("{}", err.to_string()),
        };
        Ok(handled)
    }

    fn serverend_handshake_client_hello_handler_v12(
        &mut self,
        buf: &[u8],
    ) -> Result<usize, TlsError> {
        println!("serverend_handshake_client_hello_handler_v12");

        let handled = self.serverend_handshake_client_hello_parser(buf)?;
        self.serverend_handshake_server_hello_handler()?;
        self.serverend_server_change_cipher_spec()?;
        self.serverend_handshake_encrypted_extensions_handler()?;

        println!("flushing");
        if let Err(err) = self.io_stream.flush() {
            return Err(TlsError {
                code: TlsErrorCode::IoError(err),
                msg: "failed to flush output stream".to_string(),
            });
        }

        Ok(handled)
    }

    fn serverend_handshake_server_hello_builder(&mut self) -> Result<Vec<u8>, TlsError> {
        let handshake_info = self.handshake_info.as_ref().unwrap().as_ref();

        let server_hello = ServerHello {
            version: match self.tls_version {
                ProtocolVersion::TlsV13 => ProtocolVersion::TlsV12,
                _ => self.tls_version,
            },
            random: handshake_info.server_random,
            session_id: self.session_id.clone(),
            cipher_suite: CipherSuiteValue::from(self.cipher_suite.value),
            compression_method: 0u8,
            extensions: handshake_info.build_extensions()?,
        };

        Ok(server_hello.to_be_bytes())
    }

    fn serverend_handshake_server_hello_handler(&mut self) -> Result<usize, TlsError> {
        let handshake_fragment = self.serverend_handshake_server_hello_builder()?;

        let handshake_record_len: usize = HANDSHAKE_HEADER_SIZE + handshake_fragment.len();

        let tls_plaintext_header = TlsPlaintextHeader {
            content_type: ContentType::Handshake,
            legacy_record_version: match self.tls_version {
                ProtocolVersion::TlsV13 => ProtocolVersion::TlsV12,
                _ => self.tls_version,
            },
            length: handshake_record_len as u16,
        };

        let handshake_header = HandshakeHeader {
            handshake_type: HandshakeType::ServerHello,
            length: HandshakeLength::from(handshake_fragment.len()),
        };

        let mut buf: Vec<u8> = Vec::with_capacity(handshake_record_len);
        buf.extend(handshake_header.to_bytes());
        buf.extend(handshake_fragment);

        self.write_record(tls_plaintext_header, buf.as_slice())
    }

    fn serverend_handshake_encrypted_extensions_builder(&mut self) -> Result<Vec<u8>, TlsError> {
        Ok([
            0x08, // Handshake Type: Encrypted Extensions (8)
            0x00, 0x00, 0x02, // Length: 2
            0x00, 0x00, // Extensions Length: 0
        ]
        .to_vec())
    }

    fn serverend_handshake_encrypted_extensions_handler(&mut self) -> Result<usize, TlsError> {
        let encrypted_extensions = self.serverend_handshake_encrypted_extensions_builder()?;

        match self.write(encrypted_extensions.as_slice()) {
            Ok(size) => Ok(size),
            Err(err) => Err(TlsError {
                code: TlsErrorCode::IoError(err),
                msg: format!("IO Error"),
            }),
        }
    }
}
