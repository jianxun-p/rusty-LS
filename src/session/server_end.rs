mod handshake;

use crate::{
    error::TlsError,
    session::{ContentType, ProtocolVersion, TlsPlaintextHeader, TlsSession},
};

impl TlsSession {
    pub(super) fn serverend_server_change_cipher_spec(&mut self) -> Result<usize, TlsError> {
        println!("in TlsSession::serverend_server_change_cipher_spec");

        let header = TlsPlaintextHeader {
            content_type: ContentType::ChangeCipherSpec,
            legacy_record_version: ProtocolVersion::TlsV13,
            length: 1,
        };
        let fragment = [1u8; 1];

        self.write_record(header, fragment.as_slice())
    }
}
