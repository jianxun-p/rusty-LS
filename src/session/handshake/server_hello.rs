use cryptrust::num_traits::ToBytes;

use crate::session::{handshake::SESSION_ID_LEN, CipherSuiteValue, ProtocolVersion};

use super::{Extension, RANDOM_SIZE};


pub(crate) struct ServerHello {
    pub version: ProtocolVersion,
    pub random: [u8; RANDOM_SIZE],
    pub session_id: Vec<u8>,
    pub cipher_suite: CipherSuiteValue,
    pub compression_method: u8,
    pub extensions: Vec<Extension>,
}


impl ServerHello {
    pub fn to_be_bytes(&self) -> Vec<u8> {
        println!("in TlsSession::serverend_handshake_server_hello_handler");

        // minimum length (not including extensions)
        const HANDSHAKE_SERVER_HELLO_FRAGMENT_LEN: usize =
            2 + RANDOM_SIZE + 1 + SESSION_ID_LEN + 2 + 1;

        let mut buf: Vec<u8> = Vec::with_capacity(HANDSHAKE_SERVER_HELLO_FRAGMENT_LEN);

        // server_version: ProtocolVersion
        buf.extend(self.version.to_be_bytes());

        // server_random: [u8; RANDOM_SIZE]
        buf.extend(self.random.iter());

        // session_id: [u8; SESSION_ID_LEN]
        let session_id_len = self.session_id.len();
        buf.push(session_id_len as u8);
        buf.extend(&self.session_id);

        // cipher_suite: CipherSuite
        buf.extend(self.cipher_suite.to_be_bytes());

        // compression_method: u8
        buf.push(self.compression_method);

        // extensions
        match self.version {
            ProtocolVersion::TlsV10 | ProtocolVersion::TlsV11 => {}
            ProtocolVersion::TlsV12 | ProtocolVersion::TlsV13 => {
                let mut extensions_bytes = Vec::new();
                for extension in self.extensions.iter() {
                    extensions_bytes.extend(extension.to_be_bytes());
                }
                buf.extend((extensions_bytes.len() as u16).to_be_bytes());
                buf.extend(extensions_bytes);
            }
        };

        buf
    }
}

