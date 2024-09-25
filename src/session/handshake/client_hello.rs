use crate::{error::{TlsError, TlsErrorCode}, session::{handshake::{Extension, CIPHER_SUITE_LEN_SIZE, COMPRESSION_METHOD_LEN_SIZE, EXTENSION_LEN_SIZE, RANDOM_SIZE, SESSION_ID_LEN_SIZE}, CipherSuiteValue, ProtocolVersion, PROTOCOL_VERSION_SIZE}};

pub(crate) struct ClientHello {
    pub version: ProtocolVersion,
    pub random: [u8; RANDOM_SIZE],
    pub _session_id: Vec<u8>,
    pub cipher_suites_values: Vec<CipherSuiteValue>,
    pub _compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl ClientHello {

    fn throw_parse_error_too_short() -> TlsError {
        TlsError {
            code: TlsErrorCode::ParseError,
            msg: format!("failed to parse client hello, slice length too short"),
        }
    }

    fn parse_version(data: &[u8]) -> Result<ProtocolVersion, TlsError> {
        if data.len() < PROTOCOL_VERSION_SIZE {
            Err(Self::throw_parse_error_too_short())
        } else {
            assert!(data.len() == PROTOCOL_VERSION_SIZE);
            let version = ProtocolVersion::try_from({
                let mut version_bytes = [0u8; PROTOCOL_VERSION_SIZE];
                version_bytes.copy_from_slice(data);
                u16::from_be_bytes(version_bytes)
            });
            // dbg!(version);
            version
        }
    }

    fn parse_random(data: &[u8]) -> Result<[u8; RANDOM_SIZE], TlsError> {
        if data.len() < RANDOM_SIZE {
            Err(Self::throw_parse_error_too_short())
        } else {
            assert!(data.len() == RANDOM_SIZE);
            let mut client_random = [0u8; RANDOM_SIZE];
            client_random.copy_from_slice(data);
            eprintln!("client_random: {:02x?}", client_random);
            Ok(client_random)
        }
    }

    fn parse_session_id_len(data: &[u8]) -> Result<usize, TlsError> {
        if data.len() < SESSION_ID_LEN_SIZE {
            Err(Self::throw_parse_error_too_short())
        } else {
            assert!(data.len() == SESSION_ID_LEN_SIZE);
            let client_session_id_len = data[0] as usize;
            // dbg!(client_session_id_len);
            Ok(client_session_id_len)
        }
    }

    fn parse_session_id(data: &[u8]) -> Vec<u8> {
        let client_session_id = Vec::from(data);
        // eprintln!("client_session_id: {:02x?}", client_session_id);
        client_session_id
    }

    fn parse_cipher_suite_len(data: &[u8]) -> Result<usize, TlsError> {
        if data.len() < SESSION_ID_LEN_SIZE {
            Err(Self::throw_parse_error_too_short())
        } else {
            assert!(data.len() == CIPHER_SUITE_LEN_SIZE);
            let cipher_suite_len = u16::from_be_bytes([data[0], data[1]]) as usize;
            // dbg!(cipher_suite_len);
            Ok(cipher_suite_len)
        }
    }

    fn parse_cipher_suites(data: &[u8]) -> Vec<CipherSuiteValue> {
        use crate::cipher_suite::CIPHER_SUITE_VALUE_SIZE;
        assert!(data.len() % CIPHER_SUITE_VALUE_SIZE == 0);
        let cipher_suites_num = data.len() / CIPHER_SUITE_VALUE_SIZE;
        let cipher_suites_values: Vec<CipherSuiteValue> = (0..cipher_suites_num)
            .map(|i| {
                CipherSuiteValue::from(u16::from_be_bytes([
                    data[CIPHER_SUITE_VALUE_SIZE * i],
                    data[CIPHER_SUITE_VALUE_SIZE * i + 1],
                ]))
            })
            .collect();
        eprintln!("client cipher suites values: {:?}", cipher_suites_values);
        cipher_suites_values
    }

    fn parse_compression_methods_len(data: &[u8]) -> Result<usize, TlsError> {
        if data.len() < COMPRESSION_METHOD_LEN_SIZE {
            Err(Self::throw_parse_error_too_short())
        } else {
            assert!(data.len() == COMPRESSION_METHOD_LEN_SIZE);
            let compression_methods_len = data[0] as usize;
            dbg!(compression_methods_len);
            Ok(compression_methods_len)
        }
    }

    fn parse_compression_methods(data: &[u8]) -> Vec<u8> {
        let compression_methods = Vec::from(data);
        eprintln!("compression methods: {:02x?}", compression_methods);
        compression_methods
    }

    fn parse_extension_len(data: &[u8]) -> Result<usize, TlsError> {
        if data.len() < EXTENSION_LEN_SIZE {
            Err(Self::throw_parse_error_too_short())
        } else {
            assert!(data.len() == EXTENSION_LEN_SIZE);
            let extensions_len = u16::from_be_bytes([data[0], data[1]]) as usize;
            // dbg!(extensions_len);
            Ok(extensions_len)
        }
    }

    fn parse_extensions(data: &[u8]) -> Result<Vec<Extension>, TlsError> {
        let client_extensions = Extension::parse(data);
        // dbg!(client_extensions);
        client_extensions
    }
    
}

impl TryFrom<&[u8]> for ClientHello {
    type Error = TlsError;

    fn try_from(mut buf: &[u8]) -> Result<Self, TlsError> {
        let version = Self::parse_version(&buf[..PROTOCOL_VERSION_SIZE])?;
        buf = &buf[PROTOCOL_VERSION_SIZE..];

        let client_random = Self::parse_random(&buf[..RANDOM_SIZE])?;
        buf = &buf[RANDOM_SIZE..];

        let session_id_len = Self::parse_session_id_len(&buf[..SESSION_ID_LEN_SIZE])?;
        buf = &buf[SESSION_ID_LEN_SIZE..];

        let client_session_id = Self::parse_session_id(&buf[..session_id_len]);
        buf = &buf[session_id_len..];

        let cipher_suites_len = Self::parse_cipher_suite_len(&buf[..CIPHER_SUITE_LEN_SIZE])?;
        buf = &buf[CIPHER_SUITE_LEN_SIZE..];
        
        let cipher_suites_values = Self::parse_cipher_suites(&buf[..cipher_suites_len]);
        buf = &buf[cipher_suites_len..];

        let compression_methods_len = Self::parse_compression_methods_len(&buf[..COMPRESSION_METHOD_LEN_SIZE])?;
        buf = &buf[COMPRESSION_METHOD_LEN_SIZE..];

        let compression_methods = Self::parse_compression_methods(&buf[..compression_methods_len]);
        buf = &buf[compression_methods_len..];

        if 0 == buf.len() {
            return Ok(Self {
                version: version,
                random: client_random,
                _session_id: client_session_id,
                cipher_suites_values: cipher_suites_values,
                _compression_methods: compression_methods,
                extensions: vec![],
            });
        }

        let extensions_len = Self::parse_extension_len(&buf[..EXTENSION_LEN_SIZE])?;
        buf = &buf[EXTENSION_LEN_SIZE..];

        let extensions = Self::parse_extensions(&buf[..extensions_len])?;
        buf = &buf[extensions_len..];

        match 0 == buf.len() {
            true => Ok(Self {
                version: version,
                random: client_random,
                _session_id: client_session_id,
                cipher_suites_values: cipher_suites_values,
                _compression_methods: compression_methods,
                extensions: extensions,
            }),
            false => Err(TlsError {
                code: TlsErrorCode::ParseError,
                msg: format!("failed to parse client hello"),
            }),
        }
    }
}
