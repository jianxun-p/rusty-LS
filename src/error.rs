#[derive(Debug,)]
pub enum TlsErrorCode {
    ParseError,
    SecurityError,
    IoError(std::io::Error),
}

#[derive(Debug)]
pub struct TlsError {
    pub code: TlsErrorCode,
    pub msg: String,
}

impl ToString for TlsError {
    fn to_string(&self) -> String {
        self.msg.clone()
    }
}
