

pub(crate) const PROTOCOL_VERSION_SIZE: usize = 2;
rfc_enum!(
    [Clone, Copy, Debug, PartialEq, Eq]
    (pub) ProtocolVersion: u16;
    TlsV10(0x0301),
    TlsV11(0x0302),
    TlsV12(0x0303),
    TlsV13(0x0304),
);

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::TlsV12
    }
}
