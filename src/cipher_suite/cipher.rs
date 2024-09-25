use cryptrust::{cipher::*, key::Key};

use crate::session::{TlsPlaintextHeader, TlsSession};




const TEST_VALUE_EXPLICIT_NONCE: [u8; 8] = [1,2,3,4,5,6,7,8];


#[allow(unused)]
#[derive(Debug)]
pub struct KeyBlock {
    read: Vec<u8>,
    write: Vec<u8>,
    read_iv: Vec<u8>,
    write_iv: Vec<u8>,
    read_mac: Vec<u8>,
    write_mac: Vec<u8>,
}


#[allow(unused)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) enum TlsCipherType {
    #[default]
    Null,
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
}

#[derive(Debug, Default)]
pub(crate) struct TlsCipher {
    pub(crate) cipher_type: TlsCipherType,
    pub(crate) ctx: TlsCipherCtx,
}


#[derive(Debug, Default)]
pub(crate) enum TlsCipherCtx {
    #[default]
    Null,
    Aes128Gcm((Aes128Gcm, Vec<u8>), (Aes128Gcm, Vec<u8>)),
    Aes192Gcm((Aes192Gcm, Vec<u8>), (Aes192Gcm, Vec<u8>)),
    Aes256Gcm((Aes256Gcm, Vec<u8>), (Aes256Gcm, Vec<u8>)),
}

impl TlsCipher {
    pub const fn new() -> Self {
        Self {
            cipher_type: TlsCipherType::Null, 
            ctx: TlsCipherCtx::Null, 
        }
    }
}


impl TlsCipherType {
    pub fn new_cipher_ctx(self, key_block: KeyBlock) -> TlsCipherCtx {
        match self {
            TlsCipherType::Null => TlsCipherCtx::Null,
            TlsCipherType::Aes128Gcm => {
                TlsCipherCtx::Aes128Gcm(
                    (GCM::new(
                        AES128Key::from_slice(key_block.read.as_slice()), 
                        AES128::encrypt,
                    ),
                    key_block.read_iv),
                    (GCM::new(
                        AES128Key::from_slice(key_block.write.as_slice()), 
                        AES128::encrypt,
                    ),
                    key_block.write_iv),
                )
            },
            TlsCipherType::Aes192Gcm => {
                TlsCipherCtx::Aes192Gcm(
                    (GCM::new(
                        AES192Key::from_slice(key_block.read.as_slice()), 
                        AES192::encrypt,
                    ),
                    key_block.read_iv),
                    (GCM::new(
                        AES192Key::from_slice(key_block.write.as_slice()), 
                        AES192::encrypt,
                    ),
                    key_block.write_iv),
                )
            },
            TlsCipherType::Aes256Gcm => {
                TlsCipherCtx::Aes256Gcm(
                    (GCM::new(
                        AES256Key::from_slice(key_block.read.as_slice()), 
                        AES256::encrypt,
                    ),
                    key_block.read_iv),
                    (GCM::new(
                        AES256Key::from_slice(key_block.write.as_slice()), 
                        AES256::encrypt,
                    ),
                    key_block.write_iv),
                )
            },
        }
    }
}

/// see https://www.rfc-editor.org/rfc/rfc5116#section-3.2.1
/// see https://www.rfc-editor.org/rfc/rfc5246#section-6.3
fn aead_nonce(implicit_iv: &[u8], explicit_iv: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(implicit_iv.len() + explicit_iv.len());
    v.extend_from_slice(implicit_iv);
    v.extend_from_slice(explicit_iv);
    v
}


/// see https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3.3
fn additional_data(seq_num: u64, header: TlsPlaintextHeader) -> Vec<u8> {
    let seq_n = seq_num.to_be_bytes();
    let h = header.to_bytes();
    let mut v = Vec::with_capacity(seq_n.len() + h.len());
    v.extend(seq_n);
    v.extend(h);
    v
}


type GcmBlkCipher<K> = fn(&[u8; GCM_BLK_SIZE], &K) -> [u8; GCM_BLK_SIZE];

impl TlsSession {

    /// https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3.3
    fn gcm_decrypt<K: Key>(
        &self, 
        gcm_ctx: &GCM<K, GcmBlkCipher<K>>, 
        implicit_iv: &[u8],
        generic_aead_cipher: &[u8], 
        header: TlsPlaintextHeader, 
    ) -> Option<Vec<u8>> {
        const RECORD_IV_LENGTH: usize = 8;
        let explicit_iv = Vec::from(&generic_aead_cipher[..RECORD_IV_LENGTH]);
        let cipher_content = Vec::from(&generic_aead_cipher[RECORD_IV_LENGTH..]);
        let ciphertext = Vec::from(&cipher_content[..cipher_content.len() - GCM_BLK_SIZE]);
        let tag = Vec::from(&cipher_content[cipher_content.len() - GCM_BLK_SIZE..]);
        let nonce: Vec<u8> = aead_nonce(implicit_iv, explicit_iv.as_slice());
        let aad = additional_data(self.io_sequence_num.1, header);
        if gcm_ctx.authentication_tag(ciphertext.as_slice(), nonce.as_slice(), aad.as_slice()) == tag {
            Some(gcm_ctx.decrypt(ciphertext.as_slice(), nonce.as_slice()))
        } else {
            None
        }
    }

    /// https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3.3
    fn gcm_encrypt<K: Key>(
        &self, 
        gcm_ctx: &GCM<K, GcmBlkCipher<K>>, 
        implicit_iv: &[u8],
        plaintext: &[u8], 
        header: TlsPlaintextHeader, 
    ) -> Vec<u8> {
        const RECORD_IV_LENGTH: usize = 8;
        let nonce: Vec<u8> = aead_nonce(implicit_iv, &TEST_VALUE_EXPLICIT_NONCE[..RECORD_IV_LENGTH]);
        let aad = additional_data(self.io_sequence_num.0, header);
        let ciphertext = gcm_ctx.encrypt(plaintext, nonce.as_slice());
        let tag = gcm_ctx.authentication_tag(ciphertext.as_slice(), nonce.as_slice(), aad.as_slice());
        let mut generic_aead_cipher = Vec::new();
        generic_aead_cipher.extend(TEST_VALUE_EXPLICIT_NONCE);
        generic_aead_cipher.extend(ciphertext);
        generic_aead_cipher.extend(tag);
        generic_aead_cipher
    }
    

    pub fn decrypt(&self, cipher_fragment: &[u8], header: TlsPlaintextHeader) -> Option<Vec<u8>> {
        match &self.cipher_suite.cipher.ctx {
            TlsCipherCtx::Null => Some(Vec::from(cipher_fragment)),
            TlsCipherCtx::Aes128Gcm(ctx, _) => {
                self.gcm_decrypt(&ctx.0, ctx.1.as_slice(), cipher_fragment, header)
            },
            TlsCipherCtx::Aes192Gcm(ctx, _) => {
                self.gcm_decrypt(&ctx.0, ctx.1.as_slice(), cipher_fragment, header)
            },
            TlsCipherCtx::Aes256Gcm(ctx, _) => {
                self.gcm_decrypt(&ctx.0, ctx.1.as_slice(), cipher_fragment, header)
            },
        }
    }

    pub fn encrypt(&mut self, compressed: &[u8], header: TlsPlaintextHeader) -> Vec<u8> {
        match &self.cipher_suite.cipher.ctx {
            TlsCipherCtx::Null => Vec::from(compressed),
            TlsCipherCtx::Aes128Gcm(_, ctx) => {
                self.gcm_encrypt(&ctx.0, ctx.1.as_slice(), compressed, header)
            },
            TlsCipherCtx::Aes192Gcm(_, ctx) => {
                self.gcm_encrypt(&ctx.0, ctx.1.as_slice(), compressed, header)
            },
            TlsCipherCtx::Aes256Gcm(_, ctx) => {
                self.gcm_encrypt(&ctx.0, ctx.1.as_slice(), compressed, header)
            },
        }
    }

}

