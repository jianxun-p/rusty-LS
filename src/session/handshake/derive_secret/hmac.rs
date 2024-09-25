use std::marker::PhantomData;

use digest::{Digest, OutputSizeUser};
use hmac::Mac;


pub(crate) struct Hmac<'a, D: Digest> {
    key: &'a [u8; <D as Digest>::output_size()],
    phantom: PhantomData<D>,
}

impl<D: Digest> OutputSizeUser for Hmac<'_, D> {
    type OutputSize = D::OutputSize;
    fn output_size() -> usize {
        <D as Digest>::output_size()
    }
}

impl<D: Digest> Mac for Hmac<'_, D> {
    fn new<'a>(key: &'a digest::Key<Self>) -> Self
    where
        Self: digest::KeyInit {
            Self {
                key: key,
                phantom: PhantomData, 
            }
        // todo!()
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, digest::InvalidLength>
    where
        Self: digest::KeyInit {
        todo!()
    }

    fn update(&mut self, data: &[u8]) {
        todo!()
    }

    fn chain_update(self, data: impl AsRef<[u8]>) -> Self {
        todo!()
    }

    fn finalize(self) -> digest::CtOutput<Self> {
        todo!()
    }

    fn finalize_reset(&mut self) -> digest::CtOutput<Self>
    where
        Self: digest::FixedOutputReset {
        todo!()
    }

    fn reset(&mut self)
    where
        Self: digest::Reset {
        todo!()
    }

    fn verify(self, tag: &digest::Output<Self>) -> Result<(), digest::MacError> {
        todo!()
    }

    fn verify_reset(&mut self, tag: &digest::Output<Self>) -> Result<(), digest::MacError>
    where
        Self: digest::FixedOutputReset {
        todo!()
    }

    fn verify_slice(self, tag: &[u8]) -> Result<(), digest::MacError> {
        todo!()
    }

    fn verify_slice_reset(&mut self, tag: &[u8]) -> Result<(), digest::MacError>
    where
        Self: digest::FixedOutputReset {
        todo!()
    }

    fn verify_truncated_left(self, tag: &[u8]) -> Result<(), digest::MacError> {
        todo!()
    }

    fn verify_truncated_right(self, tag: &[u8]) -> Result<(), digest::MacError> {
        todo!()
    }
}