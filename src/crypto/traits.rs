//! Trait abstractions of cryptographic operations.
//!
//! Does not contain hashing! Hashes are fixed by the rpm
//! "spec" to sha1, md5 (yes, that is correct), sha2_256.

use crate::errors::*;

pub trait Algorithm: Debug {}

/// currently only RSA is required
///
/// Farsight for future algorithm extensions of rpm
/// without breaking the API
#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct RSA;

impl Algorithm for RSA {}

use std::fmt::Debug;

/// Signing trait to be implement for RPM signing.
pub trait Signing<A>: Debug
where
    A: Algorithm,
    Self::Signature: AsRef<[u8]>,
{
    type Signature;
    fn sign(&self, data: &[u8]) -> Result<Self::Signature, RPMError>;
}

/// Verification trait to be implement for RPM signature verification.
pub trait Verifying<A>: Debug
where
    A: Algorithm,
    Self::Signature: AsRef<[u8]>,
{
    type Signature;
    fn verify(&self, data: &[u8], x: &[u8]) -> Result<(), RPMError>;
}

/// Public and secret key loading trait.
///
/// Supposed to load application specific formatted keys with
/// `fn load_from` in whatever format is desired or used by the
/// [`Signer`](Self::Signing) or [`Verifier`](Self::Verifying) itself.
pub trait KeyLoader: Sized {
    fn load_from(bytes: &[u8]) -> Result<Self, RPMError>;
    fn load_from_asc(_asc: &str) -> Result<Self, RPMError> {
        unimplemented!("ASCII ARMORED is not implemented")
    }
    fn load_from_pkcs1_der(_pkcs1_der: &[u8]) -> Result<Self, RPMError> {
        unimplemented!("pkcs1 der loading is not implemented")
    }
    fn load_from_pem(_pem: &str) -> Result<Self, RPMError> {
        unimplemented!("PEM loading is not implemented")
    }
}

/// Implement unreachable signer for empty tuple `()`
impl<A> Signing<A> for std::marker::PhantomData<A>
where
    A: Algorithm,
{
    type Signature = Vec<u8>;
    fn sign(&self, _data: &[u8]) -> Result<Self::Signature, RPMError> {
        unreachable!("if you want to verify, you need to implement `sign` of the `Signing` trait")
    }
}

/// Implement unreachable verifier for the empty tuple`()`
impl<A> Verifying<A> for std::marker::PhantomData<A>
where
    A: Algorithm,
{
    type Signature = Vec<u8>;
    fn verify(&self, _data: &[u8], _x: &[u8]) -> Result<(), RPMError> {
        unreachable!(
            "if you want to verify, you need to implement `verify` of the `Verifying` trait"
        )
    }
}
