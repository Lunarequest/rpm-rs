//! Trait abstractions of cryptographic operations.
//!
//! Does not contain hashing! Hashes are fixed by the rpm
//! "spec" to sha1, md5 (yes, that is correct), sha2_256.

use crate::errors::*;
use std::fmt::Debug;


pub mod algorithm {

    pub trait Algorithm: super::Debug {}
    /// currently only RSA is required
    ///
    /// Farsight for future algorithm extensions of rpm
    /// without breaking the API
    #[derive(Debug, Clone, Copy)]
    #[allow(non_camel_case_types)]


    pub struct RSA;

    impl Algorithm for RSA {}
    }

}

use pem;
use rsa_der;
use rsa;

/// Signing trait to be implement for RPM signing.
pub trait Signing<A>: Debug
where
    A: algorithm::Algorithm,
    Self::Signature: AsRef<[u8]>,
{
    type Signature;
    fn sign(&self, data: &[u8]) -> Result<Self::Signature, RPMError>;
}

/// Verification trait to be implement for RPM signature verification.
pub trait Verifying<A>: Debug
where
    A: algorithm::Algorithm,
    Self::Signature: AsRef<[u8]>,
{
    type Signature;
    fn verify(&self, data: &[u8], x: &[u8]) -> Result<(), RPMError>;
}




pub mod key {
pub trait KeyType : super::Debug + Copy {}

#[derive(Debug, Clone, Copy)]
pub struct Secret;
#[derive(Debug, Clone, Copy)]
pub struct Public;

impl KeyType for Secret {}
impl KeyType for Public {}
}

/// Public and secret key loading trait.
///
/// Supposed to load application specific formatted keys with
/// `fn load_from` in whatever format is desired or used by the
/// [`Signer`](Self::Signing) or [`Verifier`](Self::Verifying) itself.
pub trait KeyLoader<T>: Sized where T: key::KeyType {
    /// An application specific key loader.
    ///
    /// Should be implemented as a combination of the particular ones.
    fn load_from(bytes: &[u8]) -> Result<Self, RPMError>;

    /// Load a key from ascii armored key string.
    fn load_from_asc(_asc: &str) -> Result<Self, RPMError> {
        unimplemented!("ASCII ARMORED is not implemented")
    }

    /// Load a key from DER ASN.1 formatted bytes in PKCS#1 format.
    ///
    /// Its preamble is `-----BEGIN RSA (PRIVATE|PUBLIC) KEY-----`
    fn load_from_pkcs1_der(_pkcs1_der: &[u8]) -> Result<Self, RPMError> {
        unimplemented!("PKCS#1 der loading is not implemented")
    }

    /// Load a key from DER ASN.1 formatted bytes in PKCS#8 format.
    ///
    /// Its preamble is `-----BEGIN (ENCRYPTED)? (PRIVATE|PUBLIC) KEY-----`
    fn load_from_pkcs8_der(_pkcs8_der: &[u8]) -> Result<Self, RPMError> {
        unimplemented!("PKCS#8 der loading is not implemented")
    }

    /// Load a key from PEM formatted string in PKCS#8 or PKCS#1 internal format.
    fn load_from_pem(pem: &str) -> Result<Self, RPMError> {
        let pem = pem::parse(pem)
            .map_err(|e| format!("Failed to parse pem format: {:?}", e).into())?;
        // PEM may containe any kind of key format, so at least support
        // well know PKCS#1 and PKCS#8 formats
        match pem.tag {
            "RSA PRIVATE KEY" | "RSA PUBLIC KEY" => Self::load_from_pkcs1_der(pem.contents.as_slice()),
            "PRIVATE KEY" | "PUBLIC KEY" => Self::load_from_pkcs8_der(pem.contents.as_slice()),
            _ => Err(RPMError::from("Unknown key delimiter, only supporting PKCS#8 or PKCS#1 PRIVATE/PUBLIC keys")),
        }
    }

    /// Load a key from the openssh specific format.
    fn load_from_openssh(_openssh: &[u8]) -> Result<Self, RPMError> {
        unimplemented!("OpenSSH loading is not implemented")
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
