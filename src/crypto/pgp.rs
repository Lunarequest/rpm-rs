use crate::crypto;

use super::*;

use crate::errors::RPMError;

use pem;

use ::pgp::composed::Deserializable;
use ::pgp::crypto::hash::HashAlgorithm;
use ::pgp::de::Deserialize;
use ::pgp::key::PublicKey;
use ::pgp::key::SecretKey;
use ::pgp::packet::{Signature, SignatureVersion};
use ::pgp::types::KeyTrait;
use ::pgp::types::Mpi;
use ::pgp::types::SecretKeyTrait;
#[derive(Clone, Debug)]
pub struct Signer {
    secret_key: ::pgp::composed::signed_key::SignedSecretKey,
}

impl crypto::Signing<crypto::algorithm::RSA> for Signer {
    type Signature = Vec<u8>;
    fn sign(&self, data: &[u8]) -> Result<Self::Signature, RPMError> {
        let passwd_fn = || String::new();

        let mut sig_cfg_bldr = ::pgp::packet::SignatureConfigBuilder::default();
        let sig_cfg = sig_cfg_bldr
            .version(::pgp::packet::SignatureVersion::V4)
            .typ(::pgp::packet::SignatureType::Binary)
            .pub_alg(::pgp::crypto::public_key::PublicKeyAlgorithm::RSA)
            .hash_alg(::pgp::crypto::hash::HashAlgorithm::SHA2_256)
            .issuer(Some(self.secret_key.key_id()))
            .created(Some(::chrono::offset::Utc::now()))
            .unhashed_subpackets(vec![]) // must be initialized
            .hashed_subpackets(vec![
                ::pgp::packet::Subpacket::SignatureCreationTime(::chrono::offset::Utc::now()),
                ::pgp::packet::Subpacket::Issuer(self.secret_key.key_id()),
                //::pgp::packet::Subpacket::SignersUserID("rpm"), TODO this would be a nice addition
            ]) // must be initialized
            .build()?;

        let signature_packet = sig_cfg
            .sign(&self.secret_key, passwd_fn, data)
            .map_err(|e| format!("eee: {:?}", e))?;

        let mut signature_bytes = Vec::with_capacity(512);

        ::pgp::packet::write_packet(&mut signature_bytes, &signature_packet)
            .map_err(|e| format!("eee: {:?}", e))?;

        echo_signature("sign(pgp)", signature_bytes.as_slice());

        Ok(signature_bytes)
    }
}

impl crypto::KeyLoader<crypto::key::Secret> for Signer {
    /// load the private key for signing
    fn load_from(bytes: &[u8]) -> Result<Self, RPMError> {
        let input = ::std::str::from_utf8(bytes).expect("failed to convert to string");
        let (secret_key, _) = ::pgp::composed::signed_key::SignedSecretKey::from_string(input)
            // let secret_key = ::pgp::packet::SecretKey::from_slice(::pgp::types::Version::New, bytes)
            //     .or_else(|_| ::pgp::packet::SecretKey::from_slice(::pgp::types::Version::Old, bytes))
            .map_err(|e| format!("Failed to load secret key {:?}", e))?;
        Ok(Self { secret_key })
    }
}

#[derive(Clone, Debug)]
pub struct Verifier {
    public_key: ::pgp::composed::signed_key::SignedPublicKey,
}

impl crypto::Verifying<crypto::algorithm::RSA> for Verifier {
    type Signature = Vec<u8>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), RPMError> {
        echo_signature("verify(pgp)", signature);

        let signature = ::pgp::packet::Signature::from_slice(::pgp::types::Version::Old, signature)
            .or_else(|e| {
                ::pgp::packet::Signature::from_slice(::pgp::types::Version::New, signature)
            })
            .map_err(|e| format!("Failed to read signature: {:?}", e))?;
        signature
            .verify(&self.public_key, data)
            .map_err(|e| format!("Failed to verify signature: {:?}", e))?;
        Ok(())
    }
}

impl crypto::KeyLoader<crypto::key::Public> for Verifier {
    fn load_from_asc(bytes: &[u8]) -> Result<Self, RPMError> {
        // let cursor = std::io::Cursor::new(bytes);
        // let public_key = ::pgp::composed::signed_key::SignedPublicKey::from_bytes(cursor)
        let input = ::std::str::from_utf8(bytes).expect("failed to convert to string");
        let (public_key, _) = ::pgp::composed::signed_key::SignedPublicKey::from_string(input)
            .map_err(|e| format!("Failed to load public key {:?}", e))?;

        Ok(Self { public_key })
    }

    fn load_from_pkcs8_der(bytes: &u8) -> Result<Self, RPMError> {
        let (n, e, d, p, q) = rsa_der::private_key_from_der(bytes)
            .map_err(|_e| RPMError::new("Failed to parse secret inner der formatted key"))?;
        let secret_key = rsa::RSAPrivateKey::from_components(
            num_bigint_dig::BigUint::from_bytes_be(n.as_slice()),
            num_bigint_dig::BigUint::from_bytes_be(e.as_slice()),
            num_bigint_dig::BigUint::from_bytes_be(d.as_slice()),
            vec![
                num_bigint_dig::BigUint::from_bytes_be(p.as_slice()),
                num_bigint_dig::BigUint::from_bytes_be(q.as_slice()),
            ],
        );
        ::pgp::

        Ok(Self { secret_key })
    }
}

#[cfg(test)]
mod test {

    use crate::crypto::{Algorithm, KeyLoader, Signing, Verifying, RSA};
    use crate::errors::RPMError;

    use crate::signature::test::{load_asc_keys, load_pem_keys, roundtrip_sign_verify};

    use super::Signer;
    use super::Verifier;

    use ::pgp::de::Deserialize;

    // #[test]
    // fn parse_pkcs1_pem_rsa() {
    //     let (signing_key, verification_key) = load_pem_keys();
    //     assert!(dbg!(Signer::load_from(signing_key.as_ref())).is_ok(), );
    //     assert!(dbg!(Verifier::load_from(verification_key.as_ref())).is_ok());
    // }

    #[test]
    fn parse_asc() {
        let (signing_key, verification_key) = load_asc_keys();
        assert!(Signer::load_from(signing_key.as_ref()).is_ok());
        assert!(Verifier::load_from(verification_key.as_ref()).is_ok());
    }

    // #[test]
    // fn ref_sign_verify_round() {
    //     let (rfc4880, raw) =
    //         crate::crypto::gen_rfc4880().expect("Failed to generated rfc4880 ref package");
    //     let signature =
    //         ::pgp::packet::Signature::from_slice(::pgp::types::Version::Old, rfc4880.as_slice())
    //             .or_else(|e| {
    //                 ::pgp::packet::Signature::from_slice(
    //                     ::pgp::types::Version::New,
    //                     rfc4880.as_slice(),
    //                 )
    //             })
    //             .map_err(|e| format!("Failed to read signature: {:?}", e))
    //             .expect("Failed parse ref rfc4880");
    // }

    #[test]
    fn sign_verify_round() {
        let (signing_key, verification_key) = load_asc_keys();

        let data = b"dfsdfjsd9ivnq320348934752312308205723900000580134850sdf";

        roundtrip_sign_verify::<Signer, Verifier, _>(
            data,
            signing_key.as_ref(),
            verification_key.as_ref(),
        )
        .expect("sign verify roundtrip must always be ok");
    }
}
