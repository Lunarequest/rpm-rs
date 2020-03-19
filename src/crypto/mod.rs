mod traits;
pub use self::traits::*;

#[cfg(feature = "signing-ring")]
pub mod ring;

#[cfg(feature = "signing-pgp")]
pub mod pgp;

mod rfc4880;

pub use rfc4880::*;

// use pem;

// impl<T> KeyToPEM for T where T: KeyToDER {
//     fn from_pem(pem : &str) -> Result<Self> {
//         let pem_obj = pem::parse(secret_key_pem)
//             .map_err(|_e| RPMError::new("Failed to parse secret pem key"))?;
//         let _ = dbg!(pem_obj.tag);
//         Self::from_der(tag, &x.contents[..])

//         pem_obj.encode()
//         let _ = pem_obj.tag;
//         Self::from_der(tag, &x.contents[..])
//     }
// }

// impl<T> KeyFromPEM for T where T: KeyFromDER {
//     fn to_pem(&self) -> Result<String> {
//         let der = self.to_der();
//         let pem_obj = pem::Pem {
//             tag : dbg!(self.tag()),
//             contents : der,
//         };

//         pem::encode(&pem_obj)
//             .map_err(|_e| RPMError::new("Failed to parse PEM"))
//     }
// }

pub(crate) fn echo_signature(scope: &str, signature: &[u8]) {
    println!("{}: [len={}] {:#02x?}", scope, signature.len(), signature);
}
