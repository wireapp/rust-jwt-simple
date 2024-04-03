mod eddsa;
mod es256;
mod es256k;
mod es384;
mod es512;
mod hmac;

#[cfg(all(
    feature = "rsa",
    not(any(target_arch = "wasm32", target_arch = "wasm64"))
))]
mod rsa;
#[cfg(all(feature = "rsa", any(target_arch = "wasm32", target_arch = "wasm64")))]
mod rsa_legacy;

pub use self::eddsa::*;
pub use self::es256::*;
pub use self::es256k::*;
pub use self::es384::*;
pub use self::es512::*;
pub use self::hmac::*;

#[cfg(all(
    feature = "rsa",
    not(any(target_arch = "wasm32", target_arch = "wasm64"))
))]
pub use self::rsa::*;
#[cfg(all(feature = "rsa", any(target_arch = "wasm32", target_arch = "wasm64")))]
pub use self::rsa_legacy::*;
