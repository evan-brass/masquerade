#[allow(unused_imports)]
use super::{Attr, AttrEnc, FINGERPRINT, MESSAGE_INTEGRITY, MESSAGE_INTEGRITY_SHA256, Prefix};

// Decoding is always available, but encoding / verifying requires openssl
pub struct Integrity<'i, const L: usize> {
	pub prefix: Prefix<'i>,
	pub mac: &'i [u8; L],
}

impl<'i> Attr<'i, MESSAGE_INTEGRITY> for Integrity<'i, 20> {
	type Error = core::array::TryFromSliceError;
	fn must_precede(typ: u16) -> bool {
		typ == FINGERPRINT
	}
	fn decode(prefix: Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error> {
		Ok(Self {
			prefix,
			mac: value.try_into()?,
		})
	}
}
impl<'i> Attr<'i, MESSAGE_INTEGRITY_SHA256> for Integrity<'i, 32> {
	type Error = core::array::TryFromSliceError;
	fn must_precede(typ: u16) -> bool {
		typ == FINGERPRINT
	}
	fn decode(prefix: Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error> {
		Ok(Self {
			prefix,
			mac: value.try_into()?,
		})
	}
}

mod mbedtls_integrity {
	use hmac::{Hmac, Mac, digest::FixedOutput as _};
	use sha1::Sha1;

	use super::*;
	impl Integrity<'_, 20> {
		pub fn verify(&self, key: &[u8]) -> bool {
			let mut hasher: Hmac<Sha1> = Hmac::new_from_slice(key).unwrap();
			self.prefix.reduce_over_prefix(|s| hasher.update(s));
			hasher.verify_slice(self.mac).is_ok()
		}
	}
	impl AttrEnc<MESSAGE_INTEGRITY> for &[u8] {
		fn length(&self) -> u16 {
			20
		}
		fn encode(&self, prefix: Prefix, value: &mut [u8]) {
			let mut hasher: Hmac<Sha1> = Hmac::new_from_slice(self).unwrap();
			prefix.reduce_over_prefix(|s| hasher.update(s));
			hasher.finalize_into(value.into());
		}
	}
}
