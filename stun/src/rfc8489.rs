//! The STUN protocol
//! We only implement part of it

use crate::attr::values::{sockaddr_attr, str_attr};
use crate::attr::{Attr, AttrEnc, Prefix, ERROR_CODE, UNKNOWN_ATTRIBUTES};

sockaddr_attr!(MAPPED_ADDRESS, false);
str_attr!(USERNAME);
sockaddr_attr!(ALTERNATE_SERVER, false);
sockaddr_attr!(XOR_MAPPED_ADDRESS, true);
str_attr!(REALM);
str_attr!(NONCE);
str_attr!(ALTERNATE_DOMAIN);
str_attr!(SOFTWARE);

impl<const N: usize> Attr<'_, UNKNOWN_ATTRIBUTES> for [u16; N] {
	type Error = core::convert::Infallible;
	fn decode(_: Prefix, value: &[u8]) -> Result<Self, Self::Error> {
		let mut ret = [0; N];
		for (i, c) in value.chunks_exact(2).enumerate().take(N) {
			ret[i] = u16::from_be_bytes(c.try_into().unwrap());
		}
		Ok(ret)
	}
}
impl<const N: usize> AttrEnc<UNKNOWN_ATTRIBUTES> for [u16; N] {
	fn length(&self) -> u16 {
		(self.iter().filter(|a| **a != 0).count() * 2) as u16
	}
	fn encode(&self, _: Prefix, value: &mut [u8]) {
		for (i, a) in self.iter().enumerate() {
			if *a == 0 {
				break;
			}
			value[i * 2..][..2].copy_from_slice(&a.to_be_bytes());
		}
	}
}

#[cfg(feature = "fingerprint")]
mod fingerprint {
	use crate::attr::{Attr, AttrEnc, FINGERPRINT};
	use crc::Crc;

	pub struct BadFingerprint;

	const FINGERPRINT_MAGIC: u32 = 0x5354554e;
	const CRC: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);

	impl Attr<'_, FINGERPRINT> for () {
		type Error = BadFingerprint;
		fn decode(prefix: crate::attr::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
			let actual = u32::from_be_bytes(value.try_into().map_err(|_| BadFingerprint)?);

			let mut hasher = CRC.digest();
			prefix.reduce_over_prefix(|s| hasher.update(s));
			let expected = hasher.finalize() ^ FINGERPRINT_MAGIC;

			(expected == actual).then_some(()).ok_or(BadFingerprint)
		}

		fn must_precede(_: u16) -> bool {
			false
		}
	}
	impl AttrEnc<FINGERPRINT> for () {
		fn length(&self) -> u16 {
			4
		}
		fn encode(&self, prefix: crate::attr::Prefix, value: &mut [u8]) {
			let mut hasher = CRC.digest();
			prefix.reduce_over_prefix(|s| hasher.update(s));
			let expected = hasher.finalize() ^ FINGERPRINT_MAGIC;
			value.copy_from_slice(&expected.to_be_bytes());
		}
	}
}

pub struct UnexpectedLength;

// I dislike how STUN chose to represent error codes... and methods... and message integrity... and socket addresses... and ICE tiebreaker values... and most TURN attributes.
// More succinctly, I dislike everything about STUN.
impl<'i> Attr<'i, ERROR_CODE> for (u16, &'i str) {
	type Error = UnexpectedLength;
	fn decode(_: crate::attr::Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error> {
		if value.len() < 4 {
			return Err(UnexpectedLength);
		}
		let class = value[2] & 0b111;
		let number = value[3] % 100;
		let err_code = class as u16 * 100 + number as u16;
		let reason =
			core::str::from_utf8(&value[4..]).unwrap_or("<Reason contained invalid UTF-8>");

		Ok((err_code, reason))
	}
}
impl AttrEnc<ERROR_CODE> for (u16, &str) {
	fn length(&self) -> u16 {
		4 + self.1.len() as u16
	}
	fn encode(&self, _: crate::attr::Prefix, value: &mut [u8]) {
		assert!(self.0 <= 799); // 3-bits for the error class means 0-7
		let class = (self.0 / 100) as u8;
		let number = (self.0 % 100) as u8;
		value[0] = 0;
		value[1] = 0;
		value[2] = class;
		value[3] = number;
		value[4..].copy_from_slice(self.1.as_bytes());
	}
}
