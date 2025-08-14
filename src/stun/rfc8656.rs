//! The TURN protocol
//! We only implement part of it

use super::attr::{
	values::{empty_attr, numeric_attr, slice_attr, sockaddr_attr},
	Attr, AttrEnc, ADDRESS_ERROR_CODE, CHANNEL_NUMBER, EVEN_PORT, ICMP, RESERVATION_TOKEN,
};

sockaddr_attr!(XOR_PEER_ADDRESS, true);
sockaddr_attr!(XOR_RELAYED_ADDRESS, true);
numeric_attr!(LIFETIME, u32);
slice_attr!(DATA);
empty_attr!(DONT_FRAGMENT);

impl<'i> Attr<'i, ADDRESS_ERROR_CODE> for (u8, u16, &'i str) {
	type Error = super::rfc8489::UnexpectedLength;
	fn decode(prefix: super::attr::Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error> {
		let (code, reason) = Attr::decode(prefix, value)?;
		Ok((value[0], code, reason))
	}
}
impl AttrEnc<ADDRESS_ERROR_CODE> for (u8, u16, &str) {
	fn length(&self) -> u16 {
		AttrEnc::length(&(self.1, self.2))
	}
	fn encode(&self, prefix: super::attr::Prefix, value: &mut [u8]) {
		AttrEnc::encode(&(self.1, self.2), prefix, value);
		value[0] = self.0;
	}
}

impl Attr<'_, CHANNEL_NUMBER> for u16 {
	type Error = super::rfc8489::UnexpectedLength;
	fn decode(_: super::attr::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
		let Some(arr) = value.first_chunk() else {
			return Err(super::rfc8489::UnexpectedLength);
		};
		Ok(u16::from_be_bytes(*arr))
	}
}
impl AttrEnc<CHANNEL_NUMBER> for u16 {
	fn length(&self) -> u16 {
		4
	}
	fn encode(&self, _: super::attr::Prefix, value: &mut [u8]) {
		value[0..2].copy_from_slice(&self.to_be_bytes());
		value[2..4].fill(0);
	}
}

impl Attr<'_, EVEN_PORT> for bool {
	type Error = super::rfc8489::UnexpectedLength;
	fn decode(_: super::attr::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
		if value.is_empty() {
			return Err(super::rfc8489::UnexpectedLength);
		}
		Ok(value[0] & 0b10000000 != 0)
	}
}
impl AttrEnc<EVEN_PORT> for bool {
	fn length(&self) -> u16 {
		1
	}
	fn encode(&self, _: super::attr::Prefix, value: &mut [u8]) {
		value[0] = (*self as u8) << 7;
	}
}

macro_rules! weird_byte_attr {
	($typ:ident) => {
		impl super::attr::Attr<'_, { super::attr::$typ }> for u8 {
			type Error = super::rfc8489::UnexpectedLength;
			fn decode(_: super::attr::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
				if value.len() < 1 {
					return Err(super::rfc8489::UnexpectedLength);
				}
				Ok(value[0])
			}
		}
		impl super::attr::AttrEnc<{ super::attr::$typ }> for u8 {
			fn length(&self) -> u16 {
				4
			}
			fn encode(&self, _: super::attr::Prefix, value: &mut [u8]) {
				value[0] = *self;
				value[1..4].fill(0);
			}
		}
	};
}
weird_byte_attr!(REQUESTED_ADDRESS_FAMILY);
weird_byte_attr!(REQUESTED_TRANSPORT);
weird_byte_attr!(ADDITIONAL_ADDRESS_FAMILY);

impl Attr<'_, RESERVATION_TOKEN> for [u8; 8] {
	type Error = core::array::TryFromSliceError;
	fn decode(_: super::attr::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
		value.try_into()
	}
}
impl AttrEnc<RESERVATION_TOKEN> for [u8; 8] {
	fn length(&self) -> u16 {
		8
	}
	fn encode(&self, _: super::attr::Prefix, value: &mut [u8]) {
		value.copy_from_slice(self)
	}
}

// TODO: https://www.rfc-editor.org/rfc/rfc8656.html#section-18.13 shows the ICMP Type as being 7 bits and the ICMP Code as being 9 bits.  I'm assuming this was a mistake since wikipedia show icmp4 and icmp6 as both having 8 bit types and codes.  I briefly checked coturn, and Chrome's WebRTC code, if they even parse ICMP attributes I didn't see it.  TURN, STUN, and WebRTC are all ass.
impl Attr<'_, ICMP> for (u8, u8, [u8; 4]) {
	type Error = core::array::TryFromSliceError;
	fn decode(_: super::attr::Prefix<'_>, value: &'_ [u8]) -> Result<Self, Self::Error> {
		let [_, _, typ, cod, a, b, c, d] = value.try_into()?;
		Ok((typ, cod, [a, b, c, d]))
	}
}
impl AttrEnc<ICMP> for (u8, u8, [u8; 4]) {
	fn length(&self) -> u16 {
		8
	}
	fn encode(&self, _: super::attr::Prefix, value: &mut [u8]) {
		value[0] = 0;
		value[1] = 0;
		value[2] = self.0;
		value[3] = self.1;
		value[4..8].copy_from_slice(&self.2);
	}
}
