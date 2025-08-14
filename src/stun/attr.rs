//! STUN is a format with a 20 byte header and a list of type-length-value attributes.
//!

mod attrs;
pub mod integrity;
pub mod parse;
pub mod values;

pub trait Attr<'i, const T: u16>: Sized {
	type Error;

	fn decode(prefix: Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error>;

	/// Some attributes must preced other attributes
	fn must_precede(typ: u16) -> bool {
		matches!(
			typ,
			MESSAGE_INTEGRITY | MESSAGE_INTEGRITY_SHA256 | FINGERPRINT
		)
	}
}
pub trait AttrEnc<const T: u16> {
	fn length(&self) -> u16;
	fn encode(&self, prefix: Prefix, value: &mut [u8]);
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Prefix<'i> {
	pub(crate) first_four: [u8; 4],
	pub(crate) prefix: &'i [u8],
}
impl Prefix<'_> {
	pub fn xor_bytes(&self, dest: &mut [u8]) {
		assert!(dest.len() <= 16);
		for (i, b) in dest.iter_mut().enumerate() {
			*b ^= self.prefix[i];
		}
	}
	pub fn reduce_over_prefix<F: FnMut(&[u8])>(&self, mut func: F) {
		func(&self.first_four);
		func(self.prefix);
	}
}

macro_rules! attr_typ {
	($value:literal, $name:ident, $rfc:literal) => {
		#[doc = "Defined in "]
		#[doc = $rfc]
		pub const $name: u16 = $value;
	};
}

attr_typ!(0x0001, MAPPED_ADDRESS, "RFC8489");
attr_typ!(0x0006, USERNAME, "RFC8489");
attr_typ!(0x0008, MESSAGE_INTEGRITY, "RFC8489");
attr_typ!(0x0009, ERROR_CODE, "RFC8489");
attr_typ!(0x000A, UNKNOWN_ATTRIBUTES, "RFC8489");
attr_typ!(0x000C, CHANNEL_NUMBER, "RFC8656");
attr_typ!(0x000D, LIFETIME, "RFC8656");
attr_typ!(0x0012, XOR_PEER_ADDRESS, "RFC8656");
attr_typ!(0x0013, DATA, "RFC8656");
attr_typ!(0x0014, REALM, "RFC8489");
attr_typ!(0x0015, NONCE, "RFC8489");
attr_typ!(0x0016, XOR_RELAYED_ADDRESS, "RFC8656");
attr_typ!(0x0017, REQUESTED_ADDRESS_FAMILY, "RFC8656");
attr_typ!(0x0018, EVEN_PORT, "RFC8656");
attr_typ!(0x0019, REQUESTED_TRANSPORT, "RFC8656");
attr_typ!(0x001A, DONT_FRAGMENT, "RFC8656");
attr_typ!(0x001B, ACCESS_TOKEN, "RFC7635");
attr_typ!(0x001C, MESSAGE_INTEGRITY_SHA256, "RFC8489");
attr_typ!(0x001D, PASSWORD_ALGORITHM, "RFC8489");
attr_typ!(0x001E, USERHASH, "RFC8489");
attr_typ!(0x0020, XOR_MAPPED_ADDRESS, "RFC8489");
attr_typ!(0x0022, RESERVATION_TOKEN, "RFC8656");
attr_typ!(0x0024, PRIORITY, "RFC8445");
attr_typ!(0x0025, USE_CANDIDATE, "RFC8445");
attr_typ!(0x0026, PADDING, "RFC5780");
attr_typ!(0x0027, RESPONSE_PORT, "RFC5780");
attr_typ!(0x002A, CONNECTION_ID, "RFC6062");
attr_typ!(0x8000, ADDITIONAL_ADDRESS_FAMILY, "RFC8656");
attr_typ!(0x8001, ADDRESS_ERROR_CODE, "RFC8656");
attr_typ!(0x8002, PASSWORD_ALGORITHMS, "RFC8489");
attr_typ!(0x8003, ALTERNATE_DOMAIN, "RFC8489");
attr_typ!(0x8004, ICMP, "RFC8656");
attr_typ!(0x8022, SOFTWARE, "RFC8489");
attr_typ!(0x8023, ALTERNATE_SERVER, "RFC8489");
attr_typ!(0x8025, TRANSACTION_TRANSMIT_COUNTER, "RFC7982");
attr_typ!(0x8027, CACHE_TIMEOUT, "RFC5780");
attr_typ!(0x8028, FINGERPRINT, "RFC8489");
attr_typ!(0x8029, ICE_CONTROLLED, "RFC8445");
attr_typ!(0x802A, ICE_CONTROLLING, "RFC8445");
attr_typ!(0x802B, RESPONSE_ORIGIN, "RFC5780");
attr_typ!(0x802C, OTHER_ADDRESS, "RFC5780");
attr_typ!(0x802D, ECN_CHECK_STUN, "RFC6679");
attr_typ!(0x802E, THIRD_PARTY_AUTHORIZATION, "RFC7635");
attr_typ!(0x8030, MOBILITY_TICKET, "RFC8016");
