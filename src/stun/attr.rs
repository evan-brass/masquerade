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
	($rfc:literal, $value:literal, $name:ident) => {
		#[doc = "Defined in "]
		#[doc = $rfc]
		pub const $name: u16 = $value;
	};
}

attr_typ!("RFC8489", 0x0001, MAPPED_ADDRESS);
attr_typ!("RFC8489", 0x0006, USERNAME);
attr_typ!("RFC8489", 0x0008, MESSAGE_INTEGRITY);
attr_typ!("RFC8489", 0x0009, ERROR_CODE);
attr_typ!("RFC8489", 0x000A, UNKNOWN_ATTRIBUTES);
attr_typ!("RFC8656", 0x000C, CHANNEL_NUMBER);
attr_typ!("RFC8656", 0x000D, LIFETIME);
attr_typ!("RFC8656", 0x0012, XOR_PEER_ADDRESS);
attr_typ!("RFC8656", 0x0013, DATA);
attr_typ!("RFC8489", 0x0014, REALM);
attr_typ!("RFC8489", 0x0015, NONCE);
attr_typ!("RFC8656", 0x0016, XOR_RELAYED_ADDRESS);
attr_typ!("RFC8656", 0x0017, REQUESTED_ADDRESS_FAMILY);
attr_typ!("RFC8656", 0x0018, EVEN_PORT);
attr_typ!("RFC8656", 0x0019, REQUESTED_TRANSPORT);
attr_typ!("RFC8656", 0x001A, DONT_FRAGMENT);
attr_typ!("RFC7635", 0x001B, ACCESS_TOKEN);
attr_typ!("RFC8489", 0x001C, MESSAGE_INTEGRITY_SHA256);
attr_typ!("RFC8489", 0x001D, PASSWORD_ALGORITHM);
attr_typ!("RFC8489", 0x001E, USERHASH);
attr_typ!("RFC8489", 0x0020, XOR_MAPPED_ADDRESS);
attr_typ!("RFC8656", 0x0022, RESERVATION_TOKEN);
attr_typ!("RFC8445", 0x0024, PRIORITY);
attr_typ!("RFC8445", 0x0025, USE_CANDIDATE);
attr_typ!("RFC5780", 0x0026, PADDING);
attr_typ!("RFC5780", 0x0027, RESPONSE_PORT);
attr_typ!("RFC6062", 0x002A, CONNECTION_ID);
attr_typ!("RFC8656", 0x8000, ADDITIONAL_ADDRESS_FAMILY);
attr_typ!("RFC8656", 0x8001, ADDRESS_ERROR_CODE);
attr_typ!("RFC8489", 0x8002, PASSWORD_ALGORITHMS);
attr_typ!("RFC8489", 0x8003, ALTERNATE_DOMAIN);
attr_typ!("RFC8656", 0x8004, ICMP);
attr_typ!("RFC8489", 0x8022, SOFTWARE);
attr_typ!("RFC8489", 0x8023, ALTERNATE_SERVER);
attr_typ!("RFC7982", 0x8025, TRANSACTION_TRANSMIT_COUNTER);
attr_typ!("RFC5780", 0x8027, CACHE_TIMEOUT);
attr_typ!("RFC8489", 0x8028, FINGERPRINT);
attr_typ!("RFC8445", 0x8029, ICE_CONTROLLED);
attr_typ!("RFC8445", 0x802A, ICE_CONTROLLING);
attr_typ!("RFC5780", 0x802B, RESPONSE_ORIGIN);
attr_typ!("RFC5780", 0x802C, OTHER_ADDRESS);
attr_typ!("RFC6679", 0x802D, ECN_CHECK_STUN);
attr_typ!("RFC7635", 0x802E, THIRD_PARTY_AUTHORIZATION);
attr_typ!("RFC8016", 0x8030, MOBILITY_TICKET);
