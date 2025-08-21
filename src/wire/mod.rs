use bitfield::{bitfield, BitRange, BitRangeMut};
pub use zerocopy::{big_endian::{U16, U32}, little_endian::{U32 as U32_LE}, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub mod ip_proto {
	pub const UDP: u8 = 17;
	pub const SCTP: u8 = 132;
}

bitfield! {
	#[repr(transparent)]
	#[derive(Clone, Copy, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
	pub struct Ip6Flags([u8; 4]);
	no default BitRange;
	impl Debug;
	pub u8, version, set_version: 31, 28;
	pub u8, traffic_class, set_traffic_class: 27, 20;
	pub u32, flow_label, set_flow_label: 19, 0;
}
impl<T> BitRange<T> for Ip6Flags where u32: BitRange<T> {
	fn bit_range(&self, msb: usize, lsb: usize) -> T {
		u32::from_be_bytes(self.0).bit_range(msb, lsb)
	}
}
impl<T> BitRangeMut<T> for Ip6Flags where u32: BitRangeMut<T> {
	fn set_bit_range(&mut self, msb: usize, lsb: usize, value: T) {
		let mut t = u32::from_be_bytes(self.0);
		t.set_bit_range(msb, lsb, value);
		self.0 = t.to_be_bytes();
	}
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct Ip6Header {
	pub flags: Ip6Flags,
	pub payload_length: U16,
	pub next_header: u8,
	pub hop_limit: u8,
	pub src: [u8; 16],
	pub dst: [u8; 16],
}
impl Ip6Header {
	pub fn len(&self) -> usize {
		size_of::<Self>() + self.payload_length.get() as usize
	}
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct UdpHeader {
	pub src_port: U16,
	pub dst_port: U16,
	pub length: U16,
	pub checksum: U16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct StunHeader {
	pub typ: U16,
	pub length: U16,
	pub cookie: U32,
	pub txid: [u8; 12]
}
#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct StunAttrHeader {
	pub typ: U16,
	pub length: U16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct SctpHeader {
	pub src_port: U16,
	pub dst_port: U16,
	pub vtag: U32,
	pub checksum: U32_LE,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct DcepOpenHeader {
	pub msg_typ: u8,
	pub channel_typ: u8,
	pub priority: U16,
	pub reliability_parameter: U32,
	pub label_len: U16,
	pub protocol_len: U16,
}

bitfield! {
	#[repr(transparent)]
	#[derive(KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
	pub struct DnsFlags([u8; 2]);
	no default BitRange;
	impl Debug;
	pub is_answer, set_answer: 15;
	pub u8, opcode, set_opcode: 14, 11;
	pub is_authoritative, set_authoritative: 10;
	pub is_truncated, set_truncated: 9;
	pub is_recursion_desired, set_recursion_desired: 8;
	pub is_recursion_available, set_recursion_available: 7;
	pub _, reserved1: 6;
	pub is_authentic_data, set_authentic_data: 5;
	pub is_checking_disabled, set_checking_disabled: 4;
	pub u8, rcode, set_rcode: 3, 0;
}
impl<T> BitRange<T> for DnsFlags where u16: BitRange<T> {
	fn bit_range(&self, msb: usize, lsb: usize) -> T {
		u16::from_be_bytes(self.0).bit_range(msb, lsb)
	}
}
impl<T> BitRangeMut<T> for DnsFlags where u16: BitRangeMut<T> {
	fn set_bit_range(&mut self, msb: usize, lsb: usize, value: T) {
		let mut t = u16::from_be_bytes(self.0);
		t.set_bit_range(msb, lsb, value);
		self.0 = t.to_be_bytes();
	}
}

#[repr(C)]
#[derive(Debug, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct DnsHeader {
	pub txid: [u8; 2],
	pub flags: DnsFlags,
	pub num_query: U16,
	pub num_answer: U16,
	pub num_authority: U16,
	pub num_additional: U16,
}

#[repr(C)]
#[derive(Debug, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct Record {
	pub typ: U16,
	pub class: U16,
	pub ttl: U32,
	pub length: U16,
}

pub mod dns_type {
	use super::*;

	pub const A: U16 = U16::new(1);
	pub const AAAA: U16 = U16::new(28);
}
pub mod dns_class {
	use super::*;

	pub const IN: U16 = U16::new(0x0001);
}
