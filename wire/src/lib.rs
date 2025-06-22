pub use zerocopy::{big_endian::{U16, U32}, little_endian::{U32 as U32_LE}, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub mod ip_proto {
	pub const UDP: u8 = 17;
	pub const SCTP: u8 = 132;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct Ip6Header {
	pub flags: U32,
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
