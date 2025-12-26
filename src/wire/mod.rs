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

pub fn ip_checksum(slices: &[&[u8]]) -> u16 {
	let mut accum = 0u32;
	for (offset, b) in slices.into_iter().cloned().flatten().enumerate() {
		if (offset % 2) == 0 {
			accum += (*b as u32) << 8;
		} else {
			accum += *b as u32;
		}
	}
	while accum > 0xffff {
		accum = (accum >> 16) + (accum & 0xffff);
	}
	!(accum as u16)
}

#[test]
fn udp_checksum() {
	assert_eq!(0xaff5, ip_checksum(&[
		/* IPv4 src */ &[127, 0, 0, 1],
		/* IPv4 dst */ &[127, 0, 0, 1],

		/* UDP Pseudo */ &[0, 17, 0x00, 0x13],

		/* UDP ports */ &[0, 1, 0, 1],
		/* UDP Length */ &[0x00, 0x13],
		/* UDP Payload */ b"Hello World"
	]));
}