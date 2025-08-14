use core::net::Ipv6Addr;

pub struct IndexIp {
	pub proto: u8,
	pub site: u16,
	pub index: u64,
}
impl From<&IndexIp> for Ipv6Addr {
	fn from(IndexIp { proto, site, index }: &IndexIp) -> Self {
		let mut octets = [0xfd, *proto, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
		octets[2..4].copy_from_slice(&site.to_be_bytes());
		octets[8..].copy_from_slice(&index.to_be_bytes());
		octets.into()
	}
}
impl TryFrom<&Ipv6Addr> for IndexIp {
	type Error = Ipv6Addr;
	fn try_from(value: &Ipv6Addr) -> Result<Self, Self::Error> {
		let octets = value.octets();
		// The value must be within the private ip6 range of fd00::/8
		if octets[0] != 0xfd {
			return Err(*value)
		}
		// The value must be within the index range of fd{proto}:{site}::/64
		if octets[4..8] != [0, 0, 0, 0] {
			return Err(*value);
		}
		let proto = octets[1];
		let site = u16::from_be_bytes(octets[2..4].try_into().unwrap());
		let index = u64::from_be_bytes(octets[8..].try_into().unwrap());
		Ok(Self { proto, site, index })
	}
}
