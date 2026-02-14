// SocketAddr attributes
pub enum SocketAddrError {
	UnknownFamily(u8),
	UnexpectedLength,
}
macro_rules! sockaddr_attr {
	($typ:ident, $xor:literal) => {
		impl crate::stun::attr::Attr<'_, { crate::stun::attr::$typ }> for core::net::SocketAddr {
			type Error = crate::stun::attr::values::SocketAddrError;
			fn decode(
				prefix: crate::stun::attr::Prefix,
				value: &[u8],
			) -> Result<Self, Self::Error> {
				if value.len() < 4 {
					return Err(Self::Error::UnexpectedLength);
				}
				let family = value[1];
				let mut port: [u8; 2] = value[2..4].try_into().unwrap();
				if $xor {
					prefix.xor_bytes(&mut port);
				}
				let port = u16::from_be_bytes(port);

				let ip = match (family, value.len()) {
					(0x01, 8..) => {
						let mut octets: [u8; 4] = value[4..][..4].try_into().unwrap();
						if $xor {
							prefix.xor_bytes(&mut octets);
						}
						core::net::IpAddr::from(octets)
					}
					(0x02, 20..) => {
						let mut octets: [u8; 16] = value[4..][..16].try_into().unwrap();
						if $xor {
							prefix.xor_bytes(&mut octets);
						}
						core::net::IpAddr::from(octets)
					}
					(0x02 | 0x01, _) => return Err(Self::Error::UnexpectedLength),
					_ => return Err(Self::Error::UnknownFamily(family)),
				};

				Ok(Self::new(ip, port))
			}
		}
		impl crate::stun::attr::AttrEnc<{ crate::stun::attr::$typ }> for core::net::SocketAddr {
			fn length(&self) -> u16 {
				match self {
					Self::V4(_) => 8,
					Self::V6(_) => 20,
				}
			}
			fn encode(&self, prefix: crate::stun::attr::Prefix, value: &mut [u8]) {
				value[0] = 0;
				value[1] = if self.is_ipv4() { 0x01 } else { 0x02 };
				let mut port = self.port().to_be_bytes();
				if $xor {
					prefix.xor_bytes(&mut port);
				}
				value[2..4].copy_from_slice(&port);
				match self.ip() {
					core::net::IpAddr::V4(v4) => {
						let mut octets = v4.octets();
						if $xor {
							prefix.xor_bytes(&mut octets);
						}
						value[4..].copy_from_slice(&octets);
					}
					core::net::IpAddr::V6(v6) => {
						let mut octets = v6.octets();
						if $xor {
							prefix.xor_bytes(&mut octets);
						}
						value[4..].copy_from_slice(&octets);
					}
				}
			}
		}
	};
}
pub(crate) use sockaddr_attr;

// Numeric attributes
macro_rules! numeric_attr {
	($typ:ident, $num_typ:ident) => {
		impl crate::stun::attr::Attr<'_, { crate::stun::attr::$typ }> for $num_typ {
			type Error = core::array::TryFromSliceError;
			fn decode(_: crate::stun::attr::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
				value.try_into().map(Self::from_be_bytes)
			}
		}
		impl crate::stun::attr::AttrEnc<{ crate::stun::attr::$typ }> for $num_typ {
			fn length(&self) -> u16 {
				self.to_be_bytes().len() as u16
			}
			fn encode(&self, _: crate::stun::attr::Prefix, value: &mut [u8]) {
				value.copy_from_slice(&self.to_be_bytes())
			}
		}
	};
}
pub(crate) use numeric_attr;

// String attributes
macro_rules! str_attr {
	($typ:ident) => {
		impl<'i> crate::stun::attr::Attr<'i, { crate::stun::attr::$typ }> for &'i str {
			type Error = core::str::Utf8Error;
			fn decode(_: crate::stun::attr::Prefix, value: &'i [u8]) -> Result<Self, Self::Error> {
				core::str::from_utf8(value)
			}
		}
		impl crate::stun::attr::AttrEnc<{ crate::stun::attr::$typ }> for &str {
			fn length(&self) -> u16 {
				self.len() as u16
			}
			fn encode(&self, _: crate::stun::attr::Prefix, value: &mut [u8]) {
				value.copy_from_slice(self.as_bytes());
			}
		}
	};
}
pub(crate) use str_attr;

// Slice attributes
macro_rules! slice_attr {
	($typ:ident) => {
		impl<'i> crate::stun::attr::Attr<'i, { crate::stun::attr::$typ }> for &'i [u8] {
			type Error = core::convert::Infallible;
			fn decode(_: crate::stun::attr::Prefix, value: &'i [u8]) -> Result<Self, Self::Error> {
				Ok(value)
			}
		}
		impl crate::stun::attr::AttrEnc<{ crate::stun::attr::$typ }> for &[u8] {
			fn length(&self) -> u16 {
				self.len() as u16
			}
			fn encode(&self, _: crate::stun::attr::Prefix, value: &mut [u8]) {
				value.copy_from_slice(self)
			}
		}
	};
}
pub(crate) use slice_attr;

// Empty attributes
macro_rules! empty_attr {
	($typ:ident) => {
		impl crate::stun::attr::Attr<'_, { crate::stun::attr::$typ }> for () {
			type Error = core::convert::Infallible;
			fn decode(_: crate::stun::attr::Prefix, _: &[u8]) -> Result<Self, Self::Error> {
				Ok(())
			}
		}
		impl crate::stun::attr::AttrEnc<{ crate::stun::attr::$typ }> for () {
			fn length(&self) -> u16 {
				0
			}
			fn encode(&self, _: crate::stun::attr::Prefix, _: &mut [u8]) {}
		}
	};
}
pub(crate) use empty_attr;
