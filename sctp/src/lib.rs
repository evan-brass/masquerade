use nix::{cmsg_space, libc::{self, IPPROTO_SCTP}, sys::socket::*};
use zerocopy::FromBytes;
use std::{
	io::{IoSliceMut, Result},
	net::{SocketAddr, SocketAddrV6, ToSocketAddrs},
	os::fd::{AsRawFd, OwnedFd},
};

pub mod opts;
pub mod types;

/// 1-to-n style SCTP socket
pub struct SctpSocket {
	inner: OwnedFd,
}
impl SctpSocket {
	pub fn add_addr(&self, addr: &SocketAddr) -> Result<()> {
		let val = SockaddrIn6::from(match addr {
			SocketAddr::V4(v4) => SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0),
			SocketAddr::V6(v) => *v,
		});
		opts::SctpAddrAdd.set(&self.inner, &val)?;
		Ok(())
	}
	pub fn bind<A: ToSocketAddrs, T: IntoIterator<Item = A>>(addrs: T) -> Result<Self> {
		let inner = socket(
			AddressFamily::Inet6,
			SockType::SeqPacket,
			SockFlag::empty(),
			Some(SockProtocol::Sctp),
		)?;

		// Bind Addresses
		let ret = Self { inner };
		for a in addrs.into_iter() {
			for a in a.to_socket_addrs()? {
				ret.add_addr(&a)?;
			}
		}

		// Enable RecvInfo
		opts::SctpRecvRcvInfo.set(&ret.inner, &true)?;

		Ok(ret)
	}
	pub fn listen(&self, backlog: i32) -> Result<()> {
		let backlog = Backlog::new(backlog)?;
		listen(&self.inner, backlog)?;
		Ok(())
	}
	pub fn recvmsg(&self, buffer: &mut [u8]) -> Result<(usize, Option<SockaddrIn6>, Option<types::RcvInfo>)> {
		let mut iov = [IoSliceMut::new(buffer)];
		let mut cmsg_buffer = cmsg_space!(types::RcvInfo);
		let received = recvmsg::<SockaddrIn6>(
			self.inner.as_raw_fd(),
			&mut iov,
			Some(&mut cmsg_buffer),
			MsgFlags::empty(),
		)?;
		if received.flags.contains(MsgFlags::MSG_NOTIFICATION) {
			todo!();
		} else {
			let mut rcv_info = None;
			// BUG: ControlMessageOwned is a non-exhaustive enum.  At the moment, it doesn't contain the SCTP cmsgs we need, so they'll fall through to ControlMessageOwned::Unknown.  But if nix adds support for SCTP messages down the line, this code will break.  So don't upgrade.  They should really modify their cmsg api to have a borrowed raw control message and then an owned version that way code like this can operate beneath the non-exhaustive enum.
			// Second issue is the Clone from slice -> Vec<u8>, because this potentially narrows the alignment meaning we must copy again into our c struct.
			let mut cmsgs = received.cmsgs()?;
			while let Some((header, value)) = cmsgs.next_raw() {
				match (header.cmsg_level, header.cmsg_type) {
					(IPPROTO_SCTP, libc::SCTP_RCVINFO) => {
						rcv_info = Some(types::RcvInfo::read_from_bytes(&value).unwrap());
					}
					_ => {}
				}
			}
			Ok((received.bytes, received.address, rcv_info))
		}
	}
}
