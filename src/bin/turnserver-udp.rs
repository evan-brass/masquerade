use std::str::FromStr;
use std::{
	net::SocketAddr,
	net::SocketAddrV6,
	net::IpAddr,
	net::Ipv6Addr,
	os::fd::AsRawFd,
};

use clap::Parser;
use eyre::{Result, eyre};
use ipnet::{IpBitAnd, IpBitOr, Ipv6Net};
use mio::{
	Events, Interest, Poll, Token,
	net::UdpSocket,
	unix::SourceFd,
};
use masquerade::stun::{
	Class, Method, Stun, MAGIC_COOKIE,
	attr::{integrity::Integrity, parse::AttrIter as _, *},
};
use masquerade::wire::{ip_proto, FromBytes, Ip6Header, StunAttrHeader, UdpHeader};
use tappers::{Interface, Tun};
use tracing_subscriber::EnvFilter;
use rand::{RngCore, rng};

type Never = core::convert::Infallible;

const UDP: Token = Token(usize::MAX);
const TUN: Token = Token(usize::MAX - 1);

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "[::]:3478")]
	address: String,

	#[arg(long, short, default_value = "")]
	mappings: String,

	#[arg(long, short)]
	if_name: Option<String>,
}

// 1-to-1 IPv6 subnet mappings.  Primarily intended for mapping ::ffff:0.0.0.0/96<->[a network that you control], and potentially for mapping 2000::/3<->A000::/3 to statelessly differentiate between TURN/UDP packets from normal UDP packets received from IPv6 peers.
struct Mapping {
	udp: Ipv6Net,
	tun: Ipv6Net,
}
impl FromStr for Mapping {
	type Err = eyre::Report;
	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		let (udp, tun) = s.split_once("<->").ok_or(eyre!("stuff"))?;
		let udp = Ipv6Net::from_str(udp)?;
		let tun = Ipv6Net::from_str(tun)?;
		if udp.prefix_len() != tun.prefix_len() {
			return Err(eyre!("subnets need to have the same size"))
		}
		Ok(Self { udp, tun })
	}
}
impl Mapping {
	fn to_net(&self, addr: &mut Ipv6Addr) {
		if self.udp.contains(&*addr) {
			*addr = self.tun.network().bitor(self.udp.hostmask().bitand(*addr));
		}
	}
	fn to_udp(&self, addr: &mut Ipv6Addr) {
		if self.tun.contains(&*addr) {
			*addr = self.udp.network().bitor(self.tun.hostmask().bitand(*addr));
		}
	}
}

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;

	// Listen for TURN traffic
	let mut socket = UdpSocket::bind(args.address.parse()?)?;

	// Setup the TUN interface
	let mut network = if let Some(if_name) = args.if_name {
		Tun::new_named(Interface::new(if_name)?)?
	} else {
		Tun::new()?
	};
	network.set_nonblocking(true)?;

	// Parse subnet mappings
	let mut mappings = Vec::new();
	for s in args.mappings.split(',') {
		mappings.push(Mapping::from_str(s)?);
	}

	let mut poll = Poll::new()?;
	poll.registry()
		.register(&mut socket, UDP, Interest::READABLE)?;
	poll.registry()
		.register(&mut SourceFd(&network.as_raw_fd()), TUN, Interest::READABLE)?;

	let mut buffer = [0; 65536];
	let mut events = Events::with_capacity(128);

	// Ready to receive
	network.set_up()?;

	loop {
		// UDP recv
		loop {
			let Ok((len, sender)) = socket.recv_from(&mut buffer) else { break };
			let mut msg = Stun {
				buffer: buffer.as_mut_slice()
			};
			if msg.decode(len).is_err() { continue }

			// Cleared txid seems to be an amplification technique (possibly spoofed packets?)
			if msg.txid() == &[0; 12] { continue }

			let canonical = SocketAddr::new(sender.ip().to_canonical(), sender.port());
			let mut mapped = match sender.ip() {
				// TODO: If we encounter a v4 then we should emit v4 / canonical ip addresses to the UDP socket.
				IpAddr::V4(v4) => v4.to_ipv6_mapped(),
				IpAddr::V6(v6) => v6,
			};
			// Apply our subnet mappings to mapped
			for m in &mappings {
				m.to_net(&mut mapped);
			}
			let relayed = SocketAddr::new(mapped.into(), sender.port());

			// Parse TURN attributes
			let mut username = None;
			let mut realm = None;
			let mut integrity = None;
			let mut nonce = None;
			let mut lifetime = None;
			let mut requested_transport = None;
			let mut channel = None;
			let mut xor_peer = None;
			let mut data = None;
			let mut turn_fingerprint = None;
			let unknown_attrs = msg
				.into_iter()
				.parse::<USERNAME, &str>(&mut username)
				.parse::<REALM, &str>(&mut realm)
				.parse::<MESSAGE_INTEGRITY, Integrity<20>>(&mut integrity)
				.parse::<NONCE, &str>(&mut nonce)
				.parse::<LIFETIME, u32>(&mut lifetime)
				.parse::<REQUESTED_TRANSPORT, u8>(&mut requested_transport)
				.parse::<CHANNEL_NUMBER, u16>(&mut channel)
				.parse::<XOR_PEER_ADDRESS, SocketAddr>(&mut xor_peer)
				.parse::<DATA, &[u8]>(&mut data)
				.parse::<FINGERPRINT, ()>(&mut turn_fingerprint)
				.collect_unknown::<8>();

			let method_unknown = !matches!(
				msg.method(),
				Method::Binding
					| Method::Allocate
					| Method::Refresh
					| Method::CreatePermission
					| Method::Send
					| Method::ChannelBind
			);

			// Compute a long-term key for authentication
			let turn_key = if let (Some(username), Some(realm), Some(_)) = (username, realm, &integrity)
			{
				let mut ctx = md5::Context::new();
				ctx.consume(username);
				ctx.consume(":");
				ctx.consume(realm);
				ctx.consume(":password");
				ctx.compute().0
			} else {
				[0; 16]
			};

			match (msg.class(), msg.method()) {
				// Ignore Responses (we are a server, we shouldn't be receiving them)
				(Class::Error | Class::Success, _) => continue,

				// Binding:
				(Class::Request, Method::Binding) => {
					msg.set_length(0);
					msg.set_class(Class::Success);
					msg.append::<XOR_MAPPED_ADDRESS, SocketAddr>(&canonical)
						.unwrap();
				}

				// Unknown Method
				(Class::Request, _) if method_unknown => {
					msg.set_length(0);
					msg.set_class(Class::Error);
					msg.append::<ERROR_CODE, _>(&(404, "")).unwrap();
				}

				// Unknown Attributes
				(Class::Request, _) if unknown_attrs.is_some() => {
					msg.set_length(0);
					msg.set_class(Class::Error);
					msg.append::<ERROR_CODE, _>(&(420, "")).unwrap();
					msg.append::<UNKNOWN_ATTRIBUTES, _>(&unknown_attrs.unwrap())
						.unwrap();
				}
				_ if unknown_attrs.is_some() => continue,

				// Unauthenticated Request
				(Class::Request, _) if username.is_none() || realm.is_none() => {
					msg.set_length(0);
					msg.set_class(Class::Error);
					msg.append::<ERROR_CODE, _>(&(401, "")).unwrap();
					msg.append::<REALM, &str>(&"none").unwrap();
					msg.append::<NONCE, &str>(&"none").unwrap();
				}

				// Forbidden
				(Class::Request, _) if integrity.is_none() => continue,
				(Class::Request, _) if !integrity.unwrap().verify(&turn_key) => {
					msg.set_length(0);
					msg.set_class(Class::Error);
					msg.append::<ERROR_CODE, _>(&(403, "")).unwrap();
				}

				// Non-UDP Allocate
				(Class::Request, Method::Allocate) if requested_transport != Some(17) => {
					msg.set_length(0);
					msg.set_class(Class::Error);
					msg.append::<ERROR_CODE, _>(&(442, "")).unwrap();
					msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice())
						.unwrap();
				}

				// Allocate
				(Class::Request, Method::Allocate) => {
					msg.set_length(0);
					msg.set_class(Class::Success);
					msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical).unwrap();
					msg.append::<XOR_RELAYED_ADDRESS, SocketAddr>(&relayed)
						.unwrap();
					msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000))
						.unwrap();
					msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice())
						.unwrap();
				}

				// Refresh
				(Class::Request, Method::Refresh) if lifetime == Some(0) => continue,
				(Class::Request, Method::Refresh) => {
					msg.set_length(0);
					msg.set_class(Class::Success);
					msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000))
						.unwrap();
					msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice())
						.unwrap();
				}

				// Create Permission
				(Class::Request, Method::CreatePermission) => {
					msg.set_length(0);
					msg.set_class(Class::Success);
					msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice())
						.unwrap();
				}

				// Channel Bind
				(Class::Request, Method::ChannelBind) => {
					msg.set_length(0);
					msg.set_class(Class::Error);
					msg.append::<ERROR_CODE, _>(&(438, "")).unwrap();
					msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice())
						.unwrap();
				}

				// Send
				(Class::Indication, Method::Send) => {
					let (Some(peer), Some(data)) = (xor_peer, data) else {
						continue;
					};

					// Shift the data attribute to where we want it
					// [ STUN Header | XOR Peer Attr | Data... ]
					let len = data.len();
					let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
					if 48 + data.len() > msg.buffer.len() {
						continue;
					}
					msg.buffer.copy_within(i..i + 4 + len, 44);

					let IpAddr::V6(dst_addr) = peer.ip() else {
						continue;
					};
					let src_addr = mapped;
					let length = len as u16 + 8;

					// IP6 + UDP = 40 + 8 = 48 = STUN Data Indication! Perfect.  No copy/shift needed.
					let (ip, rest) = Ip6Header::mut_from_prefix(&mut msg.buffer).unwrap();
					let (udp, _) = UdpHeader::mut_from_prefix(rest).unwrap();
					ip.flags.set_version(6);
					ip.flags.set_traffic_class(0);
					ip.flags.set_flow_label(0);
					ip.payload_length.set(length);
					ip.next_header = ip_proto::UDP;
					ip.hop_limit = 5;
					ip.src = src_addr.octets();
					ip.dst = dst_addr.octets();
					udp.src_port.set(relayed.port());
					udp.dst_port.set(peer.port());
					udp.length.set(length);
					udp.checksum.set(0);

					// Emit the UDP packet to the network:
					let length = ip.len();
					let _ = network.send(&buffer[..length]);
					continue;
				}
				_ => continue,
			}

			// Send the STUN response:
			let length = msg.len();
			let _ = socket.send_to(&buffer[..length], sender);
		}

		// TUN Recv
		loop {
			let Ok(len) = network.recv(&mut buffer) else { break };
			let (ip, rest) = Ip6Header::mut_from_prefix(buffer.as_mut_slice()).unwrap();

			if ip.flags.version() != 6 { continue }
			if ip.len() != len { continue }

			if ip.next_header != ip_proto::UDP { continue }
			if ip.payload_length.get() < 8 { continue }
			let (udp, _) = UdpHeader::mut_from_prefix(rest).unwrap();
			if udp.length != ip.payload_length { continue }
			let padding = (4 - udp.length.get() % 4) % 4;

			// STUN (xor_peer + data header - udp header length + padding + udp packet length)
			let Some(stun_length) = (24 + 4 - 8 + padding).checked_add(udp.length.get()) else {
				continue
			};
			let data_len = udp.length.get() - 8;
			let sender = SocketAddrV6::new(ip.src.into(), udp.src_port.get(), 0, 0);
			let mut mapped = ip.dst.into();
			for m in &mappings {
				m.to_udp(&mut mapped);
			}
			// TODO: For non-dual-stack sockets, we need this to be an ipv6 mapped address and then we need to canonicalize it. (I think that's correct at least...)
			let receiver = SocketAddr::new(mapped.into(), udp.dst_port.get());

			// Create a TURN message from this network message:
			let mut msg = Stun { buffer };
			msg.set_class(Class::Indication);
			msg.set_method(Method::Data);
			msg.set_length(0);
			msg.set_cookie(MAGIC_COOKIE);
			rng().fill_bytes(msg.set_txid());
			msg.append::<XOR_PEER_ADDRESS, SocketAddr>(&sender.into()).unwrap();

			// Fill a STUN DATA attribute
			let data = StunAttrHeader::mut_from_bytes(&mut msg.buffer[44..48]).unwrap();
			data.typ.set(DATA);
			data.length.set(data_len);
			// Zero out the padding bytes:
			msg.buffer[48 + data_len as usize..][..padding as usize].fill(0);

			msg.set_length(stun_length);

			// Send the new STUN Data indication to the receiver
			let length = msg.len();
			// TODO: For non-dual-stack sockets, we probably need the receiver in canonical form...
			let _ = socket.send_to(&msg.buffer[..length], receiver.into());
		}

		// Wait for something to happen
		poll.poll(&mut events, None)?;
	}
}
