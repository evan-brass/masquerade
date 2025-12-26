use std::io::{ErrorKind, Read, Write};
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::{
	net::SocketAddr,
	net::SocketAddrV6,
	net::IpAddr,
};

use clap::Parser;
use eyre::{Result, eyre};
use ipnet::Ipv6Net;
use masquerade::stun::Error as StunError;
use mio::net::{TcpListener, TcpStream};
use mio::{
	Events, Interest, Poll, Token,
};
use masquerade::stun::{
	Class, Method, Stun, MAGIC_COOKIE,
	attr::{integrity::Integrity, parse::AttrIter as _, *},
};
use masquerade::wire::{FromBytes, IntoBytes, Ip6Header, StunAttrHeader, UdpHeader, ip_checksum, ip_proto};
use slab::Slab;
use tappers::{Interface, Tun};
use tracing_subscriber::EnvFilter;
use rand::{RngCore, rng};

type Never = core::convert::Infallible;

const TCP: Token = Token(usize::MAX);
const TUN: Token = Token(usize::MAX - 1);

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "[::]:3478")]
	address: String,

	#[arg(long, short, default_value = "fd01::/79")]
	subnet: String,

	#[arg(long, short)]
	if_name: Option<String>,
}

struct Mapping {
	subnet: Ipv6Net
}
impl Mapping {
	fn new(subnet: Ipv6Net) -> Result<Self> {
		let needed_prefix = 128 - (usize::BITS - 15);
		if subnet.prefix_len() as u32 != needed_prefix {
			return Err(eyre!("Need a /{needed_prefix} subnet for a system with {} usize bits", usize::BITS));
		}
		Ok(Self { subnet })
	}
	fn from_index(&self, index: usize) -> SocketAddr {
		// The least 15 bits become the port
		let port = (index & 0x7fff | 0x8000) as u16;

		// The remaining 17 or 49 bits are the host
		let host = Ipv6Addr::from_bits(index as u128 >> 15);
		let ip = self.subnet.network() | host;

		SocketAddr::new(ip.into(), port)
	}
	fn to_index(&self, addr: SocketAddr) -> Option<usize> {
		let IpAddr::V6(ip) = addr.ip() else { return None };
		if !self.subnet.contains(&ip) { return None };
		let host = ip & self.subnet.hostmask();
		let ret = (host.to_bits() << 15) | (0x7FFF & addr.port()) as u128;
		Some(ret as usize)
	}
}

struct Conn {
	relayed: SocketAddr,
	// TODO: Add support for channel binding?
	partial: Option<(usize, Box<[u8]>)>,
	stream: TcpStream,
}
impl PartialEq for Conn {
	fn eq(&self, other: &Self) -> bool {
		self.relayed.eq(&other.relayed)
	}
}
impl Eq for Conn {}
impl PartialOrd for Conn {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		self.relayed.partial_cmp(&other.relayed)
	}
}
impl Ord for Conn {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		self.relayed.cmp(&other.relayed)
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
	let mut listener = TcpListener::bind(args.address.parse()?)?;

	// Setup the TUN interface
	let mut network = if let Some(if_name) = args.if_name {
		Tun::new_named(Interface::new(if_name)?)?
	} else {
		Tun::new()?
	};
	network.set_nonblocking(true)?;

	// Parse subnet and use it for our mapping
	let subnet = Ipv6Net::from_str(&args.subnet)?;
	let mapping = Mapping::new(subnet)?;

	let mut poll = Poll::new()?;
	poll.registry()
		.register(&mut listener, TCP, Interest::READABLE)?;

	let mut buffer = [0; 65536];
	let mut events = Events::with_capacity(128);
	let mut streams = Slab::new();

	// Ready to receive
	network.set_up()?;

	loop {
		for e in events.into_iter() {
			match e.token() {
				// Accept incoming TCP streams
				TCP => loop {
					let Ok((mut stream, _sender)) = listener.accept() else { break };
					stream.set_nodelay(true)?;
					let entry = streams.vacant_entry();
					let key = entry.key();
					let relayed = mapping.from_index(key);
					poll.registry().register(
						&mut stream,
						Token(entry.key()),
						Interest::READABLE | Interest::WRITABLE
					)?;
					entry.insert(Conn {
						relayed,
						partial: None,
						stream,
					});
				}
				// Handle UDP traffic off the net
				TUN => loop {
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

					let receiver = SocketAddr::new(ip.dst.into(), udp.dst_port.get());
					let Some(index) = mapping.to_index(receiver) else { continue };
					let Some(conn) = streams.get_mut(index) else { continue };
					// Don't attempt to write a frame unless the previous frame has finished writing.
					if conn.partial.is_some() { continue };

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
					let frame = &msg.buffer[..length];
					match conn.stream.write(frame) {
						Ok(written) if written < length => {
							conn.partial = Some((0, Box::from(&frame[written..])));
						}
						Err(e) if e.kind() == ErrorKind::WouldBlock => {},
						Ok(_) => {},
						Err(_) => {
							// Cleanup
							let Conn { mut stream, .. } = streams.remove(index);
							poll.registry().deregister(&mut stream)?;
						}
					}
				}
				// Handle a TCP stream becoming readable / writable
				Token(index) => 'event: {
					let Some(Conn {
						stream,
						partial,
						relayed
					}) = streams.get_mut(index) else {
						// This break could be taken when multiple events are queued for a given stream, but an earlier one already closed/removed the stream
						break 'event
					};

					// NOTE: For cleanup, there's no need to finish writing partial data or anything like that, we just close.
					if e.is_read_closed() || e.is_error() {
						// Cleanup
						poll.registry().deregister(stream)?;
						streams.remove(index);
						break 'event;
					}

					// Continue writing previous partial frame
					if e.is_writable() {
						loop {
							let Some((offset, buffer)) = partial.take() else { break };
							let rest = &buffer[offset..];

							match stream.write(rest) {
								Ok(written) if written >= rest.len() => break,
								Ok(written) => *partial = Some((offset + written, buffer)),
								Err(e) if e.kind() == ErrorKind::WouldBlock => {
									*partial = Some((offset, buffer));
									break;
								}
								Err(_) => {
									// Cleanup
									poll.registry().deregister(stream)?;
									streams.remove(index);
									break 'event;
								}
							}
						}
					}

					// Handle reading
					if e.is_readable() || e.is_error() {
						let mut msg = Stun { buffer: buffer.as_mut_slice() };
						loop {
							match stream.peek(msg.buffer) {
								Err(e) if e.kind() == ErrorKind::WouldBlock => break,
								Ok(length) => match msg.decode(length) {
									Err(StunError::TooShort(_)) => break,
									Err(StunError::NotStun) => {
										// Cleanup
										poll.registry().deregister(stream)?;
										streams.remove(index);
										break 'event;
									},
									Ok(()) => {
										let length = msg.len();
										let n = stream.read(&mut msg.buffer[..length])?;
										if n != length {
											eprintln!("Read failure after successful peek. Lame.");
											// Cleanup
											poll.registry().deregister(stream)?;
											streams.remove(index);
											break 'event;
										}
									}
								}
								Err(_) => {
									// Cleanup
									poll.registry().deregister(stream)?;
									streams.remove(index);
									break 'event;
								}
							}

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
									msg.append::<XOR_MAPPED_ADDRESS, SocketAddr>(relayed)
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
									msg.append::<XOR_MAPPED_ADDRESS, _>(relayed).unwrap();
									msg.append::<XOR_RELAYED_ADDRESS, SocketAddr>(relayed)
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
									// TODO: Add support for channel binding?
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
									let IpAddr::V6(src_addr) = relayed.ip() else {
										// TODO: relayed should really be a SocketAddrV6 but I'm lazy
										unreachable!();
									};
									let length = len as u16 + 8;

									// IP6 + UDP = 40 + 8 = 48 = STUN Data Indication! Perfect.  No copy/shift needed.
									let (ip, rest) = Ip6Header::mut_from_prefix(msg.buffer).unwrap();
									let (udp, rest) = UdpHeader::mut_from_prefix(rest).unwrap();
									let data = &rest[..len];
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
									let checksum = ip_checksum(&[
										&ip.src,
										&ip.dst,
										&[0, ip.next_header],
										&ip.payload_length.as_bytes(),
										&udp.as_bytes(),
										data
									]);
									udp.checksum.set(if checksum == 0 { 0xffff } else { checksum });

									// Emit the UDP packet to the network:
									let length = ip.len();
									let _ = network.send(&msg.buffer[..length]);
									continue;
								}
								_ => continue,
							}

							// Write the STUN response (Unless we already have a frame in flight)
							if partial.is_some() { continue };

							let length = msg.len();
							let mut offset = 0;
							loop {
								let rest = &msg.buffer[offset..length];
								match stream.write(rest) {
									Ok(written) if written >= rest.len() => break,
									Ok(written) => offset += written,
									Err(e) if e.kind() == ErrorKind::WouldBlock => {
										*partial = Some((0, Box::from(rest)));
									}
									Err(_) => {
										// Cleanup
										poll.registry().deregister(stream)?;
										streams.remove(index);
										break 'event;
									}
								}
							}
						}
					}
				}
			}
		}

		// Wait for something to happen
		poll.poll(&mut events, None)?;
	}
}
