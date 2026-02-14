use std::io::{ErrorKind, Read, Write};
use std::net::Ipv6Addr;
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::{net::SocketAddr, net::SocketAddrV6};

use clap::Parser;
use eyre::{Result, eyre};
use ipnet::Ipv6Net;
use masquerade::common::{handle_net, handle_turn};
use masquerade::stun::Error as StunError;
use masquerade::stun::Stun;
use mio::net::{TcpListener, TcpStream};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use slab::Slab;
use tappers::{Interface, Tun};
use tracing_subscriber::EnvFilter;

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
	subnet: Ipv6Net,
}
impl Mapping {
	fn new(subnet: Ipv6Net) -> Result<Self> {
		let min_prefix_len = 128 - (usize::BITS - 15);
		if min_prefix_len > subnet.prefix_len() as u32 {
			return Err(eyre!(
				"Need at most /{min_prefix_len} subnet for a system with {} usize bits, found /{}",
				usize::BITS,
				subnet.prefix_len()
			));
		}
		Ok(Self { subnet })
	}
	fn from_index(&self, index: usize) -> Option<SocketAddrV6> {
		// The least 15 bits become the port
		let port = (index & 0x7fff | 0x8000) as u16;

		// The remaining 17 or 49 bits are the host
		let host = Ipv6Addr::from_bits(index as u128 >> 15);
		let ip = self.subnet.network() | host;

		// Check if we've exceeded our subnet
		if !self.subnet.contains(&ip) {
			return None;
		}

		Some(SocketAddrV6::new(ip.into(), port, 0, 0))
	}
	fn to_index(&self, addr: SocketAddrV6) -> Option<usize> {
		if !self.subnet.contains(addr.ip()) {
			return None;
		};
		let host = addr.ip() & self.subnet.hostmask();
		let ret = (host.to_bits() << 15) | (0x7FFF & addr.port()) as u128;
		Some(ret as usize)
	}
}

struct Conn {
	relayed: SocketAddrV6,
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
	poll.registry()
		.register(&mut SourceFd(&network.as_raw_fd()), TUN, Interest::READABLE)?;

	let mut buffer = [0; 65536];
	let mut events = Events::with_capacity(128);
	let mut streams = Slab::new();

	loop {
		for e in events.into_iter() {
			match e.token() {
				// Accept incoming TCP streams
				TCP => loop {
					let Ok((mut stream, _sender)) = listener.accept() else {
						break;
					};
					stream.set_nodelay(true)?;
					let entry = streams.vacant_entry();
					let key = entry.key();
					let Some(relayed) = mapping.from_index(key) else {
						continue;
					};
					poll.registry().register(
						&mut stream,
						Token(entry.key()),
						Interest::READABLE | Interest::WRITABLE,
					)?;
					entry.insert(Conn {
						relayed,
						partial: None,
						stream,
					});
				},
				// Handle UDP traffic off the net
				TUN => loop {
					let Ok(len) = network.recv(&mut buffer) else {
						break;
					};

					let Some((receiver, msg)) = handle_net(len, &mut buffer) else {
						continue;
					};

					let Some(index) = mapping.to_index(receiver) else {
						continue;
					};
					let Some(conn) = streams.get_mut(index) else {
						continue;
					};
					// Don't attempt to write a frame unless the previous frame has finished writing.
					if conn.partial.is_some() {
						continue;
					};

					// Send the new STUN Data indication to the receiver
					let length = msg.len();
					let frame = &msg.buffer[..length];
					match conn.stream.write(frame) {
						Ok(written) if written < length => {
							conn.partial = Some((0, Box::from(&frame[written..])));
						}
						Err(e) if e.kind() == ErrorKind::WouldBlock => {}
						Ok(_) => {}
						Err(_) => {
							// Cleanup
							let Conn { mut stream, .. } = streams.remove(index);
							poll.registry().deregister(&mut stream)?;
						}
					}
				},
				// Handle a TCP stream becoming readable / writable
				Token(index) => 'event: {
					let Some(Conn {
						stream,
						partial,
						relayed,
					}) = streams.get_mut(index)
					else {
						// This break could be taken when multiple events are queued for a given stream, but an earlier one already closed/removed the stream
						break 'event;
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
							let Some((offset, buffer)) = partial.take() else {
								break;
							};
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
						loop {
							let msg = Stun {
								buffer: buffer.as_mut_slice(),
							};
							match stream.peek(msg.buffer) {
								Err(e) if e.kind() == ErrorKind::WouldBlock => break,
								Ok(length) => match msg.decode(length) {
									// Stream clogged... STUN/TURN message is bigger than our static sized read buffer...
									Err(StunError::TooShort(expected))
										if expected > msg.buffer.len() =>
									{
										// Cleanup
										poll.registry().deregister(stream)?;
										streams.remove(index);
										break 'event;
									}
									Err(StunError::TooShort(_)) => break,
									Err(StunError::NotStun) => {
										// Cleanup
										poll.registry().deregister(stream)?;
										streams.remove(index);
										break 'event;
									}
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
								},
								Err(_) => {
									// Cleanup
									poll.registry().deregister(stream)?;
									streams.remove(index);
									break 'event;
								}
							}

							// Drop the TURN message if we have partial data waiting to be written out
							if partial.is_some() {
								continue;
							};

							let canonical = SocketAddr::V6(*relayed);
							let Some(resp) = handle_turn(canonical, *relayed, msg, &network) else {
								continue;
							};

							let length = resp.len();
							let mut offset = 0;
							loop {
								let rest = &resp.buffer[offset..length];
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
