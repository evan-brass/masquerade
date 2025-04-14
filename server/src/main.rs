use eyre::Result;
use rand::random_range;
use stun::{Stun, Class, Method, attr::{*, parse::AttrIter as _, integrity::Integrity}};
use tracing_subscriber::{layer::SubscriberExt, EnvFilter};
use std::{collections::BTreeMap, io::{Error, ErrorKind, Read as _, Write as _}, net::{IpAddr, Ipv6Addr}};
use std::net::SocketAddr;
use std::rc::Rc;
use mio::event::Source as _;
use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::{Events, Poll, Interest, Token};
use std::collections::btree_map::Entry;
use std::cell::Cell;
use tracing::{debug, info, trace};

// Constants used by this server
const TURN_REALM: &str = "none";
const TURN_NONCE: &str = "none";
const TURN_USER: &str = "guest";
// turn_key = md5("guest:none:password")
const TURN_KEY: &[u8] = &[
	0x01, 0x5c, 0x8a, 0x97, 0x3e, 0xa4, 0xb4, 0xa9, 0xc9, 0x45, 0xf6, 0x90, 0x14, 0x2b, 0xf3, 0xad,
];
// FUCK: Firefox seems to dislike broadcast addresses so none of my favorite options worked:
// - ::ffff:255.255.255.255 failed
// - ff02::1 failed
// So we're stuck with frickin fe80::ffff:ffff:ffff:ffff which is reserved because it is the token for UDP (probably, at least if you're 64bit)
const BROADCAST: IpAddr = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
const BROADCAST_FF: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff));

// We assign a link-local ip for each tcp stream u64 <-> Link local ip
fn make_ip(id: u64) -> IpAddr {
	let mut octets = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	octets[8..].copy_from_slice(&id.to_ne_bytes());
	IpAddr::V6(Ipv6Addr::from(octets))
}
fn get_key(ip: IpAddr) -> Option<u64> {
	match ip {
		IpAddr::V6(ip6) if ip6.is_unicast_link_local() => Some(u64::from_ne_bytes(ip6.octets()[8..].try_into().unwrap())),
		_ => None
	}
}

fn would_block<T>(res: &Result<T, Error>) -> bool {
	match res {
		Err(e) if e.kind() == ErrorKind::WouldBlock => true,
		_ => false
	}
}

// These are the turn
struct Turn {
	port: u16,
	stream: TcpStream,
	partial: Cell<Option<(usize, Rc<[u8]>)>>,
	// TODO: Firefox enforces permissions, so we also might need a map from SocketAddr -> u16 (pseudo port).  I wonder if we use a sorted map again... then firefox would see the remote port changing as they receive, but... IDK
}
impl Turn {
	pub fn read<'i>(&self, buffer: &'i mut [u8]) -> Result<Option<Stun<&'i mut [u8]>>> {
		let res = self.stream.peek(buffer);
		trace!(?res, "peek");
		let msg = Stun{buffer};
		let exp_len = msg.len();
		match res {
			// exp_len is only set after 4 bytes
			Ok(peeked) if peeked < 4 => Ok(None),
			// Read
			Ok(peeked) if peeked >= exp_len => {
				(&self.stream).read_exact(&mut msg.buffer[..exp_len])?;
				Ok(Some(msg))
			}
			Err(e) if e.kind() != ErrorKind::WouldBlock => Err(e.into()),
			_ => Ok(None)
		}
	}
	pub fn write(&self) {
		loop {
			if let Some((offset, frame)) = self.partial.take() {
				let rest = &frame[offset..];
				let res = (&self.stream).write(rest);
				trace!(?res, "write");
				match res {
					// Partial Write
					Ok(written) if written < rest.len() => {
						self.partial.set( Some((offset + written, frame)));
						// Partial writes are the only case where we retry
						continue;
					},
					// Completed Write
					Ok(_) => {},
					// Would Block
					Err(e) if e.kind() == ErrorKind::WouldBlock => self.partial.set(Some((offset, frame))),
					// Any other error
					Err(_) => {
						let _ = self.stream.shutdown(std::net::Shutdown::Both);
					}
				}
			}
			break;
		}
	}
	pub fn maybe_send(&self, frame: &Rc<[u8]>) {
		self.partial.set(match self.partial.take() {
			None => Some((0, frame.clone())),
			v => v
		});
		self.write();
	}
}

struct TurnServer {
	udp: UdpSocket,
	tcp: TcpListener,
	streams: BTreeMap<u64, Turn>,
	// TODO: Add DTLS state somewhere
}
const UDP: usize = usize::MAX;
const TCP: usize = usize::MAX - 1;
impl TurnServer {
	pub fn new(addr: SocketAddr) -> Result<Self> {
		let udp = UdpSocket::bind(addr)?;
		let tcp = TcpListener::bind(addr)?;
		Ok(Self { udp, tcp, streams: BTreeMap::new() })
	}

	fn handle_msg(&self, sender: SocketAddr, mut msg: Stun<&mut [u8]>) {
		// Canonical socket address (ipv6-mapped -> ipv4)
		let canonical = SocketAddr::new(sender.ip().to_canonical(), sender.port());

		let mut receiver = sender;

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
			.collect_unknown::<8>();

		debug!(class = ?msg.class(), method = ?msg.method(), length = msg.length(), "STUN");

		match (msg.class(), msg.method()) {
			// Unknown Method
			(Class::Request, meth)
				if ![
					Method::Binding,
					Method::Allocate,
					Method::Refresh,
					Method::CreatePermission,
					Method::ChannelBind,
				]
				.contains(&meth) =>
			{
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(404, "")).unwrap(); // Error code is not in the spec, but we don't care.
			}

			// Unknown Attributes
			(Class::Request, _) if unknown_attrs.is_some() => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(420, "")).unwrap();
				msg.append::<UNKNOWN_ATTRIBUTES, _>(&unknown_attrs.unwrap())
					.unwrap();
			}

			// Binding Request
			(Class::Request, Method::Binding) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical).unwrap();
			}

			// All future requests require authentication:
			// - Realm or nonce missing / wrong
			(Class::Request, _) if realm != Some(TURN_REALM) || nonce != Some(TURN_NONCE) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(401, "")).unwrap();
				msg.append::<REALM, _>(&TURN_REALM).unwrap();
				msg.append::<NONCE, _>(&TURN_NONCE).unwrap();
			}
			// - Wrong Username or Password
			(Class::Request, _)
				if username != Some(TURN_USER)
					|| !integrity.is_some_and(|i| i.verify(TURN_KEY)) =>
			{
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(441, "guest:none:password"))
					.unwrap();
			}

			// Allocate
			// - Wrong transport
			(Class::Request, Method::Allocate) if requested_transport != Some(17) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(442, "")).unwrap();
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).unwrap();
			}
			// - Normal
			(Class::Request, Method::Allocate) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical).unwrap();
				msg.append::<XOR_RELAYED_ADDRESS, SocketAddr>(&sender.into())
					.unwrap();
				msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000))
					.unwrap();
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).unwrap();
			}

			// Refresh
			// - Close connection (No response is needed)
			(Class::Request, Method::Refresh) if lifetime == Some(0) => return,
			// - Normal
			(Class::Request, Method::Refresh) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000))
					.unwrap();
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).unwrap();
			}

			// Create Permission
			(Class::Request, Method::CreatePermission) => {
				// We don't enforce permissions so... success.
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).unwrap();
			}

			// Channel Bind
			(Class::Request, Method::ChannelBind) => {
				// Instead of supporting channels (which would require storing state) we send a nonsensical - but seemingly nonfatal - error to placate Chrome.
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(438, "")).unwrap();
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).unwrap();
			}

			// Send
			(Class::Indication, Method::Send) => {
				if let (Some(peer), Some(data)) = (xor_peer, data) {
					// Our sockets should be dual stack so we want ip6-mapped:
					let peer = SocketAddr::new(match peer.ip() {
						IpAddr::V4(v4) => v4.to_ipv6_mapped().into(),
						v => v
					}, peer.port());
					receiver = peer;

					trace!(
						?sender,
						?receiver,
						data,
						"Relay"
					);

					// [ STUN Header | XOR Peer Attr | Data... ]

					// Shift the data attribute to where we want it
					let len = data.len();
					let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
					msg.buffer.copy_within(i..i + 4 + len, 44);
					msg.set_length(0);
					msg.set_method(Method::Data);

					// We have two modes of broadcast: one preserves the sender address (just like unicast) the other masks the ip and identifies connections via port.
					msg.append::<XOR_PEER_ADDRESS, SocketAddr>(&match peer.ip() {
						BROADCAST_FF => SocketAddr::new(BROADCAST_FF, sender.port()),
						_ => sender
					})
						.unwrap();

					// Zero out the padding bytes:
					let padding = (4 - len % 4) % 4;
					msg.buffer[48 + len..][..padding].fill(0);

					// Write the length of the Data attribute and update the length of the STUN packet
					msg.buffer[46..48].copy_from_slice(&u16::to_be_bytes(len as u16));
					msg.set_length(28 + (len + padding) as u16);
				} else {
					return;
				}
			}

			_ => return,
		}

		let frame = Rc::from(&msg.buffer[..msg.len()]);

		match (receiver.ip(), receiver.port()) {
			// Broadcast
			(BROADCAST, _) |
			(BROADCAST_FF, 65535) => {
				for turn in self.streams.values() {
					turn.maybe_send(&frame);
				}
			}
			// Fucked up hack to support firefox
			(BROADCAST_FF, port) => {
				for turn in self.streams.values() {
					if turn.port == port {
						turn.maybe_send(&frame);
					}
				}
			}
			// TCP unicast
			(ip, _) => if let Some(key) = get_key(ip) {
				if let Some(turn) = self.streams.get(&key) {
					turn.maybe_send(&frame);
				}
			}
			// UDP unicast
			else {
				let _ = self.udp.send_to(&frame, receiver);
			}
		}
	}

	pub fn run(mut self) -> Result<std::convert::Infallible> {
		let mut buffer = [0; 2048];
		let mut poll = Poll::new()?;

		let mut events = Events::with_capacity(128);
		self.udp.register(poll.registry(), Token(UDP), Interest::READABLE)?;
		self.tcp.register(poll.registry(), Token(TCP), Interest::READABLE)?;

		loop {
			for event in events.iter() {
				trace!(?event, "Event");
				match event.token().0 {
					UDP => loop {
						let res = self.udp.recv_from(&mut buffer);
						if would_block(&res) { break }

						let (len, sender) = res?;
						let msg = Stun{ buffer: &mut buffer[..] };
						if msg.len() == len {
							self.handle_msg(sender, msg);
						}
					}
					TCP => loop {
						let res = self.tcp.accept();
						if would_block(&res) { break }

						let (mut stream, addr) = res?;
						stream.set_nodelay(true)?;

						let token = random_range(0..TCP);
						let key = token as u64;

						if let Entry::Vacant(slot) = self.streams.entry(key) {
							// Coturn's default port range is 49152-65535.  Ours is 49152-65534, because 65535 is broadcast.
							let port = random_range(49152..65535);
							info!(key, port, ?addr, "Open");
							poll.registry().register(&mut stream, Token(token), Interest::READABLE | Interest::WRITABLE)?;
							slot.insert(Turn {
								stream,
								port,
								partial: Cell::default()
							});
						}
					}
					tok => {
						let key = tok as u64;
						if let Some(turn) = self.streams.get(&key) {
							if event.is_writable() { turn.write(); }
							if event.is_readable() {
								let sender = SocketAddr::new(make_ip(key), turn.port);
								loop {
									match turn.read(&mut buffer) {
										Ok(Some(msg)) => self.handle_msg(sender, msg),
										Ok(None) => break,
										Err(error) => {
											let Some(Turn{ mut stream, port, ..}) = self.streams.remove(&key) else { break };
											poll.registry().deregister(&mut stream)?;
											info!(key, port, ?error, "Close");
											break;
										}
									}
								}
							}
						}
					}
				}
			}

			trace!("Poll");
			poll.poll(&mut events, None)?;
		}
	}
}

fn main() -> Result<std::convert::Infallible> {
	// Enable logging
	tracing::subscriber::set_global_default(
		tracing_subscriber::registry()
		.with(tracing_subscriber::fmt::layer())
		.with(EnvFilter::from_default_env())
	)?;

	let addr = "[::]:3478".parse()?;
	let server = TurnServer::new(addr)?;
	server.run()
}
