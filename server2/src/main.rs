#![feature(slice_partition_dedup)]

use eyre::Result;
use stun::{Stun, Class, Method, attr::{*, parse::AttrIter as _, integrity::Integrity}};
use std::io::{Error, ErrorKind, Read as _, Write};
use std::net::SocketAddr;
use mio::event::Source;
use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::{Events, Poll, Interest, Token};

// Constants used by this server
const TURN_REALM: &str = "none";
const TURN_NONCE: &str = "none";
const TURN_USER: &str = "guest";
// turn_key = md5("guest:none:password")
const TURN_KEY: &[u8] = &[
	0x01, 0x5c, 0x8a, 0x97, 0x3e, 0xa4, 0xb4, 0xa9, 0xc9, 0x45, 0xf6, 0x90, 0x14, 0x2b, 0xf3, 0xad,
];

fn would_block<T>(res: &Result<T, Error>) -> bool {
	match res {
		Err(e) if e.kind() == ErrorKind::WouldBlock => true,
		_ => false
	}
}

// These are the turn
struct Turn {
	addr: SocketAddr,
	stream: TcpStream,
	// TODO: Firefox enforces permissions, so we also might need a map from SocketAddr -> u16 (pseudo port).  I wonder if we use a sorted map again... then firefox would see the remote port changing as they receive, but... IDK
}
struct TurnServer {
	udp: UdpSocket,
	tcp: TcpListener,
	// NOTE: streams must be sorted by Turn.addr, and
	streams: Vec<Turn>,
	// TODO: Add DTLS state
}
const UDP: usize = usize::MAX;
const TCP: usize = usize::MAX - 1;
impl TurnServer {
	pub fn new(addr: SocketAddr) -> Result<Self> {
		let udp = UdpSocket::bind(addr)?;
		let tcp = TcpListener::bind(addr)?;
		Ok(Self { udp, tcp, streams: Vec::new() })
	}

	fn handle_msg(&mut self, sender: SocketAddr, mut msg: Stun<&mut [u8]>) {
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
				if let (Some(SocketAddr::V6(peer)), Some(data)) = (xor_peer, data) {
					// [ STUN Header | XOR Peer Attr | Data... ]

					// Shift the data attribute to where we want it
					let len = data.len();
					let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
					msg.buffer.copy_within(i..i + 4 + len, 44);
					msg.set_length(0);
					msg.set_method(Method::Data);

					// Write the peer address into the space we made by shifting the data attribute
					msg.append::<XOR_PEER_ADDRESS, SocketAddr>(&sender.into())
						.unwrap();
					receiver = peer.into();

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

		// Find the tcp stream for the receiver (if no stream is available, then send it over udp)
		let response = &msg.buffer[..msg.len()];
		let res = if let Ok(i) = self.streams.binary_search_by(|t| t.addr.cmp(&receiver)) {
			let turn = &mut self.streams[i];
			turn.stream.write_all(response)
		} else {
			self.udp.send_to(response, receiver).map(|_| {})
		};
		if would_block(&res) { return }
		if let Err(e) = res {
			println!("{e:?}");
		}
	}

	pub fn run(mut self) -> Result<std::convert::Infallible> {
		let mut buffer = [0; 2048];
		let mut poll = Poll::new()?;

		const EVENT_CAPACITY: usize = 128;
		let mut events = Events::with_capacity(EVENT_CAPACITY);
		self.udp.register(poll.registry(), Token(UDP), Interest::READABLE)?;
		self.tcp.register(poll.registry(), Token(TCP), Interest::READABLE)?;
		loop {
			// We want to handle the event's in a sorted ordering.  Handling TCP last means new connections (and inserts into streams) will happen after processing everything.  This also means that we will only need to keep track of removals, which is just a fixed offset to find the true turn from it's old token.
			let mut tokens = [0; EVENT_CAPACITY];
			let mut count = 0;
			for e in events.iter() {
				tokens[count] = e.token().0;
				count += 1;
			}
			let tokens = &mut tokens[0..count];
			tokens.sort();
			// Remove duplicates(we handle in a loop below so should be fine)
			let (tokens, _) = tokens.partition_dedup();

			let mut removals = 0;

			// Iterate over each unique token
			for tok in tokens {
				match *tok {
					UDP => {
						loop {
							let res = self.udp.recv_from(&mut buffer);
							if would_block(&res) { break }

							let (len, sender) = res?;
							let msg = Stun{ buffer: &mut buffer[..] };
							if msg.len() == len {
								self.handle_msg(sender, msg);
							}
						}
					}
					TCP => {
						loop {
							let res = self.tcp.accept();
							if would_block(&res) { break }

							let (mut stream, addr) = res?;
							stream.set_nodelay(true)?;

							// We should never have two tcp streams with the same remote address.
							let i = self.streams.binary_search_by(|t| t.addr.cmp(&addr)).unwrap_err();

							// Reserve space for another stream
							if self.streams.try_reserve(1).is_err() { continue }

							stream.register(poll.registry(), Token(i), Interest::READABLE)?;
							self.streams.insert(i, Turn{addr, stream});

							// Reregister all following streams to fix their Token
							for j in (i + 1)..self.streams.len() {
								let turn = &mut self.streams[j];
								turn.stream.reregister(poll.registry(), Token(j), Interest::READABLE)?;
							}
						}
					}
					i => {
						// Adjust the token to match current indexes:
						let i = i - removals;
						loop {
							let turn = &mut self.streams[i];
							let sender = turn.addr;
							let res = turn.stream.peek(&mut buffer);
							if would_block(&res) { break }

							// Handle streams being closed / erroring out
							let Ok(len) = res else {
								turn.stream.deregister(poll.registry())?;
								self.streams.remove(i);
								removals += 1;
								break
							};
							// We can't read the msg_len of this packet until we have at least 4 bytes
							if len < 4 { break }
							let msg_len = Stun { buffer: &buffer[..] }.len();

							// Close connection if message is too large for our buffer
							if msg_len > buffer.len() {
								turn.stream.deregister(poll.registry())?;
								self.streams.remove(i);
								removals += 1;
								break
							}

							// If we don't have the full message than wait
							if msg_len > len { break }

							// Consume the peeked data
							turn.stream.read_exact(&mut buffer[..msg_len])?;

							let msg = Stun { buffer: &mut buffer[..] };
							self.handle_msg(sender, msg);
						}
					}
				}
			}
			poll.poll(&mut events, None)?;
		}
	}
}

fn main() -> Result<std::convert::Infallible> {
	let addr = "[::]:3478".parse()?;
	let server = TurnServer::new(addr)?;
	server.run()
}
