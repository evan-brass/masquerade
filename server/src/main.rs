use eyre::{eyre, Result};
use rand::random_range;
use stun::{Stun, Class, Method, attr::{*, parse::AttrIter as _, integrity::Integrity}};
use tracing_subscriber::{layer::SubscriberExt, EnvFilter};
use std::{collections::BTreeMap, io::{Error, ErrorKind, Read as _, Write as _}, net::{IpAddr, Ipv6Addr}, u16};
use std::net::SocketAddr;
use std::rc::Rc;
use mio::event::Source as _;
use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::{Events, Poll, Interest, Token};
use std::collections::btree_map::Entry;
use std::cell::Cell;
use tracing::{debug, info, trace, warn};
type Never = core::convert::Infallible;

// Constants used by this server
const ICE_KEY: &[u8] = b"the/ice/password/constant";
const HOSTED: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 65535);

// We assign a link-local ip for each tcp stream u64 <-> Link local ip
fn make_ip(id: u64) -> IpAddr {
	let mut octets = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	octets[8..].copy_from_slice(&id.to_ne_bytes());
	IpAddr::V6(Ipv6Addr::from(octets))
}

fn would_block<T>(res: &Result<T, Error>) -> bool {
	match res {
		Err(e) if e.kind() == ErrorKind::WouldBlock => true,
		_ => false
	}
}

// These are the turn
struct Turn {
	stream: TcpStream,
	canonical: SocketAddr,
	partial: Cell<Option<(usize, Rc<[u8]>)>>,
}
impl Turn {
	pub fn read<'i>(&self, buffer: &'i mut [u8]) -> Result<Option<Stun<&'i mut [u8]>>> {
		let res = self.stream.peek(buffer);
		trace!(?res, "peek");
		let msg = Stun{buffer};
		let exp_len = msg.len();
		match res {
			_ if exp_len > msg.buffer.len() => Err(eyre!("STUN message exceeds buffer")),
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
	streams: BTreeMap<SocketAddr, Rc<Turn>>,
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

	fn handle_msg(&self, sender: SocketAddr, canonical: SocketAddr, mut msg: Stun<&mut [u8]>) {
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

		debug!(class = ?msg.class(), method = ?msg.method(), length = msg.length(), "STUN");

		// Compute a long-term key for authentication
		let turn_key = if let (Some(username), Some(realm)) = (username, realm) {
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
			// - Missing realm
			(Class::Request, _) if realm.is_none() => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(401, "")).unwrap();
				msg.append::<REALM, _>(&"none").unwrap();
				msg.append::<NONCE, _>(&"none").unwrap();
			}
			// - Wrong Username or Password
			(Class::Request, _) if !integrity.is_some_and(|i| i.verify(&turn_key)) =>
			{
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(441, ""))
					.unwrap();
			}

			// Allocate
			// - Wrong transport
			(Class::Request, Method::Allocate) if requested_transport != Some(17) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(442, "")).unwrap();
				msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice()).unwrap();
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
				msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice()).unwrap();
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
				msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice()).unwrap();
			}

			// Create Permission
			(Class::Request, Method::CreatePermission) => {
				// We don't enforce permissions so... success.
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice()).unwrap();
			}

			// Channel Bind
			(Class::Request, Method::ChannelBind) => {
				// Instead of supporting channels (which would require storing state) we send a nonsensical - but seemingly nonfatal - error to placate Chrome.
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(438, "")).unwrap();
				msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice()).unwrap();
			}

			// Send
			(Class::Indication, Method::Send) => {
				let (Some(peer), Some(data)) = (xor_peer, data) else { return };
				// Our sockets should be dual stack so we want ip6-mapped:
				let peer = SocketAddr::new(match peer.ip() {
					IpAddr::V4(v4) => v4.to_ipv6_mapped().into(),
					v => v
				}, peer.port());

				// Shift the data attribute to where we want it
				// [ STUN Header | XOR Peer Attr | Data... ]
				let mut len = data.len();
				let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
				msg.buffer.copy_within(i..i + 4 + len, 44);
				msg.set_length(0);
				msg.set_method(Method::Data);
				let data = &mut msg.buffer[48..][..len];

				// Peek inside the packet
				match (peer, data.first()) {
					(_, None) => return,

					(HOSTED, Some(0..3)) => {
						let mut inner = Stun { buffer: &mut msg.buffer[48..] };
						if inner.len() != len { return }
						if inner.class() != Class::Request || inner.method() != Method::Binding { return }
						// Parse ICE attributes
						let mut username = None;
						let mut integrity = None;
						let mut ice_controlled = None;
						let mut ice_controlling = None;
						let mut priority = None;
						let mut use_candidate = None;
						let mut fingerprint = None;
						let unknowns = inner
							.into_iter()
							.parse::<USERNAME, &str>(&mut username)
							.parse::<MESSAGE_INTEGRITY, Integrity<20>>(&mut integrity)
							.parse::<ICE_CONTROLLED, u64>(&mut ice_controlled)
							.parse::<ICE_CONTROLLING, u64>(&mut ice_controlling)
							.parse::<PRIORITY, u32>(&mut priority)
							.parse::<USE_CANDIDATE, ()>(&mut use_candidate)
							.parse::<FINGERPRINT, ()>(&mut fingerprint)
							.collect_unknown::<1>();

						if unknowns.is_some() { return }

						// Make sure all expected attributes are present and no unexpected attributes exist
						let (None, Some(username), Some(integrity), Some(_), Some(_), Some(())) = (
							unknowns,
							username,
							integrity,
							ice_controlled.xor(ice_controlling),
							priority,
							fingerprint,
						) else { return };

						// Split the username into dst_ufrag and src_ufrag
						let Some((dst_ufrag, src_ufrag)) = username.split_once(':') else { return };
						debug!(dst_ufrag, src_ufrag, "HOSTED ICE");

						// Wrong credentials
						if !integrity.verify(&ICE_KEY) {
							inner.set_length(0);
							inner.set_class(Class::Error);
							inner.append::<ERROR_CODE, _>(&(441, "")).unwrap();
							inner.append::<FINGERPRINT, _>(&()).unwrap();
							trace!("ICE Error 441");
						}
						// ICE Controlled - error switch role
						else if ice_controlled.is_some() {
							/*
							 * HACK: Firefox doesn't currently support switching roles on a 487 Error.
							 * We detect Firefox because it appends the fingerprint attribute to TURN send indications (pointlessly).
							 * Instead of returning an error, we have to send a request with a conflicting role.
							 * ISSUE: https://bugzilla.mozilla.org/show_bug.cgi?id=1940001
							 */
							if turn_fingerprint.is_some() {
								let username = format!("{src_ufrag}:{dst_ufrag}");
								inner.set_length(0);
								inner.append::<USERNAME, &str>(&username.as_str()).unwrap();
								inner.append::<ICE_CONTROLLED, u64>(&u64::MIN).unwrap();
								// inner.append::<PRIORITY, u32>(&0xdeadbeef).unwrap();
								inner.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).unwrap();
								inner.append::<FINGERPRINT, _>(&()).unwrap();
								debug!("ICE Firefox role conflict");
							}
							else {
								inner.set_length(0);
								inner.set_class(Class::Error);
								inner.append::<ERROR_CODE, _>(&(487, "")).unwrap();
								inner.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).unwrap();
								inner.append::<FINGERPRINT, _>(&()).unwrap();
								trace!("ICE Error 487");
							}
						}
						// Success
						else {
							inner.set_length(0);
							inner.set_class(Class::Success);
							inner
								.append::<XOR_MAPPED_ADDRESS, SocketAddr>(&sender.into())
								.unwrap();
							inner.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).unwrap();
							inner.append::<FINGERPRINT, _>(&()).unwrap();
							trace!("ICE Success");
						}

						len = inner.len();
						msg.append::<XOR_PEER_ADDRESS, SocketAddr>(&peer)
							.unwrap();
					}
					(HOSTED, Some(20..64)) => {
						warn!(?data, "DTLS needs relay");
						return;
					}

					_ => {
						receiver = peer;
						msg.append::<XOR_PEER_ADDRESS, SocketAddr>(&sender)
							.unwrap();
					}
				}

				// Zero out the padding bytes:
				let padding = (4 - len % 4) % 4;
				msg.buffer[48 + len..][..padding].fill(0);

				// Write the length of the Data attribute and update the length of the STUN packet
				msg.buffer[46..48].copy_from_slice(&u16::to_be_bytes(len as u16));
				msg.set_length(28 + (len + padding) as u16);
			}

			_ => return,
		}

		let frame = Rc::from(&msg.buffer[..msg.len()]);

		// Send UDP
		let _ = self.udp.send_to(&frame, receiver);
		// Send TCP
		let Some(turn) = self.streams.get(&receiver) else { return };
		turn.maybe_send(&frame);
	}

	pub fn run(mut self) -> Result<Never> {
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
						let canonical = SocketAddr::new(sender.ip().to_canonical(), sender.port());
						let msg = Stun{ buffer: &mut buffer[..] };
						if msg.len() == len {
							self.handle_msg(sender, canonical, msg);
						}
					}
					TCP => loop {
						let res = self.tcp.accept();
						if would_block(&res) { break }

						let (mut stream, addr) = res?;
						let canonical = SocketAddr::new(addr.ip().to_canonical(), addr.port());
						stream.set_nodelay(true)?;

						let token = random_range(0..TCP);
						// Coturn's default port range is 49152-65535.  Ours is 49152-65534, because 65535 is broadcast.
						let port = random_range(49152..65535);
						let key = SocketAddr::new(make_ip(token as u64), port);


						if let Entry::Vacant(slot) = self.streams.entry(key) {
							info!(?key, ?canonical, "Open");
							poll.registry().register(&mut stream, Token(token), Interest::READABLE | Interest::WRITABLE)?;
							slot.insert(Rc::new(Turn {
								stream,
								canonical,
								partial: Cell::default()
							}));
						}
					}
					tok => {
						let ip = make_ip(tok as u64);
						let end = SocketAddr::new(ip, u16::MAX);
						let mut iter = self.streams.range(SocketAddr::new(ip, u16::MIN)..end);
						while let Some((sender, turn)) = iter.next() {
							let sender = sender.clone();
							if event.is_writable() { turn.write(); }
							if event.is_readable() {
								loop {
									match turn.read(&mut buffer) {
										Ok(Some(msg)) => self.handle_msg(sender, turn.canonical, msg),
										Ok(None) => break,
										Err(error) => {
											let temp = Rc::try_unwrap(self.streams.remove(&sender).unwrap());
											iter = self.streams.range(sender..=end);
											let Ok(Turn { mut stream, canonical, ..}) = temp else { break };
											poll.registry().deregister(&mut stream)?;
											info!(?sender, ?canonical, ?error, "Close");
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

fn main() -> Result<Never> {
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
