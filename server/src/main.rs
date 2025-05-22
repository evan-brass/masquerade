use mio::{
	event::Event,
	net::{TcpListener, TcpStream, UdpSocket},
	Events, Interest, Poll, Token,
};
use slab::Slab;
use std::{
	collections::BTreeSet,
	io::{self, BufWriter, ErrorKind, Read, Write},
	net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr},
	rc::Rc,
};
use rand::random;
use stun::{attr::integrity::Integrity, attr::parse::AttrIter as _, attr::*, Class, Method, Stun};
use tracing::trace;
use tracing_subscriber::{prelude::*, EnvFilter};

type Never = core::convert::Infallible;
const ACCEPT: usize = usize::MAX;
const ICE_KEY: &[u8] = b"the/ice/password/constant";
const SWITCHBOARD: SocketAddr = SocketAddr::new(
	IpAddr::V6(Ipv6Addr::new(
		0xfe80, 0, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff,
	)),
	65535,
);

// We assign a link-local ip for each tcp stream u64 <-> Link local ip
fn make_ip(token: usize) -> IpAddr {
	let mut octets = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	octets[8..].copy_from_slice(&(token as u64).to_be_bytes());
	IpAddr::V6(Ipv6Addr::from(octets))
}
fn get_key(ip: IpAddr) -> Option<usize> {
	match ip {
		IpAddr::V6(ip6) if ip6.is_unicast_link_local() => {
			Some(u64::from_be_bytes(ip6.octets()[8..].try_into().unwrap()) as usize)
		}
		_ => None,
	}
}

#[derive(Debug)]
enum Turn {
	Udp {
		socket: UdpSocket,
	},
	Tcp {
		stream: BufWriter<TcpStream>,
		canonical: SocketAddr,
		username: Option<Rc<str>>,
		ufrag: Option<String>,
	},
}
impl Turn {
	pub fn handle<'i>(
		&mut self,
		e: &Event,
		buffer: &'i mut [u8],
	) -> io::Result<Option<(SocketAddr, SocketAddr, Stun<&'i mut [u8]>)>> {
		match self {
			Self::Udp { socket } => {
				// Udp, Should only return would-block errors anyway.
				let (len, allocated) = socket
					.recv_from(buffer)
					.map_err(|e| io::Error::new(ErrorKind::WouldBlock, e))?;
				let canonical = SocketAddr::new(allocated.ip().to_canonical(), allocated.port());
				let msg = Stun { buffer };
				if len < msg.len() {
					return Ok(None);
				}
				Ok(Some((allocated, canonical, msg)))
			}
			Self::Tcp {
				stream, canonical, ..
			} => {
				let would_block = Err(io::Error::new(ErrorKind::WouldBlock, ""));
				let allocated = SocketAddr::new(make_ip(e.token().0), canonical.port());
				if e.is_writable() {
					stream.flush()?;
				}
				if e.is_read_closed() {
					stream.get_ref().shutdown(Shutdown::Both)?;
					return Err(io::Error::other("Read Closed"));
				}
				if e.is_readable() {
					let len = stream.get_ref().peek(buffer)?;
					if len < 4 {
						return would_block;
					}
					let msg = Stun { buffer };
					if msg.len() > msg.buffer.len() {
						return Err(io::Error::other("STUN message too large to fit in buffer"));
					}
					if len < msg.len() {
						return would_block;
					}
					let exp_len = msg.len();
					stream.get_ref().read_exact(&mut msg.buffer[..exp_len])?;
					return Ok(Some((allocated, *canonical, msg)));
				}
				would_block
			}
		}
	}
	pub fn maybe_send(&mut self, receiver: SocketAddr, frame: &[u8]) -> io::Result<()> {
		match self {
			Self::Udp { socket } => {
				let _ = socket.send_to(frame, receiver);
			}
			Self::Tcp { stream, .. } => {
				let spare_capacity = stream.capacity() - stream.buffer().len();
				if frame.len() <= spare_capacity {
					stream.write_all(frame).unwrap();
					stream.flush()?;
				}
			}
		}
		Ok(())
	}
}

fn main() -> eyre::Result<Never> {
	// Enable logging
	tracing::subscriber::set_global_default(
		tracing_subscriber::registry()
			.with(tracing_subscriber::fmt::layer())
			.with(EnvFilter::from_default_env()),
	)?;

	let mut streams = Slab::new();
	let mut events = Events::with_capacity(128);
	let mut usernames = BTreeSet::new();

	let mut poll = Poll::new()?;
	let addr = "[::]:3478".parse()?;
	let mut listener = TcpListener::bind(addr)?;
	poll.registry()
		.register(&mut listener, Token(ACCEPT), Interest::READABLE)?;
	let udp_key;
	{
		let mut socket = UdpSocket::bind(addr)?;
		let entry = streams.vacant_entry();
		udp_key = entry.key();
		poll.registry()
			.register(&mut socket, Token(udp_key), Interest::READABLE)?;
		entry.insert(Turn::Udp { socket });
	}

	const MAX_RECV_FRAME: usize = 16000;
	const MAX_SEND_FRAME: usize = 2048;
	let mut buffer = [0; MAX_RECV_FRAME];

	loop {
		for e in events.iter() {
			// trace!(?e, "EVENT");
			let key = e.token().0;

			if key == ACCEPT {
				loop {
					let Ok((mut stream, addr)) = listener.accept() else {
						break;
					};
					let entry = streams.vacant_entry();
					stream.set_nodelay(true)?;
					poll.registry().register(
						&mut stream,
						Token(entry.key()),
						Interest::READABLE | Interest::WRITABLE,
					)?;
					let canonical = SocketAddr::new(addr.ip().to_canonical(), addr.port());
					trace!(?canonical, "ACCEPT");
					entry.insert(Turn::Tcp {
						stream: BufWriter::with_capacity(MAX_SEND_FRAME, stream),
						canonical,
						username: None,
						ufrag: None,
					});
				}
				continue;
			}

			'msg: loop {
				let Some(turn) = streams.get_mut(e.token().0) else {
					break;
				};
				match turn.handle(e, &mut buffer) {
					Ok(Some((allocated, canonical, mut msg))) => {
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
								| Method::Allocate | Method::Refresh
								| Method::CreatePermission
								| Method::Send | Method::ChannelBind
						);

						// Compute a long-term key for authentication
						let turn_key = if let (Some(username), Some(realm), Some(_)) =
							(username, realm, &integrity)
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
							(Class::Request, Method::Allocate)
								if requested_transport != Some(17) =>
							{
								msg.set_length(0);
								msg.set_class(Class::Error);
								msg.append::<ERROR_CODE, _>(&(442, "")).unwrap();
								msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice())
									.unwrap();
							}

							// Allocate
							(Class::Request, Method::Allocate) => {
								// Register the TURN username (if TCP)
								let turn_username = username.unwrap();
								if let Turn::Tcp { username, .. } = turn {
									if username.is_none() {
										let temp: Rc<str> = Rc::from(turn_username);
										*username = Some(temp.clone());
										usernames.insert((temp, key));
									}
								}

								msg.set_length(0);
								msg.set_class(Class::Success);
								msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical).unwrap();
								msg.append::<XOR_RELAYED_ADDRESS, SocketAddr>(&allocated)
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
								// Our sockets are dual stack so we want ip6-mapped:
								let peer = SocketAddr::new(
									match peer.ip() {
										IpAddr::V4(v4) => v4.to_ipv6_mapped().into(),
										v => v,
									},
									peer.port(),
								);

								// Shift the data attribute to where we want it
								// [ STUN Header | XOR Peer Attr | Data... ]
								let mut len = data.len();
								let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
								if 48 + data.len() > msg.buffer.len() {
									continue;
								}
								msg.buffer.copy_within(i..i + 4 + len, 44);
								let data = &mut msg.buffer[48..][..len];

								let mut intercepted = false;
								'intercept: {
									if !matches!(data.first(), Some(0..3)) {
										break 'intercept;
									}
									let mut inner = Stun {
										buffer: &mut msg.buffer[48..],
									};
									if inner.len() != len {
										break 'intercept;
									}
									if inner.class() != Class::Request
										|| inner.method() != Method::Binding
									{
										break 'intercept;
									}

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

									// Make sure all expected attributes are present and no unexpected attributes exist
									let (
										None,
										Some(username),
										Some(integrity),
										Some(_),
										Some(_),
										Some(()),
									) = (
										unknowns,
										username,
										integrity,
										ice_controlled.xor(ice_controlling),
										priority,
										fingerprint,
									)
									else {
										break 'intercept;
									};

									// Split the username into dst_ufrag and src_ufrag
									let Some((dst_ufrag, src_ufrag)) = username.split_once(':')
									else {
										break 'intercept;
									};

									// Dissolve is like a threesome of ICE Agents: two full and one lite.  Once the connection is open and the full agents start renegotiating with new ICE credentials, I want the ice lite dissolve to stop responding.
									match turn {
										Turn::Tcp {
											ufrag: Some(expected),
											..
										} if expected != src_ufrag => continue 'msg,
										Turn::Tcp { ufrag, .. } if ufrag.is_none() => {
											*ufrag = Some(src_ufrag.into());
										}
										_ => {}
									}

									if dst_ufrag != "dissolve" {
										// ICE tests against SWITCHBOARD must be "dissolve"
										if peer == SWITCHBOARD {
											continue 'msg;
										};
										break 'intercept;
									}

									// Drop 50% of ICE tests to make dissolve paths suck more (and encourage Chrome to switch to host / non-intercepted paths
									if random() { continue 'msg; }

									// Wrong credentials
									if !integrity.verify(ICE_KEY) {
										inner.set_length(0);
										inner.set_class(Class::Error);
										inner.append::<ERROR_CODE, _>(&(441, "")).unwrap();
										inner.append::<FINGERPRINT, _>(&()).unwrap();
									}
									// ICE Controlled - error switch role
									else if ice_controlled.is_some() {
										/*
										 * HACK: Firefox doesn't support 487
										 * ISSUE: https://bugzilla.mozilla.org/show_bug.cgi?id=1940001
										 */
										if turn_fingerprint.is_some() {
											let username = format!("{src_ufrag}:{dst_ufrag}");
											inner.set_length(0);
											inner
												.append::<USERNAME, &str>(&username.as_str())
												.unwrap();
											inner.append::<ICE_CONTROLLED, u64>(&u64::MIN).unwrap();
											// inner.append::<PRIORITY, u32>(&0xdeadbeef).unwrap();
											inner.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).unwrap();
											inner.append::<FINGERPRINT, _>(&()).unwrap();
										} else {
											inner.set_length(0);
											inner.set_class(Class::Error);
											inner.append::<ERROR_CODE, _>(&(487, "")).unwrap();
											inner.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).unwrap();
											inner.append::<FINGERPRINT, _>(&()).unwrap();
										}
									}
									// Success
									else {
										inner.set_length(0);
										inner.set_class(Class::Success);
										inner
											.append::<XOR_MAPPED_ADDRESS, SocketAddr>(&allocated)
											.unwrap();
										inner.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).unwrap();
										inner.append::<FINGERPRINT, _>(&()).unwrap();
									}

									len = inner.len();
									intercepted = true;
								}

								// Reuse the message:
								msg.set_length(0);
								msg.set_method(Method::Data);

								// Place peer address
								msg.append::<XOR_PEER_ADDRESS, SocketAddr>(
									if peer == SWITCHBOARD || intercepted {
										&peer
									} else {
										&allocated
									},
								)
								.unwrap();

								// Zero out the padding bytes:
								let padding = (4 - len % 4) % 4;
								msg.buffer[48 + len..][..padding].fill(0);

								// Write the length of the Data attribute and update the length of the STUN packet
								msg.buffer[46..48].copy_from_slice(&u16::to_be_bytes(len as u16));
								msg.set_length(28 + (len + padding) as u16);

								// Relay the Data Indication
								if !intercepted {
									let frame = &msg.buffer[..msg.len()];
									if peer == SWITCHBOARD {
										let Turn::Tcp {
											username: Some(username),
											..
										} = turn
										else {
											continue;
										};
										let Some((a, b)) = username.split_once(':') else {
											continue;
										};
										let swapped: Rc<str> =
											Rc::from(format!("{b}:{a}").as_str());
										for (_, key) in usernames.range(
											(swapped.clone(), usize::MIN)..(swapped, usize::MAX),
										) {
											if let Some(turn) = streams.get_mut(*key) {
												let _ = turn.maybe_send(peer, frame);
											}
										}
									} else {
										if let Some(turn) =
											streams.get_mut(get_key(peer.ip()).unwrap_or(udp_key))
										{
											let _ = turn.maybe_send(peer, frame);
										}
									}

									// Data already sent, don't respond.
									continue;
								}
							}

							_ => continue,
						}

						let _ = turn.maybe_send(allocated, &msg.buffer[..msg.len()]);
					}
					Err(e) if e.kind() == ErrorKind::WouldBlock => break,
					Err(e) => {
						let Turn::Tcp {
							mut stream,
							canonical,
							username,
							..
						} = streams.remove(key)
						else {
							panic!("Turn::Udp mustn't return errors")
						};
						trace!(?e, ?canonical, "CLOSE");
						poll.registry().deregister(stream.get_mut())?;
						if let Some(username) = username {
							usernames.remove(&(username, key));
						}

						break;
					}
					_ => {}
				}
			}
		}

		poll.poll(&mut events, None)?;
	}
}
