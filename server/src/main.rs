use std::{io::{self, BufWriter, ErrorKind, Read, Write}, net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr}};

use stun::{Stun, Class, Method, attr::*, attr::parse::AttrIter as _, attr::integrity::Integrity};
use mio::{net::{TcpListener, TcpStream, UdpSocket}, Events, event::Event, Interest, Poll, Token};
use slab::Slab;
use tracing::trace;
use tracing_subscriber::{EnvFilter, prelude::*};

type Never = core::convert::Infallible;
const ACCEPT: usize = usize::MAX;
const ICE_KEY: &[u8] = b"the/ice/password/constant";

// We assign a link-local ip for each tcp stream u64 <-> Link local ip
fn make_ip(token: usize) -> IpAddr {
	let mut octets = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	octets[8..].copy_from_slice(&(token as u64).to_be_bytes());
	IpAddr::V6(Ipv6Addr::from(octets))
}
fn get_key(ip: IpAddr) -> Option<usize> {
	match ip {
		IpAddr::V6(ip6) if ip6.is_unicast_link_local() => Some(u64::from_be_bytes(ip6.octets()[8..].try_into().unwrap()) as usize),
		_ => None
	}
}

#[derive(Debug)]
enum Turn {
	Udp {
		socket: UdpSocket
	},
	Tcp {
		stream: BufWriter<TcpStream>,
		canonical: SocketAddr,
	}
}
impl Turn {
	pub fn handle<'i>(&mut self, e: &Event, buffer: &'i mut [u8]) -> io::Result<Option<(SocketAddr, SocketAddr, Stun<&'i mut [u8]>)>> {
		match self {
			Self::Udp { socket } => {
				// Udp, Should only return would-block errors anyway.
				let (len, allocated) = socket.recv_from(buffer).map_err(|e| io::Error::new(ErrorKind::WouldBlock, e))?;
				let canonical = SocketAddr::new(allocated.ip().to_canonical(), allocated.port());
				let msg = Stun { buffer };
				if len < msg.len() {
					return Ok(None);
				}
				Ok(Some((allocated, canonical, msg)))
			}
			Self::Tcp { stream, canonical } => {
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
						return Err(io::Error::other("STUN message too large to fit in buffer"))
					}
					if len < msg.len() {
						return would_block;
					}
					let exp_len = msg.len();
					stream.get_ref().read_exact(&mut msg.buffer[..exp_len])?;
					return Ok(Some((allocated, *canonical, msg)))
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
		.with(EnvFilter::from_default_env())
	)?;

	let mut streams = Slab::new();
	let mut events = Events::with_capacity(128);

	let mut poll = Poll::new()?;
	let addr = "[::]:3478".parse()?;
	let mut listener = TcpListener::bind(addr)?;
	poll.registry().register(&mut listener, Token(ACCEPT), Interest::READABLE)?;
	let udp_key; {
		let mut socket = UdpSocket::bind(addr)?;
		let entry = streams.vacant_entry();
		udp_key = entry.key();
		poll.registry().register(&mut socket, Token(udp_key), Interest::READABLE)?;
		entry.insert(Turn::Udp { socket });
	}

	const BUFFER_LEN: usize = 2048;
	let mut buffer = [0; BUFFER_LEN];

	loop {
		for e in events.iter() {
			// trace!(?e, "EVENT");
			let key = e.token().0;

			if key == ACCEPT {
				loop {
					let Ok((mut stream, addr)) = listener.accept() else { break };
					let entry = streams.vacant_entry();
					stream.set_nodelay(true)?;
					poll.registry().register(&mut stream, Token(entry.key()), Interest::READABLE | Interest::WRITABLE)?;
					let canonical = SocketAddr::new(addr.ip().to_canonical(), addr.port());
					trace!(?canonical, "ACCEPT");
					entry.insert(Turn::Tcp { stream: BufWriter::with_capacity(BUFFER_LEN, stream), canonical });
				}
				continue;
			}

			loop {
				let Some(turn) = streams.get_mut(e.token().0) else { break };
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

						// trace!(class = msg.class(), method = msg.method(), length = msg.length(), "STUN");

						let method_unknown = !matches!(msg.method(), Method::Binding | Method::Allocate | Method::Refresh | Method::CreatePermission | Method::Send | Method::ChannelBind);

						// Compute a long-term key for authentication
						let turn_key = if let (Some(username), Some(realm), Some(_)) = (username, realm, &integrity) {
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
								msg.append::<XOR_MAPPED_ADDRESS, SocketAddr>(&canonical).unwrap();
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
								msg.append::<UNKNOWN_ATTRIBUTES, _>(&unknown_attrs.unwrap()).unwrap();
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
								msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice()).unwrap();
							}

							// Allocate
							(Class::Request, Method::Allocate) => {
								msg.set_length(0);
								msg.set_class(Class::Success);
								msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical).unwrap();
								msg.append::<XOR_RELAYED_ADDRESS, SocketAddr>(&allocated).unwrap();
								msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000)).unwrap();
								msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice()).unwrap();
							}

							// Refresh
							(Class::Request, Method::Refresh) if lifetime == Some(0) => continue,
							(Class::Request, Method::Refresh) => {
								msg.set_length(0);
								msg.set_class(Class::Success);
								msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000)).unwrap();
								msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice()).unwrap();
							}

							// Create Permission
							(Class::Request, Method::CreatePermission) => {
								msg.set_length(0);
								msg.set_class(Class::Success);
								msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice()).unwrap();
							}

							// Channel Bind
							(Class::Request, Method::ChannelBind) => {
								msg.set_length(0);
								msg.set_class(Class::Error);
								msg.append::<ERROR_CODE, _>(&(438, "")).unwrap();
								msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice()).unwrap();
							}

							// Send
							(Class::Indication, Method::Send) => {
								let (Some(peer), Some(data)) = (xor_peer, data) else { continue };
								// Our sockets are dual stack so we want ip6-mapped:
								let peer = SocketAddr::new(match peer.ip() {
									IpAddr::V4(v4) => v4.to_ipv6_mapped().into(),
									v => v
								}, peer.port());

								// Shift the data attribute to where we want it
								// [ STUN Header | XOR Peer Attr | Data... ]
								let mut len = data.len();
								let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
								if 48 + data.len() > msg.buffer.len() { continue }
								msg.buffer.copy_within(i..i + 4 + len, 44);
								let data = &mut msg.buffer[48..][..len];

								let mut intercepted = false;
								'intercept: {
									if !matches!(data.first(), Some(0..3)) { break 'intercept }
									let mut inner = Stun { buffer: &mut msg.buffer[48..] };
									if inner.len() != len { break 'intercept }
									if inner.class() != Class::Request || inner.method() != Method::Binding { break 'intercept }

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

									if unknowns.is_some() { break 'intercept }

									// Make sure all expected attributes are present and no unexpected attributes exist
									let (None, Some(username), Some(integrity), Some(_), Some(_), Some(())) = (
										unknowns,
										username,
										integrity,
										ice_controlled.xor(ice_controlling),
										priority,
										fingerprint,
									) else { break 'intercept };

									// Split the username into dst_ufrag and src_ufrag
									let Some((dst_ufrag, src_ufrag)) = username.split_once(':') else { break 'intercept };

									if dst_ufrag != "dissolve" { break 'intercept }

									// Wrong credentials
									if !integrity.verify(&ICE_KEY) {
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
											inner.append::<USERNAME, &str>(&username.as_str()).unwrap();
											inner.append::<ICE_CONTROLLED, u64>(&u64::MIN).unwrap();
											// inner.append::<PRIORITY, u32>(&0xdeadbeef).unwrap();
											inner.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).unwrap();
											inner.append::<FINGERPRINT, _>(&()).unwrap();
										}
										else {
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
								msg.append::<XOR_PEER_ADDRESS, SocketAddr>(if intercepted {
									&peer
								} else {
									&allocated
								}).unwrap();

								// Zero out the padding bytes:
								let padding = (4 - len % 4) % 4;
								msg.buffer[48 + len..][..padding].fill(0);

								// Write the length of the Data attribute and update the length of the STUN packet
								msg.buffer[46..48].copy_from_slice(&u16::to_be_bytes(len as u16));
								msg.set_length(28 + (len + padding) as u16);

								// Relay the Data Indication
								if !intercepted {
									let frame = &msg.buffer[..msg.len()];
									let key = get_key(peer.ip()).unwrap_or(udp_key);
									if let Some(turn) = streams.get_mut(key) {
										// TODO: Handle errors?  Or wait for them to propagate to read?
										let _ = turn.maybe_send(peer, frame);
									}

									// Data already sent, don't respond.
									continue;
								}
							}

							_ => continue,
						}

						// TODO: Handle errors?  Or wait for them to propagate to read?
						let _ = turn.maybe_send(allocated, &msg.buffer[..msg.len()]);
					}
					Err(e) if e.kind() == ErrorKind::WouldBlock => break,
					Err(e) => {
						let Turn::Tcp { mut stream, canonical } = streams.remove(key) else {
							panic!("Turn::Udp mustn't return errors")
						};
						trace!(?e, ?canonical, "CLOSE");
						poll.registry().deregister(stream.get_mut())?;
						break;
					}
					_ => {}
				}
			}
		}

		poll.poll(&mut events, None)?;
	}
}
