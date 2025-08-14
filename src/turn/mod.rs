use std::net::{IpAddr, SocketAddrV6, SocketAddr};

use rand::{RngCore, random, rng};
use crate::stun::{
	Class, MAGIC_COOKIE, Method, Stun,
	attr::{integrity::Integrity, parse::AttrIter as _, *},
};
use crate::wire::{ip_proto, FromBytes, Ip6Header, StunAttrHeader, UdpHeader};

pub struct Server {}

#[derive(Debug, Clone, Copy)]
pub enum Action {
	SendTo { length: usize, receiver: SocketAddrV6 },
	Forward { length: usize },
}

impl Server {
	pub fn handle_stun(&mut self, mut msg: Stun<&mut [u8]>, sender: SocketAddrV6) -> Option<Action> {
		// A few proto checks to filter some false STUN traffic I saw
		if msg.cookie() != MAGIC_COOKIE {
			return None;
		}
		if msg.length() % 4 != 0 {
			return None;
		}

		let canonical = SocketAddr::new(sender.ip().to_canonical(), sender.port());

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
			(Class::Error | Class::Success, _) => return None,

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
			_ if unknown_attrs.is_some() => return None,

			// Unauthenticated Request
			(Class::Request, _) if username.is_none() || realm.is_none() => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(401, "")).unwrap();
				msg.append::<REALM, &str>(&"none").unwrap();
				msg.append::<NONCE, &str>(&"none").unwrap();
			}

			// Forbidden
			(Class::Request, _) if integrity.is_none() => return None,
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
				msg.append::<XOR_RELAYED_ADDRESS, SocketAddr>(&sender.into())
					.unwrap();
				msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000))
					.unwrap();
				msg.append::<MESSAGE_INTEGRITY, _>(&turn_key.as_slice())
					.unwrap();
			}

			// Refresh
			(Class::Request, Method::Refresh) if lifetime == Some(0) => return None,
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
					return None;
				};

				// Shift the data attribute to where we want it
				// [ STUN Header | XOR Peer Attr | Data... ]
				let mut len = data.len();
				let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
				if 48 + data.len() > msg.buffer.len() {
					return None;
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
					if inner.class() != Class::Request || inner.method() != Method::Binding {
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
					let (None, Some(username), Some(integrity), Some(_), Some(_), Some(())) = (
						unknowns,
						username,
						integrity,
						ice_controlled.xor(ice_controlling),
						priority,
						fingerprint,
					) else {
						break 'intercept;
					};

					// Split the username into dst_ufrag and src_ufrag
					let Some((dst_ufrag, src_ufrag)) = username.split_once(':') else {
						break 'intercept;
					};

					if dst_ufrag != "dissolve" {
						break 'intercept;
					}

					// Drop 50% of ICE tests to make dissolve paths suck more (and encourage Chrome to switch to host / non-intercepted paths
					if random() {
						return None;
					}

					let ice_key = b"the/ice/password/constant";
					// Wrong credentials
					if !integrity.verify(ice_key) {
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
							inner
								.append::<MESSAGE_INTEGRITY, _>(&ice_key.as_slice())
								.unwrap();
							inner.append::<FINGERPRINT, _>(&()).unwrap();
						} else {
							inner.set_length(0);
							inner.set_class(Class::Error);
							inner.append::<ERROR_CODE, _>(&(487, "")).unwrap();
							inner
								.append::<MESSAGE_INTEGRITY, _>(&ice_key.as_slice())
								.unwrap();
							inner.append::<FINGERPRINT, _>(&()).unwrap();
						}
					}
					// Success
					else {
						inner.set_length(0);
						inner.set_class(Class::Success);
						inner
							.append::<XOR_MAPPED_ADDRESS, SocketAddr>(&sender.into())
							.unwrap();
						inner
							.append::<MESSAGE_INTEGRITY, _>(&ice_key.as_slice())
							.unwrap();
						inner.append::<FINGERPRINT, _>(&()).unwrap();
					}

					len = inner.len();
					intercepted = true;

					// Reuse the message:
					msg.set_length(0);
					msg.set_method(Method::Data);

					// Place peer address
					msg.append::<XOR_PEER_ADDRESS, SocketAddr>(&peer).unwrap();

					// Zero out the padding bytes:
					let padding = (4 - len % 4) % 4;
					msg.buffer[48 + len..][..padding].fill(0);

					// Write the length of the Data attribute and update the length of the STUN packet
					msg.buffer[46..48].copy_from_slice(&u16::to_be_bytes(len as u16));
					msg.set_length(28 + (len + padding) as u16);
				}

				// If the Send indication wasn't intercepted, then we'll emit it UDP datagram instead
				if !intercepted {
					let IpAddr::V6(dst_addr) = peer.ip() else {
						return None;
					};
					let src_addr = sender.ip();
					let length = len as u16 + 8;

					// IP6 + UDP = 40 + 8 = 48 = STUN Data Indication! Perfect.  No copy/shift needed.
					let (ip, rest) = Ip6Header::mut_from_prefix(&mut msg.buffer).unwrap();
					let (udp, _) = UdpHeader::mut_from_prefix(rest).unwrap();
					ip.flags.set(6 << 28);
					ip.payload_length.set(length);
					ip.next_header = ip_proto::UDP;
					ip.hop_limit = 5;
					ip.src = src_addr.octets();
					ip.dst = dst_addr.octets();
					udp.src_port.set(sender.port());
					udp.dst_port.set(peer.port());
					udp.length.set(length);
					udp.checksum.set(0);

					return Some(Action::Forward { length: ip.len() });
				}
			}
			_ => return None,
		}

		Some(Action::SendTo {
			length: msg.len(),
			receiver: sender,
		})
	}

	pub fn handle_net(&mut self, buffer: &mut [u8], length: usize) -> Option<Action> {
		let (ip, rest) = Ip6Header::mut_from_prefix(buffer).unwrap();
		if ip.flags.get() >> 28 != 6 { return None }
		if ip.len() != length { return None }
		match ip.next_header {
			ip_proto::UDP if ip.payload_length.get() > 8 => {
				let (udp, _) = UdpHeader::mut_from_prefix(rest).unwrap();
				if udp.length != ip.payload_length { return None }
				let padding = (4 - udp.length.get() % 4) % 4;

				// STUN (xor_peer + data header - udp header length + padding + udp packet length)
				let Some(stun_length) = (24 + 4 - 8 + padding).checked_add(udp.length.get()) else {
					return None
				};
				let data_len = udp.length.get() - 8;
				let sender = SocketAddrV6::new(ip.src.into(), udp.src_port.get(), 0, 0);
				let receiver = SocketAddrV6::new(ip.dst.into(), udp.dst_port.get(), 0, 0);

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

				Some(Action::SendTo {
					length: msg.len(),
					receiver,
				})
			}
			// TODO: I don't know any WebRTC's that utilize ICMP indications, but I could generate them here for path mtu discovering perhaps
			_ => None
		}
	}
}
