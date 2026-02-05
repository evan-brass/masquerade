use std::borrow::BorrowMut;
use std::{
	net::SocketAddr,
	net::SocketAddrV6,
};

use tappers::Tun;
use crate::stun::{
	Class, Method, Stun, MAGIC_COOKIE,
	attr::{integrity::Integrity, parse::AttrIter as _, *},
};
use crate::wire::{FromBytes, Icmp6Header, IntoBytes, Ip6Header, StunAttrHeader, UdpHeader, ip_checksum, ip_proto};
use rand::{RngCore, rng};

pub fn udp_checksum_fill(ip: &Ip6Header, udp: &mut UdpHeader, data: &[u8]) {
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
}

pub fn handle_turn<'i>(canonical: SocketAddr, relayed: SocketAddrV6, mut msg: Stun<&'i mut [u8]>, network: &Tun) -> Option<Stun<&'i mut [u8]>> {
	// Forbid all zeroes txid.  Current suspicion is amplification DDOS.
	if msg.txid() == &[0; 12] { return None }

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
		ctx.finalize().0
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
			msg.append::<XOR_RELAYED_ADDRESS, SocketAddr>(&relayed.into())
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
			let (Some(SocketAddr::V6(peer)), Some(data)) = (xor_peer, data) else {
				return None;
			};

			// Shift the data attribute to where we want it
			// [ STUN Header | XOR Peer Attr | Data... ]
			let len = data.len();
			let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
			if 48 + data.len() > msg.buffer.len() {
				return None;
			}
			msg.buffer.borrow_mut().copy_within(i..i + 4 + len, 44);

			let length = len as u16 + 8;

			// IP6 + UDP = 40 + 8 = 48 = STUN Data Indication! Perfect.  No copy/shift needed.
			let (ip, rest) = Ip6Header::mut_from_prefix(msg.buffer.borrow_mut()).unwrap();
			let (udp, rest) = UdpHeader::mut_from_prefix(rest).unwrap();
			let data = &rest[..len];
			ip.flags.set_version(6);
			ip.flags.set_traffic_class(0);
			ip.flags.set_flow_label(0);
			ip.payload_length.set(length);
			ip.next_header = ip_proto::UDP;
			ip.hop_limit = 64;
			ip.src = relayed.ip().octets();
			ip.dst = peer.ip().octets();
			udp.src_port.set(relayed.port());
			udp.dst_port.set(peer.port());
			udp.length.set(length);
			udp_checksum_fill(ip, udp, data);

			// Emit the UDP packet to the network:
			let length = ip.len();
			let _ = network.send(msg.buffer.get(..length).unwrap());
			return None;
		}
		_ => return None,
	}

	Some(msg)
}

pub fn handle_net(len: usize, buffer: &mut [u8]) -> Option<(SocketAddrV6, Stun<&mut [u8]>)> {
	let (ip, rest) = Ip6Header::ref_from_prefix(buffer).unwrap();

	if ip.flags.version() != 6 { return None }
	if ip.len() != len { return None }

	// Relay UDP data
	if ip.next_header == ip_proto::UDP {
		if ip.payload_length.get() < size_of::<UdpHeader>() as u16 { return None }
		let (udp, _) = UdpHeader::ref_from_prefix(rest).unwrap();
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

		Some((receiver, msg))
	}

	// Relay ICMP messages
	// I shouldn't be writing this.  Nobody uses this information, but I can't focus on anything atm.
	else if ip.next_header == ip_proto::ICMP6 {
		if ip.payload_length.get() < (size_of::<Icmp6Header>() + size_of::<Ip6Header>() + size_of::<UdpHeader>()) as u16 { return None }
		let (icmp, rest) = Icmp6Header::read_from_prefix(rest).unwrap();
		if !matches!(icmp.typ, 1 | 2 | 3) { return None }
		let (inner, rest) = Ip6Header::ref_from_prefix(rest).unwrap();
		if inner.next_header != ip_proto::UDP { return None }
		if inner.payload_length < size_of::<UdpHeader>() as u16 { return None }
		let (udp, _) = UdpHeader::ref_from_prefix(rest).unwrap();
		if udp.length != inner.payload_length { return None }

		if ip.dst != inner.src { return None }
		let inner_sender = SocketAddrV6::new(inner.src.into(), udp.src_port.get(), 0, 0);
		let inner_receiver = SocketAddrV6::new(inner.dst.into(), udp.dst_port.get(), 0, 0);

		let mut msg = Stun { buffer };
		msg.set_class(Class::Indication);
		msg.set_method(Method::Data);
		msg.set_length(0);
		msg.set_cookie(MAGIC_COOKIE);
		rng().fill_bytes(msg.set_txid());
		msg.append::<XOR_PEER_ADDRESS, SocketAddr>(&inner_receiver.into()).unwrap();
		msg.append::<ICMP, _>(&(icmp.typ, icmp.code, icmp.arg)).unwrap();

		Some((inner_sender, msg))
	}

	else {
		None
	}
}