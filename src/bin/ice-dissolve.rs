use eyre::Result;
use clap::Parser;
use masquerade::common::udp_checksum_fill;
use tappers::{Interface, Tun};
use tracing_subscriber::EnvFilter;
use masquerade::wire::{FromBytes, Ip6Header, UdpHeader, ip_proto};
use masquerade::stun::{
	Class, Method, Stun,
	attr::{integrity::Integrity, parse::AttrIter as _, *},
};
use std::net::SocketAddr;

type Never = core::convert::Infallible;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short)]
	if_name: Option<String>,
}

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;
	
	// Setup the TUN interface
	let mut network = if let Some(if_name) = args.if_name {
		Tun::new_named(Interface::new(if_name)?)?
	} else {
		Tun::new()?
	};

	network.set_up()?;
	
	let mut buffer = [0; 65536];

	loop {
		let Ok(mut length) = network.recv(&mut buffer) else { continue };

		// Intercept ICE connection tests with `dissolve` as the dst-ufrag
		'intercept: {
			// IPv6
			let Ok((ip, rest)) = Ip6Header::mut_from_prefix(buffer.as_mut_slice()) else { break 'intercept };
			if ip.flags.version() != 6 { break 'intercept }
			if ip.len() != length { break 'intercept }

			// UDP
			if ip.next_header != ip_proto::UDP { break 'intercept }
			if (ip.payload_length.get() as usize) < size_of::<UdpHeader>() {
				break 'intercept
			}
			let Ok((udp, rest)) = UdpHeader::mut_from_prefix(rest) else { break 'intercept };
			if udp.length != ip.payload_length { break 'intercept }
			let data_len = udp.length.get() as usize - size_of::<UdpHeader>();

			// STUN
			if !matches!(rest.first(), Some(0..3)) {
				break 'intercept;
			}
			let mut inner = Stun {
				buffer: rest,
			};
			if inner.decode(data_len).is_err() {
				break 'intercept
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
			let Some((dst_ufrag, _src_ufrag)) = username.split_once(':') else {
				break 'intercept;
			};

			if dst_ufrag != "dissolve" {
				break 'intercept;
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
				inner.set_length(0);
				inner.set_class(Class::Error);
				inner.append::<ERROR_CODE, _>(&(487, "")).unwrap();
				inner
					.append::<MESSAGE_INTEGRITY, _>(&ice_key.as_slice())
					.unwrap();
				inner.append::<FINGERPRINT, _>(&()).unwrap();
			}
			// Success
			else {
				let sender = SocketAddr::new(ip.src.into(), udp.src_port.get());

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

			// Swap dst and src in udp / ip
			let t = udp.dst_port;
			udp.dst_port = udp.src_port;
			udp.src_port = t;
			let t = ip.dst;
			ip.dst = ip.src;
			ip.src = t;

			// Unwrap: Our responses are all fixed size and small enough
			let udp_length = (size_of::<UdpHeader>() as u16 + 20 /* size_of::<StunHeader>() */).checked_add(inner.length()).unwrap();
			udp.length.set(udp_length);
			ip.payload_length = udp.length;
			let data = &inner.buffer[..inner.len()];
			udp_checksum_fill(&ip, udp, &data);

			// Emit the ICE response packet:
			let new_length = ip.len();
			length = new_length;
		}

		// return the packet to the network
		let _ = network.send(&buffer[..length]);
	}
}