use std::str::FromStr;
use std::{net::IpAddr, net::Ipv6Addr, net::SocketAddr, net::SocketAddrV6, os::fd::AsRawFd};

use clap::Parser;
use eyre::{Result, eyre};
use ipnet::{IpBitAnd, IpBitOr, Ipv6Net};
use masquerade::common::{handle_net, handle_turn};
use masquerade::stun::Stun;
use mio::{Events, Interest, Poll, Token, net::UdpSocket, unix::SourceFd};
use tappers::{Interface, Tun};
use tracing_subscriber::EnvFilter;

type Never = core::convert::Infallible;

const UDP: Token = Token(usize::MAX);
const TUN: Token = Token(usize::MAX - 1);

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "[::]:3478")]
	address: String,

	#[arg(long, short, default_value = "")]
	mappings: String,

	#[arg(long, short)]
	if_name: Option<String>,
}

// 1-to-1 IPv6 subnet mappings.  Primarily intended for mapping ::ffff:0.0.0.0/96<->[a network that you control], and potentially for mapping 2000::/3<->A000::/3 to statelessly differentiate between TURN/UDP packets from normal UDP packets received from IPv6 peers.
struct Mapping {
	udp: Ipv6Net,
	tun: Ipv6Net,
}
impl FromStr for Mapping {
	type Err = eyre::Report;
	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		let (udp, tun) = s.split_once("<->").ok_or(eyre!("stuff"))?;
		let udp = Ipv6Net::from_str(udp)?;
		let tun = Ipv6Net::from_str(tun)?;
		if udp.prefix_len() != tun.prefix_len() {
			return Err(eyre!("subnets need to have the same size"));
		}
		Ok(Self { udp, tun })
	}
}
impl Mapping {
	fn to_net(&self, addr: &mut Ipv6Addr) -> bool {
		if self.udp.contains(&*addr) {
			*addr = self.tun.network().bitor(self.udp.hostmask().bitand(*addr));
			return true;
		}
		false
	}
	fn to_udp(&self, addr: &mut Ipv6Addr) -> bool {
		if self.tun.contains(&*addr) {
			*addr = self.udp.network().bitor(self.tun.hostmask().bitand(*addr));
			return true;
		}
		false
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
	let mut socket = UdpSocket::bind(args.address.parse()?)?;

	// Setup the TUN interface
	let mut network = if let Some(if_name) = args.if_name {
		Tun::new_named(Interface::new(if_name)?)?
	} else {
		Tun::new()?
	};
	network.set_nonblocking(true)?;

	// Parse subnet mappings
	let mut mappings = Vec::new();
	for s in args.mappings.split(',') {
		if s.is_empty() {
			continue;
		};
		mappings.push(Mapping::from_str(s)?);
	}

	let mut poll = Poll::new()?;
	poll.registry()
		.register(&mut socket, UDP, Interest::READABLE)?;
	poll.registry()
		.register(&mut SourceFd(&network.as_raw_fd()), TUN, Interest::READABLE)?;

	let mut buffer = [0; 65536];
	let mut events = Events::with_capacity(128);

	loop {
		for e in events.into_iter() {
			match e.token() {
				// UDP recv
				UDP => loop {
					let Ok((len, sender)) = socket.recv_from(&mut buffer) else {
						break;
					};
					let msg = Stun {
						buffer: buffer.as_mut_slice(),
					};
					if msg.decode(len).is_err() {
						continue;
					}

					let canonical = SocketAddr::new(sender.ip().to_canonical(), sender.port());
					let mut mapped = match sender.ip() {
						// TODO: If we encounter a v4 then we should emit v4 / canonical ip addresses to the UDP socket.
						IpAddr::V4(v4) => v4.to_ipv6_mapped(),
						IpAddr::V6(v6) => v6,
					};
					// Apply our subnet mappings to mapped
					for m in &mappings {
						if m.to_net(&mut mapped) {
							break;
						}
					}
					let relayed = SocketAddrV6::new(mapped, sender.port(), 0, 0);

					let Some(resp) = handle_turn(canonical, relayed, msg, &network) else {
						continue;
					};

					// Send the STUN response:
					let length = resp.len();
					let _ = socket.send_to(&buffer[..length], sender);
				},

				// TUN Recv
				TUN => loop {
					let Ok(len) = network.recv(&mut buffer) else {
						break;
					};

					let Some((receiver, msg)) = handle_net(len, &mut buffer) else {
						continue;
					};

					let mut mapped = *receiver.ip();
					for m in &mappings {
						if m.to_udp(&mut mapped) {
							break;
						}
					}
					// TODO: For non-dual-stack sockets, we need this to be an ipv6 mapped address and then we need to canonicalize it. (I think that's correct at least...)
					let mapped_receiver = SocketAddr::new(mapped.into(), receiver.port());

					// Send the new STUN Data indication to the receiver
					let length = msg.len();
					// TODO: For non-dual-stack sockets, we probably need the receiver in canonical form...
					let _ = socket.send_to(&msg.buffer[..length], mapped_receiver);
				},
				// We don't use any other tokens
				_ => unreachable!(),
			}
		}

		// Wait for something to happen
		poll.poll(&mut events, None)?;
	}
}
