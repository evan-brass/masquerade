use std::{os::fd::AsRawFd, usize};

use eyre::Result;
use mio::{net::UdpSocket, unix::SourceFd, Events, Interest, Poll, Token};
use tappers::{Interface, Tun};
use turn::{Action, handle};
use stun::Stun;

type Never = core::convert::Infallible;

const UDP: Token = Token(usize::MAX);
const TUN: Token = Token(usize::MAX - 1);

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt().init();

	// Listen for TURN traffic
	let addr = "[::]:3478".parse()?;
	let mut socket = UdpSocket::bind(addr)?;

	// Setup the TUN interface
	// let iface = Interface::new("tun0")?;
	// let mut network = Tun::new_named(iface)?;
	let mut network = Tun::new()?;
	network.set_nonblocking(true)?;

	let mut poll = Poll::new()?;
	poll.registry().register(&mut socket, UDP, Interest::READABLE)?;
	poll.registry().register(&mut SourceFd(&network.as_raw_fd()), TUN, Interest::READABLE)?;

	let mut buffer = [0; 65536];
	let mut events = Events::with_capacity(128);

	loop {
		for e in events.into_iter() {
			match e.token() {
				UDP => loop {
					let Ok((len, sender)) = socket.recv_from(&mut buffer) else { break };
					let msg = Stun { buffer: buffer.as_mut_slice() };
					if len < msg.len() { continue };
					// TODO: Modify ipv4 mapped senders into a private ipv6 address space
					match handle(msg, sender) {
						Action::Drop => {},
						Action::Respond { length } => {
							let _ = socket.send_to(&buffer[..length], sender);
						}
						Action::Forward { length } => {
							let _ = network.send(&buffer[..length]);
						}
					}
				}
				TUN => loop {
					let Ok(len) = network.recv(&mut buffer) else { break };
					println!("TUN {:?}", &buffer[..len]);
				}
				_ => unreachable!()
			}
		}
		poll.poll(&mut events, None)?;
	}
}
