use std::os::fd::AsRawFd;

use clap::Parser;
use eyre::Result;
use mio::{net::UdpSocket, unix::SourceFd, Events, Interest, Poll, Token};
use tappers::{Interface, Tun};
use turn::{handle, handle_net, Action};
use stun::Stun;

type Never = core::convert::Infallible;

const UDP: Token = Token(usize::MAX);
const TUN: Token = Token(usize::MAX - 1);

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(default_value = "[::]:3478")]
	bind: String,

	#[arg(default_value = "tun0")]
	interface: String,
}

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt().init();

	// Parse command line arguments
	let args = Args::try_parse()?;

	// Listen for TURN traffic
	let addr = args.bind.parse()?;
	let mut socket = UdpSocket::bind(addr)?;

	// Setup the TUN interface
	let iface = Interface::new(args.interface)?;
	let mut network = Tun::new_named(iface)?;
	network.set_nonblocking(true)?;

	let mut poll = Poll::new()?;
	poll.registry().register(&mut socket, UDP, Interest::READABLE)?;
	poll.registry().register(&mut SourceFd(&network.as_raw_fd()), TUN, Interest::READABLE)?;

	let mut buffer = [0; 65536];
	let mut events = Events::with_capacity(128);

	loop {
		for e in events.into_iter() {
			loop {
				let action = match e.token() {
					UDP => {
						let Ok((len, sender)) = socket.recv_from(&mut buffer) else { break };
						let msg = Stun { buffer: buffer.as_mut_slice() };
						if len < msg.len() { continue };
						handle(msg, sender)
					}
					TUN => {
						let Ok(len) = network.recv(&mut buffer) else { break };
						handle_net(buffer.as_mut_slice(), len)
					}
					_ => unreachable!()
				};
				match action {
					Action::Drop => {},
					Action::SendTo { length, receiver } => {
						let _ = socket.send_to(&buffer[..length], receiver);
					}
					Action::Forward { length } => {
						let _ = network.send(&buffer[..length]);
					}
				}
			}
		}
		poll.poll(&mut events, None)?;
	}
}
