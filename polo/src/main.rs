use std::io::{Read, Write};
use std::{
	io::{self, BufWriter, ErrorKind},
	net::{IpAddr, Shutdown, SocketAddr},
	os::fd::AsRawFd,
};

use clap::Parser;
use eyre::Result;
use mio::{
	Events, Interest, Poll, Token,
	event::Event,
	net::{TcpListener, UdpSocket},
	unix::SourceFd,
};
use slab::Slab;
use stun::Stun;
use tappers::{Interface, Tun};

mod server;
use crate::server::{Action, Server};

type Never = core::convert::Infallible;

const UDP: Token = Token(usize::MAX);
const TCP: Token = Token(usize::MAX - 1);
const TUN: Token = Token(usize::MAX - 2);

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "[::]:3478")]
	udp: String,

	#[arg(long, short, default_value = "[::]:3478")]
	tcp: String,

	#[arg(long, short, default_value_t = 0x01)]
	site: u16,

	#[arg(long, short)]
	if_name: Option<String>,
}

struct Conn {
	canonical: SocketAddr,
	stream: BufWriter<mio::net::TcpStream>,
}
impl Conn {
	pub fn handle<'i>(
		&mut self,
		e: &Event,
		buffer: &'i mut [u8],
	) -> Result<Stun<&'i mut [u8]>, io::Error> {
		let would_block = Err(io::Error::new(ErrorKind::WouldBlock, ""));
		if e.is_writable() {
			self.stream.flush()?;
		}
		if e.is_read_closed() {
			self.stream.get_ref().shutdown(Shutdown::Both)?;
			return Err(io::Error::other("Read Closed"));
		}
		if e.is_readable() {
			let len = self.stream.get_ref().peek(buffer)?;
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
			self.stream
				.get_ref()
				.read_exact(&mut msg.buffer[..exp_len])?;
			return Ok(msg);
		}
		would_block
	}
}

// We assign a link-local ip for each tcp stream u64 <-> Link local ip
fn to_ip(site: u16, index: u64) -> IpAddr {
	let mut octets = [0xfd, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	octets[2..4].copy_from_slice(&site.to_be_bytes());
	octets[8..].copy_from_slice(&index.to_be_bytes());
	IpAddr::from(octets)
}
fn from_ip(ip: IpAddr) -> Option<(u16, u64)> {
	let IpAddr::V6(ip6) = ip else { return None };
	let octets = ip6.octets();
	if octets[0..2] != [0xfd, 0x01] {
		return None;
	}
	let site = u16::from_be_bytes(octets[2..4].try_into().unwrap());
	if octets[4..8] != [0, 0, 0, 0] {
		return None;
	}
	let index = u64::from_be_bytes(octets[8..].try_into().unwrap());
	Some((site, index))
}

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt().init();

	// Parse command line arguments
	let args = Args::try_parse()?;

	// Listen for TURN traffic
	let mut socket = UdpSocket::bind(args.udp.parse()?)?;
	let mut listen = TcpListener::bind(args.tcp.parse()?)?;

	// Setup the TUN interface
	let mut network = if let Some(if_name) = args.if_name {
		Tun::new_named(Interface::new(if_name)?)?
	} else {
		Tun::new()?
	};
	network.set_nonblocking(true)?;

	let mut poll = Poll::new()?;
	poll.registry()
		.register(&mut socket, UDP, Interest::READABLE)?;
	poll.registry()
		.register(&mut listen, TCP, Interest::READABLE)?;
	poll.registry()
		.register(&mut SourceFd(&network.as_raw_fd()), TUN, Interest::READABLE)?;

	let mut buffer = [0; 65536];
	let mut events = Events::with_capacity(128);
	let mut streams = Slab::new();
	let mut server = Server {};

	loop {
		for e in events.into_iter() {
			loop {
				let action = match e.token() {
					TCP => {
						let Ok((mut stream, canonical)) = listen.accept() else {
							break;
						};
						stream.set_nodelay(true)?;
						let entry = streams.vacant_entry();
						poll.registry().register(
							&mut stream,
							Token(entry.key()),
							Interest::READABLE | Interest::WRITABLE,
						)?;
						entry.insert(Conn {
							canonical,
							stream: BufWriter::with_capacity(2048, stream),
						});
						continue;
					}
					UDP => {
						let Ok((len, sender)) = socket.recv_from(&mut buffer) else {
							break;
						};
						let msg = Stun {
							buffer: buffer.as_mut_slice(),
						};
						if len < msg.len() {
							continue;
						};
						server.handle_stun(msg, sender)
					}
					TUN => {
						let Ok(len) = network.recv(&mut buffer) else {
							break;
						};
						server.handle_net(buffer.as_mut_slice(), len)
					}
					Token(index) => {
						let Some(stream) = streams.get_mut(index) else {
							break;
						};
						match stream.handle(e, &mut buffer) {
							Ok(msg) => {
								let sender = SocketAddr::new(
									to_ip(args.site, index as u64),
									stream.canonical.port(),
								);
								server.handle_stun(msg, sender)
							}
							Err(e) if e.kind() == ErrorKind::WouldBlock => break,
							Err(_) => {
								let Conn {
									stream: mut inner, ..
								} = streams.remove(index);
								poll.registry().deregister(inner.get_mut())?;
								break;
							}
						}
					}
				};
				match action {
					Action::Drop => {}
					Action::SendTo { length, receiver } => {
						if let Some((site, index)) = from_ip(receiver.ip()) {
							if args.site == site {
								if let Some(Conn { stream, .. }) = streams.get_mut(index as usize) {
									let spare_capacity = stream.capacity() - stream.buffer().len();
									if length <= spare_capacity {
										stream.write_all(&buffer[..length]).unwrap();
										let _ = stream.flush();
									}
								}
							}
						} else {
							let _ = socket.send_to(&buffer[..length], receiver);
						}
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
