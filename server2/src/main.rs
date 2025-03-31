use eyre::Result;
use stun::Stun;
use std::io::{ErrorKind, Read as _, Error};
use std::net::SocketAddr;
use mio::event::Source;
use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::{Events, Poll, Interest, Token};

fn would_block<T>(res: &Result<T, Error>) -> bool {
	match res {
		Err(e) if e.kind() == ErrorKind::WouldBlock => true,
		_ => false
	}
}

// These are the turn
struct Turn {
	addr: SocketAddr,
	stream: TcpStream,
	// TODO: Firefox enforces permissions, so we also might need a map from SocketAddr -> u16 (pseudo port).  I wonder if we use a sorted map again... then firefox would see the remote port changing as they receive, but... IDK
}
struct TurnServer {
	udp: UdpSocket,
	tcp: TcpListener,
	// NOTE: streams must be sorted by Turn.addr, and
	streams: Vec<Turn>,
	// TODO: Add DTLS state
}
const UDP: Token = Token(usize::MAX);
const TCP: Token = Token(usize::MAX - 1);
impl TurnServer {
	pub fn new(addr: SocketAddr) -> Result<Self> {
		let udp = UdpSocket::bind(addr)?;
		let tcp = TcpListener::bind(addr)?;
		Ok(Self { udp, tcp, streams: Vec::new() })
	}

	fn close(&mut self, i: usize, poll: &mut Poll) -> Result<()> {
		let mut turn = self.streams.remove(i);
		turn.stream.deregister(poll.registry())?;
		// Reregister every stream following this one:

		Ok(())
	}

	fn handle_msg(&mut self, sender: SocketAddr, msg: Stun<&mut [u8]>) {
		println!("{sender} {:?} {:?} {}", msg.class(), msg.method(), msg.len());
	}

	pub fn run(mut self) -> Result<std::convert::Infallible> {
		let mut buffer = [0; 2048];
		let mut poll = Poll::new()?;
		let mut events = Events::with_capacity(1);
		self.udp.register(poll.registry(), UDP, Interest::READABLE)?;
		self.tcp.register(poll.registry(), TCP, Interest::READABLE)?;
		loop {
			// TODO: New problem we can't handle more than 1 event at a time, because inserting / removing streams changes the indexes of other streams and thus the tokens of later events (in this poll that haven't been handled yet) will not match the new indexes...
			for e in events.into_iter() {
				match e.token() {
					UDP => {
						let res = self.udp.recv_from(&mut buffer);
						// Check for spurious wakes
						if would_block(&res) { continue }
						let (len, sender) = res?;
						let msg = Stun{ buffer: &mut buffer[..] };
						if msg.len() == len {
							self.handle_msg(sender, msg);
						}
					}
					TCP => {
						let res = self.tcp.accept();
						// Check for spurious wakes
						if would_block(&res) { continue }
						let (mut stream, addr) = res?;

						// We should never have two tcp streams with the same remote address.
						let i = self.streams.binary_search_by(|t| t.addr.cmp(&addr)).unwrap_err();

						// Reserve space for another stream
						if self.streams.try_reserve(1).is_err() { continue }

						stream.register(poll.registry(), Token(i), Interest::READABLE)?;
						self.streams.insert(i, Turn{addr, stream});

						// Reregister all following streams to fix their Token
						for j in (i + 1)..self.streams.len() {
							let turn = &mut self.streams[j];
							turn.stream.reregister(poll.registry(), Token(j), Interest::READABLE)?;
						}
					}
					Token(i) => {
						loop {
							let turn = &mut self.streams[i];
							let sender = turn.addr;
							let res = turn.stream.peek(&mut buffer);
							if would_block(&res) { break }

							// Handle streams being closed / erroring out
							let Ok(len) = res else {
								self.close(i, &mut poll)?;
								break
							};
							// We can't read the msg_len of this packet until we have at least 4 bytes
							if len < 4 { break }
							let msg_len = Stun { buffer: &buffer[..] }.len();

							// Close connection if message is too large for our buffer
							if msg_len > buffer.len() {
								self.close(i, &mut poll)?;
								break
							}

							// If we don't have the full message than wait
							if msg_len > len { break }

							// Consume the peeked data
							turn.stream.read_exact(&mut buffer[..msg_len])?;

							let msg = Stun { buffer: &mut buffer[..] };
							self.handle_msg(sender, msg);
						}
					}
				}
			}
			poll.poll(&mut events, None)?;
		}
	}
}

fn main() -> Result<std::convert::Infallible> {
	let addr = "[::]:3478".parse()?;
	let server = TurnServer::new(addr)?;
	server.run()
}
