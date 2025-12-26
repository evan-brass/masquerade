use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Error, ErrorKind, Read, Write};
use std::{
	net::SocketAddr,
	rc::Rc,
};

use clap::Parser;
use eyre::Result;
use masquerade::wire::{Ip6Header, UdpHeader, ip_checksum, ip_proto};
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod, SslStream};
use tappers::{Interface, Tun};
use tracing_subscriber::EnvFilter;
use zerocopy::{FromBytes, IntoBytes};

type Never = core::convert::Infallible;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "cert.pem")]
	cert: String,

	#[arg(long, short)]
	if_name: Option<String>,
}

struct Buffers {
	buffer: Vec<u8>,
	network: Rc<Tun>,
	received: VecDeque<u8>,
}
impl Write for Buffers {
	fn flush(&mut self) -> std::io::Result<()> {
		// TODO: Anything here?
		Ok(())
	}
	fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
		let packet_len = size_of::<Ip6Header>() + size_of::<UdpHeader>() + buf.len();
		self.buffer.resize(packet_len, 0);
		let (ip, rest) = Ip6Header::mut_from_prefix(self.buffer.as_mut()).unwrap();
		let (udp, rest) = UdpHeader::mut_from_prefix(rest).unwrap();
		rest.copy_from_slice(buf);

		// Fixup the packet lengths:
		let len = (size_of::<UdpHeader>() + buf.len()) as u16;
		ip.payload_length.set(len);
		udp.length = ip.payload_length;
		udp.checksum.set(0);
		let checksum = ip_checksum(&[
			&ip.src,
			&ip.dst,
			&[0, ip.next_header],
			&ip.payload_length.as_bytes(),
			&udp.as_bytes(),
			buf
		]);
		udp.checksum.set(if checksum == 0 { 0xffff } else { checksum });

		let _ = self.network.send(&self.buffer);
		Ok(buf.len())
	}
}
impl Read for Buffers {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		match self.received.read(buf) {
			Ok(0) => Err(Error::new(ErrorKind::WouldBlock, "")),
			v => v,
		}
	}
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
	let network = Rc::new(network);

	// Configure the DTLS server
	let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
	acceptor.set_private_key_file(&args.cert, SslFiletype::PEM)?;
	acceptor.set_certificate_chain_file(&args.cert)?;
	acceptor.check_private_key()?;
	let context = acceptor.build().into_context();
	
	//
	let mut buffer = [0; 65536];
	let mut streams = BTreeMap::<SocketAddr, SslStream<_>>::new();

	loop {
		let Ok(length) = network.recv(&mut buffer) else { continue };

		// TODO: Cleanup old connections using a last encrypt timeout (destination must respond to keep the connection alive: SCTP would keep this up with heartbeats)

		// Packet:
		let (ip, rest) = Ip6Header::mut_from_prefix(buffer.as_mut_slice()).unwrap();
		let (udp, rest) = UdpHeader::mut_from_prefix(rest).unwrap();
		
		// IPv6
		if ip.flags.version() != 6 { continue }
		if ip.len() != length { continue }

		// UDP
		if ip.next_header != ip_proto::UDP { continue }
		if (ip.payload_length.get() as usize) < size_of::<UdpHeader>() { continue }
		if udp.length != ip.payload_length { continue }
		let data_len = udp.length.get() as usize - size_of::<UdpHeader>();
		let data = &rest[..data_len];

		// Encrypt the UDP payload and re-emit
		if let Some(stream) = streams.get_mut(&SocketAddr::new(ip.src.into(), udp.src_port.get())) {
			// TODO: Set the prefix to unmodified ip+udp, then call ssl_write if our handshake state is complete.
			let Buffers { buffer, .. } = stream.get_mut();
			buffer.clear();
			buffer.extend(ip.as_bytes());
			buffer.extend(udp.as_bytes());

			let _res = stream.ssl_write(data);
			// TODO: Handle write errors
		}

		// Handshake or decrypt the payload
		else {
			let dst = SocketAddr::new(ip.dst.into(), udp.dst_port.get());

			let mut occupied = match streams.entry(dst) {
				Entry::Occupied(e) => e,
				Entry::Vacant(e) => {
					let mut ssl = Ssl::new(&context)?;
					ssl.set_accept_state();
					let buffers = Buffers {
						buffer: Vec::new(),
						received: VecDeque::new(),
						network: network.clone(),
					};
					let stream = SslStream::new(ssl, buffers)?;
					e.insert_entry(stream)
				}
			};
			let stream = occupied.get_mut();

			// Set the prefix to reversed src/dst ip+udp, copy the data into the recv queue
			{	let Buffers { buffer, received, .. } = stream.get_mut();
				let mut ip = ip.clone();
				let t = ip.dst;
				ip.dst = ip.src;
				ip.src = t;
				let mut udp = udp.clone();
				let t = udp.dst_port;
				udp.dst_port = udp.src_port;
				udp.src_port = t;
				udp.checksum.set(0);
				buffer.clear();
				buffer.extend(ip.as_bytes());
				buffer.extend(udp.as_bytes());

				// Extend the receive buffer with received DTLS frames
				received.extend(data);
			}
			
			// Attempt to receive decrypted application data:
			loop {
				let (ip, rest) = Ip6Header::mut_from_prefix(buffer.as_mut_slice()).unwrap();
				let (udp, rest) = UdpHeader::mut_from_prefix(rest).unwrap();
				let res = stream.read(rest);
				match res {
					Err(e) if e.kind() == ErrorKind::WouldBlock => break,
					Ok(0) | Err(_) => {
						// TODO: Cleanup
						occupied.remove();
						break;
					}
					Ok(len) => {
						udp.length.set((size_of::<UdpHeader>() + len) as u16);
						ip.payload_length = udp.length;
						udp.checksum.set(0);
						let checksum = ip_checksum(&[
							&ip.src,
							&ip.dst,
							&[0, ip.next_header],
							&ip.payload_length.as_bytes(),
							&udp.as_bytes(),
							&rest[..len]
						]);
						udp.checksum.set(if checksum == 0 { 0xffff } else { checksum });
						let length = ip.len();
						let _ = network.send(&buffer[..length]);
					}
				}
			}
		}
	}
}
