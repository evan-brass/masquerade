use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Error, ErrorKind, Read, Write};
use std::net::SocketAddrV6;
use std::time::{Duration, Instant};
use std::{
	rc::Rc,
};

use clap::Parser;
use eyre::Result;
use masquerade::common::udp_checksum_fill;
use masquerade::wire::{Ip6Header, UdpHeader, ip_proto};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sign::Signer;
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod, SslOptions, SslStream};
use tappers::{Interface, Tun};
use tracing_subscriber::EnvFilter;
use zerocopy::{FromBytes, FromZeros, IntoBytes};

type Never = core::convert::Infallible;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "cert.pem")]
	cert: String,

	#[arg(long, short)]
	if_name: Option<String>,
}

struct Bio {
	send_from: SocketAddrV6,
	send_to: SocketAddrV6,
	network: Rc<Tun>,
	received: VecDeque<u8>,
}
impl Write for Bio {
	fn flush(&mut self) -> std::io::Result<()> {
		// TODO: Anything here?
		Ok(())
	}
	fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
		let packet_len = size_of::<Ip6Header>() + size_of::<UdpHeader>() + buf.len();
		let mut buffer = Vec::with_capacity(packet_len);

		let mut ip = Ip6Header::new_zeroed();
		ip.flags.set_version(6);
		ip.flags.set_traffic_class(0);
		ip.flags.set_flow_label(0);
		ip.next_header = ip_proto::UDP;
		ip.hop_limit = 64;
		ip.payload_length.set(size_of::<UdpHeader>() as u16 + buf.len() as u16);
		ip.src = self.send_from.ip().octets();
		ip.dst = self.send_to.ip().octets();
		buffer.extend_from_slice(ip.as_bytes());

		let mut udp = UdpHeader::new_zeroed();
		udp.src_port.set(self.send_from.port());
		udp.dst_port.set(self.send_to.port());
		udp.length = ip.payload_length;
		udp_checksum_fill(&ip, &mut udp, buf);
		buffer.extend_from_slice(udp.as_bytes());

		buffer.extend_from_slice(buf);

		// Fixup the packet lengths:
		let len = (size_of::<UdpHeader>() + buf.len()) as u16;
		ip.payload_length.set(len);
		udp.length = ip.payload_length;
		udp_checksum_fill(&ip, &mut udp, buf);

		let _ = self.network.send(&buffer);
		Ok(buf.len())
	}
}
impl Read for Bio {
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
	let network = Rc::new(if let Some(if_name) = args.if_name {
		Tun::new_named(Interface::new(if_name)?)?
	} else {
		Tun::new()?
	});

	// Configure the DTLS server
	let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
	acceptor.set_private_key_file(&args.cert, SslFiletype::PEM)?;
	acceptor.set_certificate_chain_file(&args.cert)?;
	acceptor.check_private_key()?;

	// Enable DTLS Cookies
	acceptor.set_options(SslOptions::COOKIE_EXCHANGE);
	let cookie_info = Ssl::new_ex_index::<SocketAddrV6>()?;
	let mut cookey = [0; 16];
	rand_bytes(&mut cookey)?;
	let startup = Instant::now();

	acceptor.set_cookie_generate_cb(move |ssl, output| {
		let info = ssl.ex_data(cookie_info).unwrap();
		let (timestamp, rest) = output.split_first_chunk_mut().unwrap();
		let (mac, _) = rest.split_first_chunk_mut::<20>().unwrap();
		*timestamp = startup.elapsed().as_secs().to_be_bytes();

		let cookey = PKey::hmac(&cookey)?;
		let mut s = Signer::new(MessageDigest::sha1(), &cookey)?;
		s.update(timestamp)?;
		s.update(&info.ip().octets())?;
		s.update(&info.port().to_be_bytes())?;
		let len = s.sign(mac)?;

		Ok(timestamp.len() + len)
	});
	acceptor.set_cookie_verify_cb(move |ssl, input| {
		let info = ssl.ex_data(cookie_info).unwrap();
		let Some((timestamp, mac)) = input.split_first_chunk::<8>() else { return false };
		let then = u64::from_be_bytes(*timestamp);
		let now = startup.elapsed().as_secs();
		let Some(how_old) = now.checked_sub(then).map(Duration::from_secs) else { return false };
		let too_old = Duration::from_mins(5);
		if how_old > too_old { 
			eprint!("Too OLD");
			return false
		}

		let cookey = PKey::hmac(&cookey).unwrap();
		let mut v = Signer::new(MessageDigest::sha1(), &cookey).unwrap();
		v.update(timestamp).unwrap();
		v.update(&info.ip().octets()).unwrap();
		v.update(&info.port().to_be_bytes()).unwrap();
		let mut temp = [0; 20];
		assert_eq!(v.sign(&mut temp).unwrap(), temp.len(), "HMAC sign wrong length");
		temp == mac
	});

	let context = acceptor.build().into_context();
	
	//
	let mut buffer = [0; 65536];
	let mut streams = BTreeMap::<SocketAddrV6, SslStream<_>>::new();

	loop {
		let Ok(length) = network.recv(&mut buffer) else { continue };

		// TODO: Cleanup old connections using a last encrypt timeout (destination must respond to keep the connection alive: SCTP would keep this up with heartbeats, but actually you could also keep this up by sending INIT requests and getting ABORT responses... so we're screwed.)

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

		let dst = SocketAddrV6::new(ip.dst.into(), udp.dst_port.get(), 0, 0);
		let src = SocketAddrV6::new(ip.src.into(), udp.src_port.get(), 0, 0);

		// Encrypt the UDP payload and re-emit
		if let Some(stream) = streams.get_mut(&src) {
			// TODO: Set the prefix to unmodified ip+udp, then call ssl_write if our handshake state is complete.
			let Bio { send_from, send_to, .. } = stream.get_mut();
			*send_from = src;
			*send_to = dst;

			let _res = stream.ssl_write(data);
			// TODO: Handle write errors
		}

		// Handshake or decrypt the payload
		else {
			let mut occupied = match streams.entry(dst) {
				Entry::Occupied(e) => e,
				Entry::Vacant(e) => {
					let mut ssl = Ssl::new(&context)?;
					ssl.set_ex_data(cookie_info, dst);
					ssl.set_accept_state();
					let buffers = Bio {
						send_from: dst,
						send_to: src,
						received: VecDeque::new(),
						network: network.clone(),
					};
					let stream = SslStream::new(ssl, buffers)?;
					e.insert_entry(stream)
				}
			};
			let stream = occupied.get_mut();

			// Set the prefix to reversed src/dst ip+udp, copy the data into the recv queue
			{	let Bio { send_from, send_to, received, .. } = stream.get_mut();
				*send_from = dst;
				*send_to = src;

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
						let data = &rest[..len];
						udp_checksum_fill(&ip, udp, data);
						let length = ip.len();
						let _ = network.send(&buffer[..length]);
					}
				}
			}
		}
	}
}
