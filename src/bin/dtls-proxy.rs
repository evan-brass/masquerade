use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::io::{Cursor, Error, ErrorKind, Read, Write};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::rc::Rc;
use std::str::FromStr;
use std::time::{Duration, Instant};

use clap::Parser;
use eyre::Result;
use masquerade::common::udp_checksum_fill;
use masquerade::wire::{Ip6Header, Udp6Packet, UdpHeader, ip_proto};
use openssl::ssl::{ErrorCode, Ssl, SslAcceptor, SslFiletype, SslMethod, SslStream};
use srtp::openssl::{Config, InboundSession, OutboundSession, session_pair};
use tappers::{Interface, Tun};
use tracing::trace;
use tracing_subscriber::EnvFilter;
use zerocopy::{FromZeros, IntoBytes};

type Never = core::convert::Infallible;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "cert.pem")]
	cert: String,

	#[arg(long, short)]
	if_name: Option<String>,

	#[arg(long, short, default_value = "[::1]:9899")]
	endpoint: String,

	#[arg(long, short, default_value = "[::1]:4666")]
	rtp_endpoint: String,
}

type SharedBuffer = Rc<RefCell<Udp6Packet<4096>>>;

struct Bio {
	send_from: SocketAddrV6,
	send_to: SocketAddrV6,
	network: Rc<Tun>,
	buffer: SharedBuffer,
	last_update: Instant,

	sessions: Option<(InboundSession, OutboundSession)>,
}
impl Write for Bio {
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
	fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
		let mut packet = self.buffer.borrow_mut();
		let payload_length = size_of::<UdpHeader>() + buf.len();
		let packet_length = size_of::<Ip6Header>() + payload_length;

		// Check if the buf fits into our packet
		let &mut Udp6Packet {
			ref mut ip,
			ref mut udp,
			ref mut buffer,
		} = &mut *packet;
		let Some(dst) = buffer.get_mut(..buf.len()) else {
			return Err(Error::new(ErrorKind::OutOfMemory, "Packet too large"));
		};
		dst.copy_from_slice(buf);
		ip.flags.set_version(6);
		ip.flags.set_traffic_class(0);
		ip.flags.set_flow_label(0);
		ip.next_header = ip_proto::UDP;
		ip.hop_limit = 64;
		ip.payload_length.set(payload_length as u16);
		ip.src = self.send_from.ip().octets();
		ip.dst = self.send_to.ip().octets();
		udp.src_port.set(self.send_from.port());
		udp.dst_port.set(self.send_to.port());
		udp.length = ip.payload_length;
		udp_checksum_fill(ip, udp, buf);

		let _ = self.network.send(&packet.as_bytes()[..packet_length]);
		// Burn the written packet
		packet.udp.length.set(0);

		// TODO: It would probably be better to update this somewhere else
		self.last_update = Instant::now();

		Ok(buf.len())
	}
}
impl Read for Bio {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		let mut packet = self.buffer.borrow_mut();
		let &mut Udp6Packet {
			ref ip,
			ref mut udp,
			ref mut buffer,
		} = &mut *packet;

		// Check UDP length
		let Some(len) = udp.length.get().checked_sub(size_of::<UdpHeader>() as u16) else {
			return Err(Error::new(ErrorKind::WouldBlock, "Packet burned"));
		};

		// Check dst ip
		if Ipv6Addr::from(ip.dst) != *self.send_from.ip() {
			return Err(Error::new(ErrorKind::WouldBlock, "IP mismatch"));
		}
		// Check dst port
		if udp.dst_port.get() != self.send_from.port() {
			return Err(Error::new(ErrorKind::WouldBlock, "UDP port mismatch"));
		}
		// Burn the packet
		udp.length.set(0);

		// Copy the data
		let len = len as usize;
		let src = buffer.get(..len).unwrap();
		let Some(dst) = buf.get_mut(..len) else {
			return Err(Error::new(ErrorKind::OutOfMemory, "Buffer too small"));
		};
		dst.copy_from_slice(src);

		Ok(len)
	}
}

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;
	let endpoint = SocketAddrV6::from_str(&args.endpoint)?;
	let rtp_endpoint = SocketAddrV6::from_str(&args.rtp_endpoint)?;

	// Setup the TUN interface
	let network = Rc::new(if let Some(if_name) = args.if_name {
		Tun::new_named(Interface::new(if_name)?)?
	} else {
		Tun::new()?
	});

	// Configure the DTLS server
	let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
	acceptor.set_tlsext_use_srtp(srtp::openssl::SRTP_PROFILE_NAMES)?;
	acceptor.set_private_key_file(&args.cert, SslFiletype::PEM)?;
	acceptor.set_certificate_chain_file(&args.cert)?;
	acceptor.check_private_key()?;

	let context = acceptor.build().into_context();

	//
	let buffer: SharedBuffer = Rc::new(RefCell::new(Udp6Packet::new_zeroed()));
	let mut streams = BTreeMap::<SocketAddrV6, SslStream<_>>::new();
	let mut next_cleanup = 10;

	loop {
		let dst;
		let src;
		let plain;
		let first_bytes;

		// Receive a packet off the TUN
		{
			let mut buffer = buffer.borrow_mut();
			let Ok(length) = network.recv(buffer.as_mut_bytes()) else {
				continue;
			};
			let &Udp6Packet {
				ref ip,
				ref udp,
				buffer,
			} = &*buffer;

			// TODO: Cleanup old connections using a last encrypt timeout (destination must respond to keep the connection alive: SCTP would keep this up with heartbeats, but actually you could also keep this up by sending INIT requests and getting ABORT responses... so we're screwed.)

			// IPv6
			if ip.flags.version() != 6 {
				continue;
			}
			if ip.len() != length {
				continue;
			}

			// UDP
			if ip.next_header != ip_proto::UDP {
				continue;
			}
			if (ip.payload_length.get() as usize) < size_of::<UdpHeader>() {
				continue;
			}
			if udp.length != ip.payload_length {
				continue;
			}
			let len = udp.length.get() as usize - size_of::<UdpHeader>();
			let data = &buffer[..len];

			dst = SocketAddrV6::new(ip.dst.into(), udp.dst_port.get(), 0, 0);
			src = SocketAddrV6::new(ip.src.into(), udp.src_port.get(), 0, 0);

			first_bytes = data.first_chunk::<2>().cloned();
			// Copy out the plaintext (which only comes from endpoint)
			if src == endpoint {
				plain = Vec::from(data);
			} else {
				plain = Vec::new();
			}
		}

		let mut entry = match streams.entry(dst) {
			// TODO: This should be an ICMP destination unreachable error
			// Drop packets coming from endpoint where we don't have a stream
			Entry::Vacant(_) if src == endpoint => continue,

			// Create new DTLS streams
			Entry::Vacant(e) => {
				let mut ssl = Ssl::new(&context)?;
				ssl.set_accept_state();
				let buffers = Bio {
					send_from: dst,
					send_to: src,
					buffer: buffer.clone(),
					network: network.clone(),
					last_update: Instant::now(),
					sessions: None,
				};
				let stream = SslStream::new(ssl, buffers)?;

				e.insert_entry(stream)
			}

			// Existing Streams
			Entry::Occupied(e) => e,
		};
		let stream = entry.get_mut();

		let res = if stream.ssl().is_init_finished() == false {
			// Progress the handshake if that's what we're doing
			let res = stream.do_handshake();
			if stream.ssl().is_init_finished() {
				let session = session_pair(
					stream.ssl(),
					Config {
						window_size: 0,
						allow_repeat_tx: false,
						encrypt_extension_headers: &[],
					},
				);
				trace!(?session, "srtp session_pair");
				stream.get_mut().sessions = session.ok();
			}
			res
		} else if let Some([128..191, second_byte]) = first_bytes {
			let mut packet = buffer.borrow_mut();
			let &mut Udp6Packet {
				ref mut ip,
				ref mut udp,
				ref mut buffer,
			} = &mut *packet;
			let &mut Bio {
				send_from,
				send_to,
				last_update: _, // TODO: Update last_update?
				sessions: Some((ref mut incoming, ref mut outgoing)),
				..
			} = stream.get_mut()
			else {
				continue;
			};
			let mut cursor = Cursor::new(buffer.as_mut_bytes());
			cursor.set_position(udp.length.get() as u64 - size_of::<UdpHeader>() as u64);

			// Decrypt/encrypt media packets
			let res = match (src == rtp_endpoint, second_byte) {
				// https://datatracker.ietf.org/doc/html/rfc5761#section-8
				(false, 200..224) => incoming.unprotect_rtcp(&mut cursor),
				(false, _) => incoming.unprotect(&mut cursor),
				(true, 200..224) => outgoing.protect_rtcp(&mut cursor),
				(true, _) => outgoing.protect(&mut cursor),
			};
			let Ok(()) = res else { continue };

			// Pass cipher text back to send_to, and plaintext out to rtp_endpoint
			let receiver = if src == rtp_endpoint {
				send_to
			} else {
				rtp_endpoint
			};

			let new_len = cursor.position() as usize;
			let data = &buffer[..new_len];
			let payload_length = u16::try_from(size_of::<UdpHeader>() + new_len)?;
			let packet_length = size_of::<Ip6Header>() + size_of::<UdpHeader>() + new_len;
			ip.payload_length.set(payload_length);
			ip.src = send_from.ip().octets();
			ip.dst = receiver.ip().octets();
			udp.length = ip.payload_length;
			udp.src_port.set(send_from.port());
			udp.dst_port.set(receiver.port());
			udp_checksum_fill(ip, udp, data);
			let _ = network.send(&packet.as_bytes()[..packet_length]);
			// Packet has been handled: continue
			continue;
		} else if src == endpoint {
			// Write plaintext from endpoint or fetch/peek data off the stream
			stream.ssl_write(&plain).map(|_| {})
		} else {
			// Use peek to prime the thing in the thing
			let mut temp = [0; 4];
			stream.ssl_peek(&mut temp).map(|_| {})
		};

		// Handle errors:
		if let Err(e) = res {
			if !matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) {
				entry.remove();
				continue;
			}
		}

		// Pull data out, and emit plaintext UDP
		while stream.ssl().pending() > 0 {
			let mut packet = buffer.borrow_mut();
			let &mut Udp6Packet {
				ref mut ip,
				ref mut udp,
				ref mut buffer,
			} = &mut *packet;

			let Ok(len) = stream.ssl_read(buffer) else {
				break;
			};
			let buf = &buffer[..len];
			let payload_length = size_of::<UdpHeader>() + buf.len();
			let packet_length = size_of::<Ip6Header>() + payload_length;

			// After a successful read, update the send_to because we must have had valid application data:
			let Bio {
				send_from, send_to, ..
			} = stream.get_mut();
			*send_to = src;

			// Construct our plaintext packet
			ip.flags.set_version(6);
			ip.flags.set_traffic_class(0);
			ip.flags.set_flow_label(0);
			ip.next_header = ip_proto::UDP;
			ip.hop_limit = 64;
			ip.payload_length.set(payload_length as u16);
			ip.src = send_from.ip().octets();
			ip.dst = endpoint.ip().octets();
			udp.src_port.set(send_from.port());
			udp.dst_port.set(endpoint.port());
			udp.length = ip.payload_length;
			udp_checksum_fill(ip, udp, buf);

			let _ = network.send(&packet.as_bytes()[..packet_length]);
		}

		// Handle cleaning up old connections
		let max_age = Duration::from_mins(5);
		if streams.len() > next_cleanup {
			streams.retain(|_, stream| stream.get_ref().last_update.elapsed() < max_age);
			next_cleanup = streams.len() + 10;
		}
	}
}
