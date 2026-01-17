use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{
	rc::Rc,
};

use clap::Parser;
use eyre::Result;
use foreign_types::ForeignTypeRef;
use masquerade::common::udp_checksum_fill;
use masquerade::wire::{Ip6Header, Udp6Packet, UdpHeader, ip_proto};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sign::Signer;
use openssl::ssl::{ErrorCode, Ssl, SslAcceptor, SslFiletype, SslMethod, SslOptions, SslStream};
use tappers::{Interface, Tun};
use tracing::trace;
use tracing_subscriber::EnvFilter;
use zerocopy::{FromZeros, IntoBytes};

// Neither openssl nor openssl-sys expose DTLSv1_listen.  We can set the cookie callbacks, but without DTLSv1_listen, the connection will reassemble the client hello (stateful), before issuing the HelloVerifyRequest... making the cookies pointless... pain and misery spring forth unending.
unsafe extern "C" {
	fn BIO_ADDR_new() -> *mut core::ffi::c_void;
	fn DTLSv1_listen(s: *mut openssl_sys::SSL, ba: *mut core::ffi::c_void) -> core::ffi::c_int;
}

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

	// TODO: srtp_endpoint
}

type SharedBuffer = Rc<RefCell<Udp6Packet<4096>>>;

struct Bio {
	send_from: SocketAddrV6,
	send_to: SocketAddrV6,
	network: Rc<Tun>,
	buffer: SharedBuffer,

	did_write: bool,
}
impl Write for Bio {
	fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
	fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
		let mut packet = self.buffer.borrow_mut();
		let payload_length = size_of::<UdpHeader>() + buf.len();
		let packet_length = size_of::<Ip6Header>() + payload_length;

		// Check if the buf fits into our packet
		let &mut Udp6Packet { ref mut ip, ref mut udp, ref mut buffer } = &mut*packet;
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

		self.did_write = true;

		Ok(buf.len())
	}
}
impl Read for Bio {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		let mut packet = self.buffer.borrow_mut();
		let &mut Udp6Packet { ref ip, ref mut udp, ref mut buffer } = &mut *packet;

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
			return Err(Error::new(ErrorKind::OutOfMemory, "Buffer too small"))
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
	let buffer: SharedBuffer = Rc::new(RefCell::new(Udp6Packet::new_zeroed()));
	let mut streams = BTreeMap::<SocketAddrV6, SslStream<_>>::new();

	trace!(version = openssl::version::version(), "OpenSSL");
	let bio_addr = unsafe { BIO_ADDR_new() };

	loop {
		let dst;
		let src;
		let plain;

		// Receive a packet off the TUN
		{	let mut buffer = buffer.borrow_mut();
			let Ok(length) = network.recv(buffer.as_mut_bytes()) else { continue };
			let &Udp6Packet { ref ip, ref udp, buffer } = &*buffer;

			// TODO: Cleanup old connections using a last encrypt timeout (destination must respond to keep the connection alive: SCTP would keep this up with heartbeats, but actually you could also keep this up by sending INIT requests and getting ABORT responses... so we're screwed.)
			
			// IPv6
			if ip.flags.version() != 6 { continue }
			if ip.len() != length { continue }

			// UDP
			if ip.next_header != ip_proto::UDP { continue }
			if (ip.payload_length.get() as usize) < size_of::<UdpHeader>() { continue }
			if udp.length != ip.payload_length { continue }
			let len = udp.length.get() as usize - size_of::<UdpHeader>();

			dst = SocketAddrV6::new(ip.dst.into(), udp.dst_port.get(), 0, 0);
			src = SocketAddrV6::new(ip.src.into(), udp.src_port.get(), 0, 0);

			// Copy out the plaintext (which only comes from endpoint)
			if src == endpoint {
				plain = Vec::from(&buffer[..len]);
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
				ssl.set_ex_data(cookie_info, dst);
				ssl.set_accept_state();
				let buffers = Bio {
					send_from: dst,
					send_to: src,
					buffer: buffer.clone(),
					network: network.clone(),
					did_write: false,
				};
				let stream = SslStream::new(ssl, buffers)?;

				// Verify Cookies and set the accept state
				// FUCK/TODO: Following 2 lines of code break FireFox...
				let res = unsafe { DTLSv1_listen(stream.ssl().as_ptr(), bio_addr) };
				if res < 1 { continue }

				e.insert_entry(stream)
			}

			// Existing Streams
			Entry::Occupied(e) => e,
		};
		let stream = entry.get_mut();

		let res = if stream.ssl().is_init_finished() == false {
			// Progress the handshake if that's what we're doing
			stream.do_handshake()
		} else if src == endpoint {
			// Write plaintext from endpoint or fetch/peek data off the stream
			// TODO: SRTP
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
			let &mut Udp6Packet { ref mut ip, ref mut udp, ref mut buffer } = &mut *packet;

			let Ok(len) = stream.ssl_read(buffer) else { break };
			let buf = &buffer[..len];
			let payload_length = size_of::<UdpHeader>() + buf.len();
			let packet_length = size_of::<Ip6Header>() + payload_length;

			// After a successful read, update the send_to because we must have had valid application data:
			let Bio { send_from, send_to, .. } = stream.get_mut();
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
	}
}
