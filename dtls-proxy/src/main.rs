use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use eyre::Result;
type Never = core::convert::Infallible;
use clap::Parser;
use mbedtls::error::codes;
use mbedtls::error::HiError::SslWantRead;
use mbedtls::pk::Pk;
use mbedtls::rng::{CtrDrbg, OsEntropy};
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::context::Timer;
use mbedtls::ssl::{Config, Context, CookieContext, Io};
use mbedtls::x509::Certificate;
use tappers::Tun;
use tracing_subscriber::EnvFilter;
use tracing::trace;
use wire::{ip_proto, FromBytes, Ip6Header, SctpHeader, UdpHeader};
use tappers::Interface;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "cert.pem")]
	cert_file: String,

	#[arg(long, short, default_value = "fd00:1::")]
	endpoint: String,

	#[arg(long, short)]
	if_name: Option<String>,
}

struct Wrapper {
	// Random Destination ip
	send_from: ([u8; 16], u16),
	// Last seen source ip (update with the sender of fresh decrypted data)
	send_to: ([u8; 16], u16),

	// Handle to the network for send
	network: Rc<Tun>,

	// Shared receive and send buffers
	recv_buffer: Rc<RefCell<[u8]>>,
	send_buffer: Rc<RefCell<[u8]>>,

	// Timestamp to cleanup old connections
	last_update: Instant,
}
impl Io for Wrapper {
	fn recv(&mut self, buf: &mut [u8]) -> mbedtls::Result<usize> {
		let would_block = Err(mbedtls::Error::HighLevel(codes::SslWantRead));
		let Ok(mut buffer) = self.recv_buffer.try_borrow_mut() else { return  would_block };
		let (ip, rest) = Ip6Header::mut_from_prefix(&mut buffer).unwrap();
		if (ip.flags.get() >> 28) != 6 { return would_block }
		if ip.next_header != ip_proto::UDP { return would_block }
		if ip.payload_length.get() <= 8 { return would_block }

		// Mark the packet as consumed so that we return would_block for repeat reads
		ip.next_header = 0xff;

		let len = usize::min(buf.len(), ip.payload_length.get() as usize - 8);
		buf[..len].copy_from_slice(&rest[8..][..len]);
		Ok(len)
	}
	fn send(&mut self, buf: &[u8]) -> mbedtls::Result<usize> {
		let mut buffer = self.send_buffer.borrow_mut();
		let (ip, rest) = Ip6Header::mut_from_prefix(&mut buffer).unwrap();
		let (udp, rest) = UdpHeader::mut_from_prefix(rest).unwrap();
		if rest.len() < buf.len() { return Err(mbedtls::Error::HighLevel(codes::SslBufferTooSmall)) }
		let Some(length) = u16::try_from(buf.len()).ok().and_then(|l| l.checked_add(8)) else { return Err(mbedtls::Error::HighLevel(codes::SslBufferTooSmall)) };

		ip.flags.set(6 << 28);
		ip.payload_length.set(length);
		ip.next_header = ip_proto::UDP;
		ip.hop_limit = 5;
		ip.dst = self.send_to.0;
		ip.src = self.send_from.0;
		udp.dst_port.set(self.send_to.1);
		udp.src_port.set(self.send_from.1);
		udp.length.set(length);
		udp.checksum.set(0);
		rest[..buf.len()].copy_from_slice(buf);

		let tot_len = ip.len();
		self.network.send(&buffer[..tot_len])
			.map_err(|_|mbedtls::Error::Other(-15))?;

		Ok(buf.len())
	}
}

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;

	// Parse the destination ip address
	let endpoint = Ipv6Addr::from_str(&args.endpoint)?.octets();

	// Setup the TUN interface
	let network = Rc::new(if let Some(if_name) = args.if_name {
		Tun::new_named(Interface::new(if_name)?)?
	} else {
		Tun::new()?
	});

	// Enable mbedtls logging
	unsafe { mbedtls::set_global_debug_threshold(2); }

	// Setup random
	let entropy = Arc::new(OsEntropy::new());
	let rng = Arc::new(CtrDrbg::new(entropy, None)?);

	// Configure our DTLS server
	let mut config = Config::new(Endpoint::Server, Transport::Datagram, Preset::Default);
	config.set_dbg_callback(|level, file, line, message| {
		trace!("MBEDTLS({level}) {file}:{line} {message}");
	});
	config.set_rng(rng.clone());
	// TODO: Peer certificate verify

	// Load our certificate file
	let mut pem = std::fs::read(args.cert_file)?; pem.push(0); // Null terminate the PEM as required by mbedtls
	let cert = Arc::new(Certificate::from_pem_multiple(&pem)?);
	let key = Arc::new(Pk::from_private_key(&pem, None)?);
	config.push_cert(cert, key)?;

	// Enable DTLS cookies
	let cookies = CookieContext::new(rng)?;
	config.set_dtls_cookies(Arc::new(cookies));

	let config = Arc::new(config);

	// Buffers
	const BUFFER_LENGTH: usize = 4096;
	let recv_buffer = Rc::new(RefCell::new([0; BUFFER_LENGTH]));
	let send_buffer = Rc::new(RefCell::new([0; BUFFER_LENGTH]));
	let mut decrypted = [0; BUFFER_LENGTH];

	// Connection state
	let mut connections = BTreeMap::new();
	// TODO: Keep a map from (src ip, src port) -> dst ip so that we limit each src socket addr to 1 DTLS connection.

	// Cleanup state
	let timeout = Duration::from_secs(60 * 2);
	let cleanup = Duration::from_secs(30);
	let mut last_cleanup = Instant::now();

	loop {
		// Periodically Cleanup the connections
		if last_cleanup.elapsed() > cleanup {
			connections.retain(|_, v: &mut Context<Wrapper>| {
				let Some(Wrapper { last_update, .. }) = v.io() else { unreachable!() };
				last_update.elapsed() < timeout
			});
			last_cleanup = Instant::now();
		}

		// Read a packet from the network interface
		let (in_ip, src_port, dst_port) = {
			let mut buffer = recv_buffer.borrow_mut();
			let Ok(length) = network.recv( buffer.as_mut_slice()) else { continue };
			let (ip, rest) = Ip6Header::ref_from_prefix(buffer.as_slice()).unwrap();
			trace!(?ip, "TUN PACKET");
			if (ip.flags.get() >> 28) != 6 { continue }
			if ip.len() != length { continue }

			let (src_port, dst_port) = match (ip.next_header, ip.payload_length.get()) {
				(ip_proto::UDP, 8..) => {
					let (udp, _rest) = UdpHeader::ref_from_prefix(rest).unwrap();
					if udp.length != ip.payload_length { continue }
					(udp.src_port.get(), udp.dst_port.get())
				}
				(ip_proto::SCTP, 12..) => {
					let (sctp, _rest) = SctpHeader::ref_from_prefix(rest).unwrap();
					(sctp.src_port.get(), sctp.dst_port.get())
				}
				_ => continue,
			};

			(ip.clone(), src_port, dst_port)
		};

		let entry = connections.entry(in_ip.dst);
		let ctx = match entry {
			Entry::Vacant(_) if in_ip.next_header != ip_proto::UDP => {
				// TODO: ICMP error?
				// Don't create a DTLS context if we're receiving SCTP traffic
				continue;
			}
			Entry::Vacant(v) => {
				let wrap = Wrapper {
					send_from: (in_ip.dst, dst_port),
					send_to: (in_ip.src, src_port),
					recv_buffer: recv_buffer.clone(),
					send_buffer: send_buffer.clone(),
					network: network.clone(),
					last_update: Instant::now(),
				};
				let mut ssl = Context::new(config.clone());
				ssl.set_timer_callback(Box::new(Timer::new()));
				// Set the *client id* which is really just input to do DTLS cookies.
				ssl.set_client_transport_id_once(&in_ip.dst);
				let res = ssl.establish(wrap, None);
				trace!(?res, "ESTABLISH");
				match res {
					Ok(()) => {}
					Err(e) if e.high_level() == Some(SslWantRead) => {}
					// Don't insert the new ssl unless we successfully establish or want more recv data
					// TODO: This probably isn't correct, what if we receive a non DTLS packet - that would mean there isn'
					_ => continue
				}
				v.insert(ssl)
			}
			Entry::Occupied(o) => o.into_mut()
		};

		// Retry the ssl operation until it would block, fails, or succeeds if it's SCTP
		loop {
			match in_ip.next_header {
				// Decrypt the DTLS packet
				ip_proto::UDP => {
					let (out_ip, rest) = Ip6Header::mut_from_prefix(decrypted.as_mut_slice()).unwrap();

					let res = ctx.recv(rest);
					trace!(?res, "SCTP DECRYPT");
					match res {
						Err(e) if e.high_level() == Some(codes::SslWantRead) => break,
						Ok(length) if length > 0 => {
							// Update the send_to address using the last seen src ip and port
							let Wrapper { last_update, send_to, ..} = ctx.io_mut().unwrap();
							// TODO: handle src tracking to limit src ip+port to a single dtls connection
							*last_update = Instant::now();
							*send_to = (in_ip.src, src_port);

							let length = u16::try_from(length).unwrap();
							out_ip.flags.set(6 << 28);
							out_ip.payload_length.set(length);
							out_ip.next_header = ip_proto::SCTP;
							out_ip.hop_limit = 5;
							out_ip.src = in_ip.dst;
							out_ip.dst = endpoint;
							let tot_len = out_ip.len();
							network.send(&decrypted[..tot_len])?;
						}
						_ => {
							connections.remove(&in_ip.dst);
							break
						}
					}
				}
				// Encrypt the SCTP packet (if it came from endpoint)
				ip_proto::SCTP => {
					// Drop packets if they didn't originate from the endpoint we're relaying for
					if in_ip.src != endpoint { continue }

					let res = ctx.send(&recv_buffer.borrow()[40..in_ip.len()]);
					trace!(?res, "SCTP ENCRYPT");
					match res {
						Err(e) if e.high_level() == Some(codes::SslWantRead) => break,
						Ok(length) if length > 0 => break,
						_ => {
							connections.remove(&in_ip.dst);
							break
						}
					}
				}
				// We've filtered to UDP or SCTP already
				_ => unreachable!(),
			}
		}
	}
}
