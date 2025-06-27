use std::{cell::RefCell, collections::{btree_map::Entry, BTreeMap}, io::{ErrorKind, Read, Write}, net::{Ipv6Addr, /* SocketAddrV6 */}, str::FromStr};
use eyre::Result;
// use openssl_sys::SRTP_PROTECTION_PROFILE;
use std::io::Error;
use std::rc::Rc;
// use sctp::{Chunk, Data, Init, Param, Sack, Sctp};
// use rand::random;

use clap::Parser;
// use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod, SslStream, SslVerifyMode};
// use smoltcp::{phy::ChecksumCapabilities, wire::{IpProtocol, Ipv6Packet, Ipv6Repr, UdpPacket, UdpRepr}};
use tappers::{Interface, Tun};
// use tracing::{debug, trace};

use openssl::ssl::SslStream;
use openssl::{
	// error::ErrorStack,
	// ex_data::Index,
	// hash::MessageDigest,
	pkey::PKey,
	// sign::{Signer, Verifier},
	ssl::{Ssl, SslAcceptor, SslMethod, /* SslVerifyMode */},
	x509::X509,
};
use tracing_subscriber::EnvFilter;
use wire::{ip_proto, FromBytes, Ip6Header, SctpHeader, UdpHeader};

type Never = core::convert::Infallible;

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
	send_from: ([u8; 16], u16),
	send_to: ([u8; 16], u16),
	tun: Rc<Tun>,
	recv_buffer: Rc<RefCell<[u8; 65536]>>,
	send_buffer: Rc<RefCell<[u8; 65536]>>,
}
impl Read for Wrapper {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
		let would_block = Err(Error::new(ErrorKind::WouldBlock, ""));
		let Ok(mut buffer) = self.recv_buffer.try_borrow_mut() else { return  would_block };
		let (ip, rest) = Ip6Header::mut_from_prefix(buffer.as_mut_slice()).unwrap();
		if (ip.flags.get() >> 28) != 6 { return would_block }
		if ip.next_header != ip_proto::UDP { return would_block }
		if ip.payload_length.get() <= 8 { return would_block }

		// Mark the packet as consumed so that we return would_block for repeat reads
		ip.next_header = 0xff;

		let len = usize::min(buf.len(), ip.payload_length.get() as usize - 8);
		buf[..len].copy_from_slice(&rest[8..][..len]);
		Ok(len)
	}
}
impl Write for Wrapper {
	fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
	fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
		let mut buffer = self.send_buffer.borrow_mut();
		let (ip, rest) = Ip6Header::mut_from_prefix(buffer.as_mut_slice()).unwrap();
		let (udp, rest) = UdpHeader::mut_from_prefix(rest).unwrap();
		if rest.len() < buf.len() { return Err(Error::other("Packet too large")) }
		let Some(length) = u16::try_from(buf.len()).ok().and_then(|l| l.checked_add(8)) else { return Err(Error::other("Packet too large")) };

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
		self.tun.send(&buffer[..tot_len])?;

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
	let endpoint = Ipv6Addr::from_str(&args.endpoint)?;

	// Configure our DTLS server
	let pem = std::fs::read(args.cert_file)?;
	let certificate = X509::from_pem(&pem)?;
	let pkey = PKey::private_key_from_pem(&pem)?;

	// Figure out what our ufrag is
	// let mut fingerprint = certificate.digest(MessageDigest::sha256())?;
	// let ice_ufrag = to_base62(&mut fingerprint);
	// debug!(ice_ufrag, "Hosted");

	// Configure a DTLS server
	let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::dtls())?;
	acceptor.set_certificate(&certificate)?;
	acceptor.set_private_key(&pkey)?;
	acceptor.check_private_key()?;
	// acceptor.add_client_ca(&certificate)?;
	// let mode = SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT;
	// acceptor.set_verify_callback(mode, |_preverify, _cert_store| {
	// 	// TODO: Check certificate expiration?
	// 	true
	// });

	// Get a slot to hold the socketaddress so that we can generate and check dtls cookies:
	// let (addr_index, generate, verify) = dtls_cookies()?;
	// acceptor.set_cookie_generate_cb(generate);
	// acceptor.set_cookie_verify_cb(verify);
	let acceptor = acceptor.build();

	// Setup the TUN interface
	let tun = Rc::new(if let Some(if_name) = args.if_name {
		Tun::new_named(Interface::new(if_name)?)?
	} else {
		Tun::new()?
	});

	// TODO: Shrink buffers, this is ridiculous
	let recv_buffer = Rc::new(RefCell::new([0; 65536]));
	let send_buffer = Rc::new(RefCell::new([0; 65536]));
	let mut sctp_buffer = [0; 65536];
	let mut connections = BTreeMap::new();

	loop {
		let (in_ip, src_port, dst_port) = {
			let mut buffer = recv_buffer.borrow_mut();
			let Ok(length) = tun.recv( buffer.as_mut_slice()) else { continue };
			let (ip, rest) = Ip6Header::ref_from_prefix(buffer.as_slice()).unwrap();
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
					tun: tun.clone(),
				};
				let mut ssl = Ssl::new(acceptor.context())?;
				ssl.set_accept_state();
				let Ok(_) = ssl.set_mtu(2000) else { continue };
				let ssl = SslStream::new(ssl, wrap)?;
				v.insert(ssl)
			}
			Entry::Occupied(o) => o.into_mut()
		};

		// Retry the ssl operation until it would block, fails, or succeeds if it's SCTP
		loop {
			match in_ip.next_header {
				// Decrypt the DTLS packet
				ip_proto::UDP => {
					let (out_ip, rest) = Ip6Header::mut_from_prefix(sctp_buffer.as_mut_slice()).unwrap();// TODO: If we end up switching to UDP encapsulated SCTP, then distinguishing between DTLS UDP traffic and SCTP UDP traffic might be annoying.  I generally disapprove of muxing, the whole point of these programs is to not do that when possible.  Probably the right thing to do in that case would be to use two different TUN interfaces: one for DTLS and one for SCTP so that routing rules can
					// let (out_udp, rest) = UdpHeader::mut_from_prefix(rest).unwrap();

					match ctx.read(rest) {
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						Ok(length) if length > 0 => {
							// Update the send_to address using the last seen src ip and port
							ctx.get_mut().send_to = (in_ip.src, src_port);

							let length = u16::try_from(length).unwrap();
							out_ip.flags.set(6 << 28);
							out_ip.payload_length.set(length);
							out_ip.next_header = ip_proto::SCTP;
							out_ip.hop_limit = 5;
							out_ip.src = in_ip.dst;
							out_ip.dst = endpoint.octets();
							let tot_len = out_ip.len();
							tun.send(&sctp_buffer[..tot_len])?;
						}
						_ => {
							connections.remove(&in_ip.dst);
							break
						}
					}
				}
				// Encrypt the SCTP packet
				ip_proto::SCTP => {
					match ctx.write(&recv_buffer.borrow()[40..in_ip.len()]) {
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
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
