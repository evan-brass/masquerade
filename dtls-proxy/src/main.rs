use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use eyre::{eyre, Result};
type Never = core::convert::Infallible;
use clap::Parser;
use mbedtls::error::codes;
use mbedtls::error::HiError::SslWantRead;
use mbedtls::hash;
use mbedtls::pk::Pk;
use mbedtls::rng::{CtrDrbg, OsEntropy};
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::context::Timer;
use mbedtls::ssl::{Config, Context, CookieContext, Io};
use mbedtls::x509::{Certificate, VerifyError};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use socket2::{Domain, Protocol, Socket, Type};
use tappers::Tun;
use tracing_subscriber::EnvFilter;
use tracing::{info, trace};
use wire::{ip_proto, FromBytes, Ip6Header, UdpHeader};
use tappers::Interface;
use stun::{Stun, Class, Method, attr::*, attr::integrity::Integrity, attr::parse::AttrIter as _};
use std::net::SocketAddr;
use slab::Slab;
use core::ptr::from_ref;
use core::ffi::c_void;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "cert.pem")]
	cert_file: String,

	#[arg(long, short, default_value = "[fd00:1::]:5001")]
	sctp: String,

	#[arg(long, short)]
	if_name: Option<String>,
}

const B62_CHARSET: &[char] = &[
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
	'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
	'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
	'5', '6', '7', '8', '9',
];
fn to_base62(fingerprint: &mut [u8]) -> String {
	let mut res = [0; 43];
	for j in 0..43 {
		let mut remainder = 0;
		for i in 0..32 {
			let v = 256 * remainder + fingerprint[i] as u32;
			remainder = v % 62;
			fingerprint[i] = (v / 62) as u8;
		}
		res[j] = remainder as u8;
	}
	res.reverse();

	let mut ret = String::with_capacity(43);

	for i in res {
		if ret.is_empty() && i == 0 {
			continue;
		}
		ret.push(B62_CHARSET[i as usize]);
	}
	if ret.is_empty() {
		ret.push('A');
	}

	ret
}


struct IndexIp {
	proto: u8,
	site: u16,
	index: u64,
}
impl From<&IndexIp> for Ipv6Addr {
	fn from(IndexIp { proto, site, index }: &IndexIp) -> Self {
		let mut octets = [0xfd, *proto, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
		octets[2..4].copy_from_slice(&site.to_be_bytes());
		octets[8..].copy_from_slice(&index.to_be_bytes());
		octets.into()
	}
}
impl TryFrom<&Ipv6Addr> for IndexIp {
	type Error = Ipv6Addr;
	fn try_from(value: &Ipv6Addr) -> Result<Self, Self::Error> {
		let octets = value.octets();
		// The value must be within the private ip6 range of fd00::/8
		if octets[0] != 0xfd {
			return Err(*value)
		}
		// The value must be within the index range of fd{proto}:{site}::/64
		if octets[4..8] != [0, 0, 0, 0] {
			return Err(*value);
		}
		let proto = octets[1];
		let site = u16::from_be_bytes(octets[2..4].try_into().unwrap());
		let index = u64::from_be_bytes(octets[8..].try_into().unwrap());
		Ok(Self { proto, site, index })
	}
}

struct Wrapper {
	// Random Destination ip
	send_from: SocketAddrV6,
	// Last seen source ip (update with the sender of fresh decrypted data)
	send_to: SocketAddrV6,

	// Handle to the network for send
	network: Rc<Tun>,

	// Shared receive and send buffers
	recv_buffer: Rc<RefCell<[u8]>>,
	send_buffer: Rc<RefCell<[u8]>>,

	// Timestamp to cleanup old connections
	last_update: Instant,

	// Possible SCTP Socket of the parent DTLS Context
	sctp: Option<Socket>,
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
		ip.dst = self.send_to.ip().octets();
		ip.src = self.send_from.ip().octets();
		udp.dst_port.set(self.send_to.port());
		udp.src_port.set(self.send_from.port());
		udp.length.set(length);
		udp.checksum.set(0);
		rest[..buf.len()].copy_from_slice(buf);

		let tot_len = ip.len();
		self.network.send(&buffer[..tot_len])
			.map_err(|_|mbedtls::Error::Other(-15))?;

		Ok(buf.len())
	}
}

const NET: Token = Token(usize::MAX);
const SCTP: Token = Token(usize::MAX - 1);

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;

	// Prep async
	let mut poll = Poll::new()?;
	let mut events = Events::with_capacity(128);

	// Setup the TUN interface
	let mut network = if let Some(if_name) = args.if_name {
		Tun::new_named(Interface::new(if_name)?)?
	} else {
		Tun::new()?
	};
	network.set_nonblocking(true)?;
	poll.registry().register(&mut SourceFd(&network.as_raw_fd()), NET, Interest::READABLE)?;
	let network = Rc::new(network);

	// Parse the destination ip address
	let sctp_addr = SocketAddrV6::from_str(&args.sctp)?;
	let IndexIp { site: our_site, .. } = IndexIp::try_from(sctp_addr.ip()).map_err(|_ip| eyre!("sctp address wasn't an indexip"))?;
	let endpoint = sctp_addr.ip().octets();

	// Bind our SCTP Listener
	let sctp = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::SCTP))?;
	// TODO: Why doesn't sctp_addr work here?
	sctp.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, sctp_addr.port(), 0, 0).into())?;
	sctp.set_nonblocking(true)?;
	sctp.listen(128)?;
	poll.registry().register(&mut SourceFd(&sctp.as_raw_fd()), SCTP, Interest::READABLE)?;

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

	// Load our certificate file
	let mut pem = std::fs::read(args.cert_file)?; pem.push(0); // Null terminate the PEM as required by mbedtls
	let cert = Certificate::from_pem(&pem)?;

	let mut fingerprint = [0; 32];
	assert_eq!(hash::Md::hash(hash::Type::Sha256, cert.as_der(), &mut fingerprint)?, 32);
	let self_pid = to_base62(&mut fingerprint);
	info!(?self_pid, "SELF PID");

	let fullchain = Arc::new(FromIterator::from_iter([cert]));
	let key = Arc::new(Pk::from_private_key(&pem, None)?);
	config.push_cert(fullchain, key)?;

	// Enable DTLS cookies
	let cookies = CookieContext::new(rng)?;
	config.set_dtls_cookies(Arc::new(cookies));
	config.set_authmode(mbedtls::ssl::config::AuthMode::Optional);
	config.set_verify_callback(|cert, unk, verify_error| {
		trace!(?cert, ?unk, ?verify_error, "CERT VERIFY");
		// WebRTC mostly doesn't use verified certificates
		verify_error.remove(VerifyError::CERT_NOT_TRUSTED);
		// TODO: Verify that the certificate is not valid for more than 365 days?
		Ok(())
	});

	let config = Arc::new(config);

	// Buffers
	const BUFFER_LENGTH: usize = 4096;
	let recv_buffer = Rc::new(RefCell::new([0; BUFFER_LENGTH]));
	let send_buffer = Rc::new(RefCell::new([0; BUFFER_LENGTH]));
	let mut decrypted = [0; BUFFER_LENGTH];

	// Connection state
	let mut cids: BTreeMap<SocketAddrV6, usize> = BTreeMap::new();
	let mut connections: Slab<Context<Wrapper>> = Slab::new();
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

		// Handle Events
		for e in events.into_iter() {
			loop {
				match e.token() {
					NET => {
						// Read a packet from the network interface
						let mut buffer = recv_buffer.borrow_mut();
						let Ok(length) = network.recv(buffer.as_mut_slice()) else { break };
						let (ip, rest) = Ip6Header::mut_from_prefix(buffer.as_mut_slice()).unwrap();

						trace!(?ip, "TUN PACKET");
						if (ip.flags.get() >> 28) != 6 { continue }
						if ip.len() != length { continue }

						match (IndexIp::try_from(&Ipv6Addr::from(ip.dst)), ip.next_header, ip.payload_length.get(), rest[8]) {
							// Traffic for VPN Allocations
							(Ok(IndexIp { proto: 0x04, index, .. }), _, _, _) => {
								let Some(context) = connections.get_mut(index as usize) else { continue };
								let Wrapper { sctp, .. } = context.io_mut().unwrap();
								let Some(socket) = sctp else { continue };

								// Relay the IPv6 packet as SCTP data
								trace!(packet = &buffer[..length], ?index, "In");
								let _ = socket.write(&buffer[..length]);
							}
							// Plaintext SCTP
							(Ok(IndexIp { proto: 0x03, index, .. }), ip_proto::SCTP, 12.., _) => {
								let key = index as usize;
								let Some(context) = connections.get_mut(key) else { continue };

								// Drop packets if they didn't originate from the endpoint we're relaying for
								if ip.src != endpoint { continue }

								// Try to encrypt the SCTP plaintext
								let res = context.send(&rest[..ip.payload_length.get() as usize]);
								trace!(?res, "DTLS SEND");
								match res {
									Err(e) if e.high_level() == Some(codes::SslWantRead) => {},
									Ok(length) if length > 0 => {},
									_ => {
										let context = connections.remove(key);
										let Wrapper { send_from, sctp, .. } = context.io().unwrap();
										if let Some(socket) = sctp {
											poll.registry().deregister(&mut SourceFd(&socket.as_raw_fd()))?;
										}
										cids.remove(send_from);
									}
								}
							}
							// Possibly DTLS
							(Err(src_ip), ip_proto::UDP, 9.., 20..64) => {
								let (udp, _rest) = UdpHeader::mut_from_prefix(rest).unwrap();
								let cid = SocketAddrV6::new(src_ip, udp.dst_port.get(), 0, 0);
								let sender = SocketAddrV6::new(ip.src.into(), udp.src_port.get(), 0, 0);
								drop(buffer);

								let key = match cids.entry(cid) {
									Entry::Vacant(v) => {
										let wrap = Wrapper {
											send_from: cid,
											send_to: sender,
											recv_buffer: recv_buffer.clone(),
											send_buffer: send_buffer.clone(),
											network: network.clone(),
											last_update: Instant::now(),
											sctp: None,
										};
										let mut ssl = Context::new(config.clone());
										ssl.set_timer_callback(Box::new(Timer::new()));
										// Set the *client id* which is really just input to do DTLS cookies.
										let mut temp = [0; 18];
										temp[0..16].copy_from_slice(&cid.ip().octets());
										temp[16..18].copy_from_slice(&cid.port().to_ne_bytes());
										ssl.set_client_transport_id_once(&temp);
										let res = ssl.establish(wrap, None);
										trace!(?res, "ESTABLISH");
										match res {
											Ok(()) => {}
											Err(e) if e.high_level() == Some(SslWantRead) => {}
											// Don't insert the new ssl unless we successfully establish or want more recv data
											// TODO: This isn't correct: if we receive a non DTLS packet then the result would still be SslWantRead.  To fix this, we need to check that the Context's state has advanced past the client hello stage (meaning it must have had a valid DTLS Cookie).
											_ => continue
										}
										*v.insert(connections.insert(ssl))
									}
									Entry::Occupied(entry) => *entry.get(),
								};

								let Some(context) = connections.get_mut(key) else {
									continue
								};

								// Repeatedly Read the DTLS context
								loop {
									let (out_ip, rest) = Ip6Header::mut_from_prefix(decrypted.as_mut_slice()).unwrap();

									let res = context.recv(rest);
									trace!(?res, "DTLS RECV");
									match res {
										Err(e) if e.high_level() == Some(codes::SslWantRead) => break,
										Ok(length) if length > 0 => {
											// Update the send_to address using the last seen src ip and port
											let Wrapper { last_update, send_to, ..} = context.io_mut().unwrap();
											// TODO: handle src tracking to limit src ip+port to a single dtls connection
											*last_update = Instant::now();
											*send_to = sender;

											let length = u16::try_from(length).unwrap();
											out_ip.flags.set(6 << 28);
											out_ip.payload_length.set(length);
											out_ip.next_header = ip_proto::SCTP;
											out_ip.hop_limit = 5;
											out_ip.src = Ipv6Addr::from(&IndexIp { proto: 0x03, site: our_site, index: key as u64 }).octets();
											out_ip.dst = endpoint;
											let tot_len = out_ip.len();
											network.send(&decrypted[..tot_len])?;
										}
										_ => {
											let context = connections.remove(key);
											let Wrapper { send_from, sctp, .. } = context.io().unwrap();
											if let Some(socket) = sctp {
												poll.registry().deregister(&mut SourceFd(&socket.as_raw_fd()))?;
											}
											cids.remove(send_from);
											break
										}
									}
								}
							}
							// Possibly STUN
							(Err(src_ip), ip_proto::UDP, 9.., 0..3) => {
								let (udp, rest) = UdpHeader::mut_from_prefix(rest).unwrap();
								let sender = SocketAddrV6::new(ip.src.into(), udp.src_port.get(), 0, 0);
								let receiver = SocketAddrV6::new(src_ip, udp.dst_port.get(), 0, 0);

								let mut inner = Stun {
									buffer: rest,
								};
								if inner.len() != ip.payload_length.get() as usize - 8 {
									continue;
								}
								if inner.class() != Class::Request || inner.method() != Method::Binding {
									continue;
								}

								// Parse ICE attributes
								let mut username = None;
								let mut integrity = None;
								let mut ice_controlled = None;
								let mut ice_controlling = None;
								let mut priority = None;
								let mut use_candidate = None;
								let mut fingerprint = None;
								let unknowns = inner
									.into_iter()
									.parse::<USERNAME, &str>(&mut username)
									.parse::<MESSAGE_INTEGRITY, Integrity<20>>(&mut integrity)
									.parse::<ICE_CONTROLLED, u64>(&mut ice_controlled)
									.parse::<ICE_CONTROLLING, u64>(&mut ice_controlling)
									.parse::<PRIORITY, u32>(&mut priority)
									.parse::<USE_CANDIDATE, ()>(&mut use_candidate)
									.parse::<FINGERPRINT, ()>(&mut fingerprint)
									.collect_unknown::<1>();

								// Make sure all expected attributes are present and no unexpected attributes exist
								let (None, Some(username), Some(integrity), Some(_), Some(_), Some(())) = (
									unknowns,
									username,
									integrity,
									ice_controlled.xor(ice_controlling),
									priority,
									fingerprint,
								) else {
									continue;
								};

								// Split the username into dst_ufrag and src_ufrag
								let Some((dst_ufrag, _src_ufrag)) = username.split_once(':') else {
									continue;
								};

								// Split the dst_ufrag into dst_pid and src_pid
								let Some((dst_pid, _src_pid)) = dst_ufrag.split_once('+') else {
									continue;
								};

								// Only answer connection tests for our certificate
								if dst_pid != self_pid {
									continue
								}

								let ice_key = b"the/ice/password/constant";
								// Wrong credentials
								if !integrity.verify(ice_key) {
									inner.set_length(0);
									inner.set_class(Class::Error);
									inner.append::<ERROR_CODE, _>(&(441, "")).unwrap();
									inner.append::<FINGERPRINT, _>(&()).unwrap();
								}
								// ICE Controlled - error switch role
								else if ice_controlled.is_some() {
									inner.set_length(0);
									inner.set_class(Class::Error);
									inner.append::<ERROR_CODE, _>(&(487, "")).unwrap();
									inner
										.append::<MESSAGE_INTEGRITY, _>(&ice_key.as_slice())
										.unwrap();
									inner.append::<FINGERPRINT, _>(&()).unwrap();
								}
								// Success
								else {
									inner.set_length(0);
									inner.set_class(Class::Success);
									inner
										.append::<XOR_MAPPED_ADDRESS, SocketAddr>(&sender.into())
										.unwrap();
									inner
										.append::<MESSAGE_INTEGRITY, _>(&ice_key.as_slice())
										.unwrap();
									inner.append::<FINGERPRINT, _>(&()).unwrap();
								}

								// Send the response packet:
								ip.dst = sender.ip().octets();
								ip.src = receiver.ip().octets();
								udp.dst_port.set(sender.port());
								udp.src_port.set(receiver.port());
								ip.payload_length.set(inner.len() as u16 + 8);
								udp.length = ip.payload_length;
								udp.checksum.set(0);
								ip.flags.set(6 << 28);

								// Send the packet
								let length = ip.len();
								let _ = network.send(&buffer[..length]);
								continue;
							}
							// Other
							_ => continue,
						}
					}
					SCTP => {
						// Accept the SCTP Socket, and then associate it with a DTLS Context
						let Ok((socket, proxy_ip)) = sctp.accept() else { break };
						let Some(proxy_ip) = proxy_ip.as_socket_ipv6() else { continue };
						let Ok(IndexIp { proto: 0x03, index, .. }) = proxy_ip.ip().try_into() else { continue };
						let key = index as usize;
						let Some(context) = connections.get_mut(key) else { continue };
						let Ok(Some(cert_list)) = context.peer_cert() else { continue };
						let Ok(()) = context.verify_result() else { continue };
						let Some(cert) = cert_list.iter().next() else { continue };
						let mut fingerprint = [0; 32];
						assert_eq!(hash::Md::hash(hash::Type::Sha256, cert.as_der(), &mut fingerprint)?, 32);
						let pid = to_base62(&mut fingerprint);
						trace!(?pid, ?index, ?fingerprint, ?cert, "SCTP Establish");

						// Configure Unreliable (zero retransmit)
						// let pr_info = libc::sctp_prinfo {
						// 	pr_policy: libc::SCTP_PR_SCTP_RTX as u16,
						// 	pr_value: 0
						// };
						// if 0 != unsafe { libc::setsockopt(
						// 	assoc.as_raw_fd(),
						// 	libc::IPPROTO_SCTP,
						// 	libc::SCTP_DEFAULT_PRINFO,
						// 	from_ref(&pr_info).cast::<c_void>(),
						// 	size_of_val(&pr_info) as libc::socklen_t
						// ) } {
						// 	continue
						// }

						// Configure stream 1, unordered, and a binary data type
						let snd_info = libc::sctp_sndinfo {
							snd_sid: 1,
							snd_flags: libc::SCTP_UNORDERED as u16,
							snd_ppid: 53_u32.to_be() /* WebRTC Binary PPID */,
							snd_context: 0,
							snd_assoc_id: 0,
						};
						if 0 != unsafe { libc::setsockopt(
							socket.as_raw_fd(),
							libc::IPPROTO_SCTP,
							libc::SCTP_DEFAULT_SNDINFO,
							from_ref(&snd_info).cast::<c_void>(),
							size_of_val(&snd_info) as libc::socklen_t
						) } {
							continue
						}
						socket.set_nonblocking(true)?;
						poll.registry().register(&mut SourceFd(&socket.as_raw_fd()), Token(key), Interest::READABLE)?;
						let wrapper = context.io_mut().unwrap();
						wrapper.sctp = Some(socket);
					}
					// Data available on a split-off SCTP Socket
					Token(key) => {
						let context = connections.get(key).unwrap();
						let Some(Wrapper { sctp: Some(socket), .. }) = context.io() else { unreachable!() };
						let mut socket = socket;

						let mut buffer = recv_buffer.borrow_mut();
						let Ok(length) = socket.read(buffer.as_mut_slice()) else { break };

						trace!(?length, "VPN Packet");
						let (ip, _rest) = Ip6Header::mut_from_prefix(buffer.as_mut_slice()).unwrap();
						if ip.flags.get() >> 28 != 6 { continue }
						if ip.len() != length { continue }
						let exp_src = Ipv6Addr::from(&IndexIp { proto: 0x04, site: our_site, index: key as u64}).octets();

						// TODO: Just drop the packet here, but send a reliable JSON configuration message containing your assigned ip address when we first split-off the SCTP association.
						if ip.src != exp_src {
							ip.dst = exp_src;
							ip.src = [0; 16];
							ip.payload_length.set(0);
							ip.next_header = 0xff;
							let len = ip.len();

							trace!(packet = &buffer[..len], "Discover");
							socket.write(&buffer[..len])?;
							continue
						}
						trace!(packet = &buffer[..length], "Out");
						let _ = network.send(&buffer[..length]);
					},
				}
			}
		}
		poll.poll(&mut events, Some(cleanup))?;
	}
}
