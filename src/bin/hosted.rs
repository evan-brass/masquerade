use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::io::{IoSlice, Write};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::ptr::{null_mut, write_unaligned, NonNull};
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
use num_bigint::BigUint;
use socket2::{Domain, MaybeUninitSlice, MsgHdr, MsgHdrMut, Protocol, Socket, Type};
use tappers::Tun;
use tempfile::NamedTempFile;
use tracing_subscriber::EnvFilter;
use tracing::{info, trace, debug};
use masquerade::wire::{ip_proto, DcepOpenHeader, FromBytes, IntoBytes, Ip6Header, UdpHeader};
use tappers::Interface;
use masquerade::stun::{Stun, Class, Method, attr::*, attr::integrity::Integrity, attr::parse::AttrIter as _};
use std::net::SocketAddr;
use slab::Slab;
use core::ptr::from_ref;
use core::ffi::{c_void, c_int, c_uint};
use masquerade::ip::IndexIp;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "cert.pem")]
	cert_file: String,

	#[arg(long, short, default_value = "[fd00:1::]:5000")]
	sctp: String,

	#[arg(long, short, default_value = "stun.evan-brass.net.")]
	hostname: String,

	#[arg(long, short)]
	if_name: Option<String>,
}


struct RcvInfo {
	inner: libc::sctp_rcvinfo,
}
impl RcvInfo {
	fn from_control(control: &mut Vec<u8>) -> Option<Self> {
		let msghdr = libc::msghdr {
			msg_name: null_mut(),
			msg_namelen: 0,
			msg_iov: null_mut(),
			msg_iovlen: 0,
			msg_control: control.as_mut_ptr().cast::<c_void>(),
			msg_controllen: control.len(),
			msg_flags: 0
		};
		let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
		while let Some(mut ptr) = NonNull::new(cmsg) {
			let libc::cmsghdr {
				cmsg_level,
				cmsg_type,
				..
			} = unsafe { ptr.read_unaligned() };
			trace!(?cmsg_level, ?cmsg_type, "CMSG");
			match (cmsg_level, cmsg_type) {
				(libc::IPPROTO_SCTP, libc::SCTP_RCVINFO) => {
					let inner = unsafe { libc::CMSG_DATA(ptr.as_mut()).cast::<libc::sctp_rcvinfo>().read_unaligned() };
					return Some(Self { inner });
				}
				_ => {}
			}
			cmsg = unsafe { libc::CMSG_NXTHDR(&msghdr, cmsg) };
		}
		None
	}
}

struct SndInfo {
	inner: libc::sctp_sndinfo,
	pr_info: Option<libc::sctp_prinfo>,
}
impl SndInfo {
	fn to_control(&self, control: &mut Vec<u8>) {
		let len = unsafe {
			libc::CMSG_SPACE(size_of::<libc::sctp_sndinfo>() as c_uint) +
			self.pr_info.map_or(0, |_| libc::CMSG_SPACE(size_of::<libc::sctp_prinfo>() as c_uint))
		};
		control.clear();
		control.reserve(len as usize);
		let msghdr = libc::msghdr {
			msg_name: null_mut(),
			msg_namelen: 0,
			msg_iov: null_mut(),
			msg_iovlen: 0,
			msg_control: control.as_mut_ptr().cast::<c_void>(),
			msg_controllen: control.capacity(),
			msg_flags: 0
		};
		unsafe {
			let cmsg = libc::CMSG_FIRSTHDR(&msghdr);
			write_unaligned(cmsg, libc::cmsghdr {
				cmsg_level: libc::IPPROTO_SCTP,
				cmsg_type: libc::SCTP_SNDINFO,
				cmsg_len: libc::CMSG_LEN(size_of::<libc::sctp_sndinfo>() as c_uint) as usize
			});
			write_unaligned::<libc::sctp_sndinfo>(libc::CMSG_DATA(cmsg).cast(), self.inner);

			if let Some(pr_info) = self.pr_info {
				let cmsg = libc::CMSG_NXTHDR(&msghdr, cmsg);
				write_unaligned(cmsg, libc::cmsghdr {
					cmsg_level: libc::IPPROTO_SCTP,
					cmsg_type: libc::SCTP_PRINFO,
					cmsg_len: libc::CMSG_LEN(size_of::<libc::sctp_prinfo>() as c_uint) as usize
				});
				write_unaligned::<libc::sctp_prinfo>(libc::CMSG_DATA(cmsg).cast(), pr_info);
			}

			// Mark the control data as initialized (VERY IMPORTANT, because the vec length will be used as the msg_controllen later!)
			control.set_len(len as usize);
		}
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
	sctp: Option<(Socket, String)>,
}
impl Io for Wrapper {
	fn recv(&mut self, buf: &mut [u8]) -> mbedtls::Result<usize> {
		let would_block = Err(mbedtls::Error::HighLevel(codes::SslWantRead));
		let Ok(mut buffer) = self.recv_buffer.try_borrow_mut() else { return  would_block };
		let (ip, rest) = Ip6Header::mut_from_prefix(&mut buffer).unwrap();
		if ip.flags.version() != 6 { return would_block }
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

		ip.flags.set_version(6);
		ip.flags.set_traffic_class(0);
		ip.flags.set_flow_label(0);
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

	let mut self_fingerprint = [0; 32];
	assert_eq!(hash::Md::hash(hash::Type::Sha256, cert.as_der(), &mut self_fingerprint)?, 32);
	let self_pid = BigUint::from_bytes_be(&self_fingerprint).to_str_radix(36);
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

	// TODO: Figure out buffer lengths and stuff.
	let mut sctp_buffer = Vec::with_capacity(4096);
	let mut sctp_control = Vec::with_capacity(2048);

	// Connection state
	let mut cids: BTreeMap<SocketAddrV6, usize> = BTreeMap::new();
	let mut connections: Slab<Context<Wrapper>> = Slab::new();
	// TODO: Keep a map from (src ip, src port) -> dst ip so that we limit each src socket addr to 1 DTLS connection.

	// Cleanup state
	let timeout = Duration::from_secs(60 * 2);
	let cleanup = Duration::from_secs(30);
	let mut last_cleanup = Instant::now();

	// nsupdate stuff
	let hostname = args.hostname;

	loop {
		// Periodically Cleanup the connections
		if last_cleanup.elapsed() > cleanup {
			cids.retain(|_cid, key| {
				let Some(context) = connections.get_mut(*key) else {
					return false;
				};
				let Wrapper { last_update, sctp, .. } = context.io_mut().unwrap();
				if last_update.elapsed() < timeout { return true }

				let allocated = Ipv6Addr::from(&IndexIp { proto: 0x04, site: our_site, index: *key as u64 });
				if let Some((socket, pid)) = sctp.take() {
					// nsupdate remove the pid -> allocated record
					let mut operations_file = NamedTempFile::new().expect("Failed tempfile");
					// TODO: Add a TXT entry that's "data:application/x-x509-user-cert;base64,<certificate der as base64>"
					operations_file.write_fmt(format_args!(
"update delete {pid}.{hostname} 60 AAAA {allocated}
send
quit
")).expect("Failed to write ops file");
					operations_file.flush()
						.expect("Failed to flush ops file");
					let status = Command::new("nsupdate")
						.arg("-l")
						.arg(operations_file.path())
						.status()
						// TODO: Move expect to an error?
						.expect("nsupdate failed");
					trace!(?status, "nsupdate");
					if !status.success() {
						panic!("nsupdate failed: {status}");
					}

					poll.registry().deregister(&mut SourceFd(&socket.as_raw_fd())).expect("Failed to deregister SCTP socket during register.");
				}
				connections.remove(*key);

				false
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
						if ip.flags.version() != 6 { continue }
						if ip.len() != length { continue }

						match (IndexIp::try_from(&Ipv6Addr::from(ip.dst)), ip.next_header, ip.payload_length.get(), rest[8]) {
							// Traffic for VPN Allocations
							(Ok(IndexIp { proto: 0x04, index, .. }), _, _, _) => {
								let Some(context) = connections.get_mut(index as usize) else { continue };
								let Wrapper { sctp, .. } = context.io_mut().unwrap();
								let Some((socket, _pid)) = sctp else { continue };

								SndInfo {
									pr_info: Some(libc::sctp_prinfo {
										pr_policy: libc::SCTP_PR_SCTP_RTX as u16,
										pr_value: 0,
									}),
									inner: libc::sctp_sndinfo {
										snd_sid: 1,
										snd_flags: libc::SCTP_UNORDERED as u16,
										snd_ppid: u32::to_be(53),
										snd_context: 0,
										snd_assoc_id: 0,
									},
								}.to_control(&mut sctp_control);

								// Relay the IPv6 packet as SCTP data
								trace!(packet = &buffer[..length], ?index, "In");
								let iovec = [IoSlice::new(&buffer[..length])];
								let msg = MsgHdr::new()
									.with_buffers(&iovec)
									.with_control(&sctp_control);

								let _ = socket.sendmsg(&msg, libc::MSG_EOR);
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
										let mut context = connections.remove(key);
										let Wrapper { send_from, sctp, .. } = context.io_mut().unwrap();

										let allocated = Ipv6Addr::from(&IndexIp { proto: 0x04, site: our_site, index });
										if let Some((socket, pid)) = sctp.take() {
											// nsupdate remove the pid -> allocated record
											let mut operations_file = NamedTempFile::new()?;
											// TODO: Add a TXT entry that's "data:application/x-x509-user-cert;base64,<certificate der as base64>"
											operations_file.write_fmt(format_args!(
"update delete {pid}.{hostname} 60 AAAA {allocated}
send
quit
"))?;
											operations_file.flush()?;
											let status = Command::new("nsupdate")
												.arg("-l")
												.arg(operations_file.path())
												.status()?;
											trace!(?status, "nsupdate");
											if !status.success() {
												return Err(eyre!("nsupdate failed: {status}"));
											}

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
											out_ip.flags.set_version(6);
											out_ip.flags.set_traffic_class(0);
											out_ip.flags.set_flow_label(0);
											out_ip.payload_length.set(length);
											out_ip.next_header = ip_proto::SCTP;
											out_ip.hop_limit = 5;
											out_ip.src = Ipv6Addr::from(&IndexIp { proto: 0x03, site: our_site, index: key as u64 }).octets();
											out_ip.dst = endpoint;
											let tot_len = out_ip.len();
											network.send(&decrypted[..tot_len])?;
										}
										_ => {
											let mut context = connections.remove(key);
											let Wrapper { send_from, sctp, .. } = context.io_mut().unwrap();
											let allocated = Ipv6Addr::from(&IndexIp { proto: 0x04, site: our_site, index: key as u64 });
											if let Some((socket, pid)) = sctp.take() {
												// nsupdate remove the pid -> allocated record
												let mut operations_file = NamedTempFile::new()?;
												// TODO: Add a TXT entry that's "data:application/x-x509-user-cert;base64,<certificate der as base64>"
												operations_file.write_fmt(format_args!(
"update delete {pid}.{hostname} 60 AAAA {allocated}
send
quit
"))?;
												operations_file.flush()?;
												let status = Command::new("nsupdate")
													.arg("-l")
													.arg(operations_file.path())
													.status()?;
												trace!(?status, "nsupdate");
												if !status.success() {
													return Err(eyre!("nsupdate failed: {status}"));
												}

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
								ip.flags.set_version(6);
								ip.flags.set_traffic_class(0);
								ip.flags.set_flow_label(0);

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
						let pid = BigUint::from_bytes_be(&fingerprint).to_str_radix(36);
						trace!(?index, ?pid, ?cert, "SCTP Establish");

						// Enable receiving SCTP message info in the control buffer (ppid, stream id, etc.)
						let enable: c_int = 1;
						if 0 != unsafe { libc::setsockopt(
							socket.as_raw_fd(),
							libc::IPPROTO_SCTP,
							libc::SCTP_RECVRCVINFO,
							from_ref(&enable).cast::<c_void>(),
							size_of_val(&enable) as libc::socklen_t
						)} {
							debug!("FAILED SOCKOPT");
							continue;
						}
						socket.set_nonblocking(true)?;

						// Open a WebRTC DataChannel using stream 1 with unreliable, unordered semantics, label = your allocated IP, protocol is IP6
						SndInfo {
							pr_info: None,
							inner: libc::sctp_sndinfo {
								snd_sid: 1,
								snd_flags: 0,
								snd_ppid: u32::to_be(50),
								snd_context: 0,
								snd_assoc_id: 0,
							},
						}.to_control(&mut sctp_control);

						// Relay the IPv6 packet as SCTP data
						let allocated = Ipv6Addr::from(&IndexIp { proto: 0x04, site: our_site, index });
						let label = format!("{}", allocated);
						let protocol = "IPv6";
						let dcep_header = DcepOpenHeader {
							msg_typ: 0x03 /* DCEP_CHANNEL_OPEN */,
							channel_typ: 0x81 /* CHANNEL_TYPE_PARTIAL_RELIABLE_REXMIT_UNORDERED */,
							priority: 1024.into() /* extra high */,
							reliability_parameter: 0.into(),
							label_len: (label.len() as u16).into(),
							protocol_len: (protocol.len() as u16).into()
						};
						let dcep = [
							IoSlice::new(dcep_header.as_bytes()),
							IoSlice::new(label.as_bytes()),
							IoSlice::new(protocol.as_bytes()),
						];

						let msg = MsgHdr::new()
							.with_buffers(&dcep)
							.with_control(&sctp_control);

						let res = socket.sendmsg(&msg, libc::MSG_EOR);
						trace!(?res, "DCEP SEND");

						poll.registry().register(&mut SourceFd(&socket.as_raw_fd()), Token(key), Interest::READABLE)?;
						let wrapper = context.io_mut().unwrap();

						// nsupdate the pid -> allocated
						let mut operations_file = NamedTempFile::new()?;
						// TODO: Add a TXT entry that's "data:application/x-x509-user-cert;base64,<certificate der as base64>"
						operations_file.write_fmt(format_args!(
"update add {pid}.{hostname} 60 AAAA {allocated}
send
quit
"))?;
						operations_file.flush()?;
						let status = Command::new("nsupdate")
							.arg("-l")
							.arg(operations_file.path())
							.status()?;
						trace!(?status, "nsupdate");
						if !status.success() {
							return Err(eyre!("nsupdate add failed {status:?}"));
						}

						// Store the socket on the context
						wrapper.sctp = Some((socket, pid));
					}
					// Data available on a split-off SCTP Socket
					Token(key) => {
						let context = connections.get_mut(key).unwrap();
						let Some(Wrapper { sctp, .. }) = context.io_mut() else { unreachable!() };
						let Some((socket, _pid)) = sctp.as_ref() else { unreachable!() };

						sctp_buffer.clear();
						sctp_control.clear();

						let mut iov = [MaybeUninitSlice::new(sctp_buffer.spare_capacity_mut())];
						let mut msg = MsgHdrMut::new()
							.with_buffers(iov.as_mut_slice())
							.with_control(sctp_control.spare_capacity_mut());
						let Ok(length) = socket.recvmsg(&mut msg, 0) else { break };
						let control_len = msg.control_len();

						if msg.flags().is_truncated() { continue }
						if !msg.flags().is_end_of_record() { continue }

						// Mark data as initialized
						unsafe {
							sctp_buffer.set_len(length);
							sctp_control.set_len(control_len);
						}
						trace!(?sctp_buffer, ?sctp_control, "SCTP MSG");

						let Some(RcvInfo { inner: libc::sctp_rcvinfo {
							rcv_sid: sid,
							rcv_ppid: ppid,
							..
						} }) = RcvInfo::from_control(&mut sctp_control) else { continue };
						trace!(?sid, ?ppid, ?length, "DataChannel Message");

						// Currently only handle Binary messages on stream 1 (Our VPN channel)
						if sid != 1 || ppid != u32::to_be(53) { continue }

						let Ok((ip, _rest)) = Ip6Header::mut_from_prefix(sctp_buffer.as_mut_slice()) else {
							continue
						};
						if ip.flags.version() != 6 { continue }
						if ip.len() != length { continue }
						let exp_src = Ipv6Addr::from(&IndexIp { proto: 0x04, site: our_site, index: key as u64}).octets();
						// Verify that the src ip is what we've allocated to this client:
						if ip.src != exp_src { continue };
						trace!(packet = &sctp_buffer[..length], "Out");
						let _ = network.send(&sctp_buffer[..length]);
					},
				}
			}
		}
		poll.poll(&mut events, Some(cleanup))?;
	}
}
