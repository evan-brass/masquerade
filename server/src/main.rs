use std::collections::VecDeque;
use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::net::UdpSocket;
use std::{
	thread::sleep,
	time::{Duration, Instant},
};

use openssl::ssl::{ErrorCode, SslStream};
use openssl::{
	error::ErrorStack,
	ex_data::Index,
	hash::MessageDigest,
	pkey::PKey,
	sign::{Signer, Verifier},
	ssl::{Ssl, SslAcceptor, SslMethod, SslRef, SslVerifyMode},
	x509::X509,
};
use rand::{random, thread_rng, RngCore};

use sctp::{Chunk, Data, Init, Param, Sack, Sctp};
use stun::{attr::integrity::Integrity, attr::parse::AttrIter as _, attr::*, Class, Method, Stun};

const B62_CHARSET: &[char] = &[
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
	'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
	'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
	'5', '6', '7', '8', '9',
];
fn to_base62(fingerprint: &mut [u8]) -> Option<String> {
	let mut res = [0; 43];
	for j in (0..43).rev() {
		let mut remainder = 0;
		for i in 0..32 {
			let v = 256 * remainder + fingerprint[i] as u32;
			remainder = v % 62;
			fingerprint[i] = (v / 62) as u8;
		}
		res[j] = remainder as u8;
	}

	let mut ret = String::new();
	ret.try_reserve(43).ok()?;

	for i in res {
		if ret.is_empty() && i == 0 {
			continue;
		}
		ret.push(B62_CHARSET[i as usize]);
	}
	if ret.is_empty() {
		ret.push('A');
	}

	Some(ret)
}

const HOSTED: SocketAddrV6 = SocketAddrV6::new(Ipv4Addr::BROADCAST.to_ipv6_mapped(), 3478, 0, 0);

fn send(sock: &UdpSocket, buf: &[u8], receiver: SocketAddrV6) -> io::Result<usize> {
	// Send the message:
	let ret = sock.send_to(buf, receiver)?;

	// Sleep ~1 ms per 40 bytes sent to cap send bandwidth
	sleep(Duration::from_millis(1 + ret as u64 / 40));

	Ok(ret)
}

struct Wrapper<'i> {
	// Used to clear old connections
	#[allow(unused)] // TODO: Cleanup Contexts if they haven't received data in a few minutes
	last_recv: Instant,

	// ufrag mapping of the peer's certificate
	pid: Option<String>,

	// Address that the hadshake was performed from
	init_addr: SocketAddrV6,

	// Address that data was last received from
	data_addr: SocketAddrV6,

	// 1 packet of recv data yet to be read by openssl
	input: VecDeque<u8>,

	// Handle to the UdpSocket so we can implement write on Wrapper
	sock: &'i UdpSocket,

	// Minimum required SCTP data (remote vtag, local tsn)
	sctp_data: Option<(u32, u32)>,
}
impl io::Read for Wrapper<'_> {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		match self.input.read(buf) {
			// Make read async:
			Ok(0) => Err(io::Error::new(io::ErrorKind::WouldBlock, "")),
			r => r,
		}
	}
}
impl io::Write for Wrapper<'_> {
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		let mut ind = Stun::new([0; 2048]);
		ind.set_class(Class::Indication);
		ind.set_method(Method::Data);
		ind.set_cookie(0x2112a442);
		thread_rng().fill_bytes(ind.set_txid());
		ind.append::<XOR_PEER_ADDRESS, SocketAddr>(&HOSTED.into())
			.map_err(io::Error::other)?;
		ind.append::<DATA, _>(&buf).map_err(io::Error::other)?;

		let packet = &ind.buffer[..ind.len()];

		send(self.sock, packet, self.data_addr)
	}
}

// Constants used by this server
const TURN_REALM: &str = "none";
const TURN_NONCE: &str = "none";
const TURN_USER: &str = "guest";
// turn_key = md5("guest:none:password")
const TURN_KEY: &[u8] = &[
	0x01, 0x5c, 0x8a, 0x97, 0x3e, 0xa4, 0xb4, 0xa9, 0xc9, 0x45, 0xf6, 0x90, 0x14, 0x2b, 0xf3, 0xad,
];
const ICE_KEY: &[u8] = b"the/ice/password/constant";

fn dtls_cookies() -> Result<
	(
		Index<Ssl, SocketAddrV6>,
		impl Fn(&mut SslRef, &mut [u8]) -> Result<usize, ErrorStack>,
		impl Fn(&mut SslRef, &[u8]) -> bool,
	),
	ErrorStack,
> {
	let startup = Instant::now();
	let digest = MessageDigest::sha1();
	let index = Ssl::new_ex_index()?;
	let cookie_expiration = 1000 * 60 * 2;
	let keys = PKey::hmac(&random::<[u8; 16]>())?;
	let keyv = keys.clone();
	Ok((
		index,
		move |ssl: &mut SslRef, output: &mut [u8]| {
			let addr = ssl.ex_data(index).unwrap();
			let mut signer = Signer::new(digest, &keys)?;

			let serial = (startup.elapsed().as_millis() as u32).to_be_bytes();
			signer.update(&serial)?;
			signer.update(&addr.ip().octets())?;
			signer.update(&addr.port().to_be_bytes())?;

			let (serial_dst, signature) = output.split_at_mut(4);
			serial_dst.copy_from_slice(&serial);

			Ok(4 + signer.sign(signature)?)
		},
		move |ssl: &mut SslRef, input: &[u8]| {
			let addr = ssl.ex_data(index).unwrap();
			if input.len() < 4 {
				return false;
			}
			let (serial, signature) = input.split_at(4);
			// Check the expiration of the serial
			if startup.elapsed().as_millis()
				> u32::from_be_bytes(serial.try_into().unwrap()) as u128 + cookie_expiration
			{
				return false;
			}
			let Ok(mut verifier) = Verifier::new(digest, &keyv) else {
				return false;
			};
			verifier.update(serial).is_ok()
				&& verifier.update(&addr.ip().octets()).is_ok()
				&& verifier.update(&addr.port().to_be_bytes()).is_ok()
				&& verifier.verify(signature).unwrap_or(false)
		},
	))
}

fn main() -> Result<std::convert::Infallible, std::io::Error> {
	// Configure our DTLS server
	let pem = std::fs::read("cert.pem")?;
	let certificate = X509::from_pem(&pem)?;
	let pkey = PKey::private_key_from_pem(&pem)?;

	// Figure out what our ufrag is
	let mut fingerprint = certificate.digest(MessageDigest::sha256())?;
	let ice_ufrag = to_base62(&mut fingerprint).unwrap();
	println!("Our ufrag: {ice_ufrag}");

	// Configure a DTLS server
	let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::dtls())?;
	acceptor.set_certificate(&certificate)?;
	acceptor.set_private_key(&pkey)?;
	acceptor.check_private_key()?;
	let mut mode = SslVerifyMode::PEER;
	mode.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
	acceptor.set_verify_callback(mode, |_preverify, _cert_store| {
		// TODO: Check certificate expiration?
		true
	});

	// Get a slot to hold the socketaddress so that we can generate and check dtls cookies:
	let (addr_index, generate, verify) = dtls_cookies()?;
	acceptor.set_cookie_generate_cb(generate);
	acceptor.set_cookie_verify_cb(verify);
	let acceptor = acceptor.build();

	// Cleanup stuff
	let mut last_cleanup = Instant::now();

	// Network stuff
	let sock = UdpSocket::bind("[::]:3478")?;
	let mut buffer = [0; 2048];
	let dtls_mtu = buffer.len() - 20 - 4 - 24; // dtls is always encapsulated inside TURN so...

	// Connections sorted by socket address
	let mut connections: Vec<SslStream<Wrapper<'_>>> = Vec::new();
	// TODO: Add a second vec sorted by pid to accelerate forwarding

	'packet_loop: loop {
		let (len, SocketAddr::V6(sender)) = sock.recv_from(&mut buffer)? else {
			continue;
		};

		// Perform a cleanup every 2 min:
		if last_cleanup.elapsed().as_secs() > 60 * 2 {
			last_cleanup = Instant::now();
			// Iterate through the connections and drop any that haven't received data in 4 min
			connections.retain_mut(|ctx| ctx.get_ref().last_recv.elapsed().as_secs() < 4 * 60);
		}

		let mut msg = Stun::new(buffer.as_mut_slice());
		if msg.len() != len {
			continue;
		}

		// Canonical socket address (ipv6-mapped -> ipv4)
		let canonical = SocketAddr::new(sender.ip().to_canonical(), sender.port());

		let mut receiver = sender;

		// Parse TURN attributes
		let mut username = None;
		let mut realm = None;
		let mut integrity = None;
		let mut nonce = None;
		let mut lifetime = None;
		let mut requested_transport = None;
		let mut channel = None;
		let mut xor_peer = None;
		let mut data = None;
		let unknown_attrs = msg
			.into_iter()
			.parse::<USERNAME, &str>(&mut username)
			.parse::<REALM, &str>(&mut realm)
			.parse::<MESSAGE_INTEGRITY, Integrity<20>>(&mut integrity)
			.parse::<NONCE, &str>(&mut nonce)
			.parse::<LIFETIME, u32>(&mut lifetime)
			.parse::<REQUESTED_TRANSPORT, u8>(&mut requested_transport)
			.parse::<CHANNEL_NUMBER, u16>(&mut channel)
			.parse::<XOR_PEER_ADDRESS, SocketAddr>(&mut xor_peer)
			.parse::<DATA, &[u8]>(&mut data)
			.collect_unknown::<8>();

		match (msg.class(), msg.method()) {
			// Unknown Method
			(Class::Request, meth)
				if ![
					Method::Binding,
					Method::Allocate,
					Method::Refresh,
					Method::CreatePermission,
					Method::ChannelBind,
				]
				.contains(&meth) =>
			{
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(404, "")).unwrap(); // Error code is not in the spec, but we don't care.
			}

			// Unknown Attributes
			(Class::Request, _) if unknown_attrs.is_some() => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(420, "")).unwrap();
				msg.append::<UNKNOWN_ATTRIBUTES, _>(&unknown_attrs.unwrap())
					.unwrap();
			}

			// Binding Request
			(Class::Request, Method::Binding) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical).unwrap();
			}

			// All future requests require authentication:
			// - Realm or nonce missing / wrong
			(Class::Request, _) if realm != Some(TURN_REALM) || nonce != Some(TURN_NONCE) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(401, "")).unwrap();
				msg.append::<REALM, _>(&TURN_REALM).unwrap();
				msg.append::<NONCE, _>(&TURN_NONCE).unwrap();
			}
			// - Wrong Username or Password
			(Class::Request, _)
				if username != Some(TURN_USER)
					|| !integrity.is_some_and(|i| i.verify(TURN_KEY)) =>
			{
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(441, "guest:none:password"))
					.unwrap();
			}

			// Allocate
			// - Wrong transport
			(Class::Request, Method::Allocate) if requested_transport != Some(17) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(442, "")).unwrap();
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).unwrap();
			}
			// - Normal
			(Class::Request, Method::Allocate) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical).unwrap();
				msg.append::<XOR_RELAYED_ADDRESS, SocketAddr>(&sender.into())
					.unwrap();
				msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000))
					.unwrap();
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).unwrap();
			}

			// Refresh
			// - Close connection (No response is needed)
			(Class::Request, Method::Refresh) if lifetime == Some(0) => continue,
			// - Normal
			(Class::Request, Method::Refresh) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000))
					.unwrap();
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).unwrap();
			}

			// Create Permission
			(Class::Request, Method::CreatePermission) => {
				// We don't enforce permissions so... success.
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).unwrap();
			}

			// Channel Bind
			(Class::Request, Method::ChannelBind) => {
				// Instead of supporting channels (which would require storing state) we send a nonsensical - but seemingly nonfatal - error to placate Chrome.
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(438, "")).unwrap();
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).unwrap();
			}

			// Send
			(Class::Indication, Method::Send) => {
				if let (Some(SocketAddr::V6(peer)), Some(data)) = (xor_peer, data) {
					// [ STUN Header | XOR Peer Attr | Data... ]

					// Shift the data attribute to where we want it
					let mut len = data.len();
					let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
					msg.buffer.copy_within(i..i + 4 + len, 44);
					msg.set_length(0);
					msg.set_method(Method::Data);

					// Write the peer address into the space we made by shifting the data attribute
					if peer == HOSTED {
						msg.append::<XOR_PEER_ADDRESS, SocketAddr>(&HOSTED.into())
							.unwrap();
					} else {
						msg.append::<XOR_PEER_ADDRESS, SocketAddr>(&sender.into())
							.unwrap();
						receiver = peer;
					}

					// Reborrow the data from its new location
					let data: &mut [u8] = &mut msg.buffer[48..][..len];

					// Peek inside the Packet
					match (peer, data.first()) {
						// Hosted STUN
						(HOSTED, Some(0..20)) => {
							let mut inner = Stun::new(&mut msg.buffer[48..]);
							if inner.len() != len {
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

							// Only handle ICE connection tests
							if inner.class() != Class::Request || inner.method() != Method::Binding
							{
								continue;
							}

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

							// Answer the ICE connection test ourself if it is addressed to us
							if dst_ufrag == ice_ufrag {
								// Wrong credentials
								if !integrity.verify(&ICE_KEY) {
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
									inner.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).unwrap();
									inner.append::<FINGERPRINT, _>(&()).unwrap();
								}
								// Success
								else {
									inner.set_length(0);
									inner.set_class(Class::Success);
									inner
										.append::<XOR_MAPPED_ADDRESS, SocketAddr>(&sender.into())
										.unwrap();
									inner.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).unwrap();
									inner.append::<FINGERPRINT, _>(&()).unwrap();
								}
								len = inner.len();
							}
							// If the ICE test isn't addressed to us, then encapsulate it and pass it along
							else {
								// Look for a DTLS session where base64(fingerprint(peer cert)) == dst
								// TODO: Accelerate this using a map from pid -> context?
								let Some(context) = connections.iter_mut().find(|context| {
									context
										.get_ref()
										.pid
										.as_ref()
										.is_some_and(|pid| pid == dst_ufrag)
								}) else {
									continue;
								};
								// Get the SCTP state for this session:
								let Some((vtag, ref mut tsn)) = context.get_mut().sctp_data else {
									continue;
								};

								// Truncate the ICE connection test to remove the fingerprint attribute (I wish it wasn't even there to begin with)
								let trunc_length = integrity.mac.as_ptr() as usize
									- inner.buffer.as_ptr() as usize
									- 20 + 20; // -20 to remove STUN header, +20 to include the 20byte sha-1 value
								inner.set_length(trunc_length as u16);

								// Append the peer address to the inner packet:
								let Ok(_) =
									inner.append::<XOR_PEER_ADDRESS, SocketAddr>(&sender.into())
								else {
									continue;
								};

								// Ok, start eating the old TURN packet and turning it into an SCTP packet with a single data chunk:
								// NOTE: There's no copy into the DATA chunk, because the STUN data is already there, we just wrap that data chunk around the existing packet
								let data_len = 16 + inner.len();
								let mut data = Data {
									chunk: Chunk {
										buffer: &mut buffer[32..],
									},
								};

								// Data Chunk:
								data.chunk.set_typ(0);
								data.chunk.set_flags(0b111); // Unordered, begin, end
								data.chunk.set_length(data_len as u16);
								// TODO: Write and increment the TSN
								data.set_tsn(*tsn);
								*tsn = tsn.wrapping_add(1);
								data.set_stream(0);
								data.set_seq(42); // Unused
								data.set_ppid(53); // PPID for Binary WebRTC messages = 53

								// SCTP header:
								let mut packet = Sctp {
									buffer: &mut buffer[20..],
								};
								packet.set_dport(5000);
								packet.set_sport(5000);
								packet.set_vtag(vtag);
								let packet_len = 12 + data_len;
								packet.set_chksum(packet.expected_chksum(packet_len));

								// TODO: Check the error
								let _ = context.ssl_write(&buffer[20..][..packet_len]);

								// Don't send a TURN STUN message, the DTLS layer handles sending the encrypted application data
								continue;
							}
						}

						// Hosted DTLS
						(HOSTED, Some(20..64)) => {
							// Look for the DTLS context
							let loc = connections
								.binary_search_by_key(&sender, |s| s.get_ref().init_addr);
							let i = loc.unwrap_or_else(|i| i);

							// Create a new DTLS context if needed:
							if loc.is_err() && data[0] == 22 && connections.try_reserve(1).is_ok() {
								// Create a new DTLS context:
								let Ok(mut ssl) = Ssl::new(acceptor.context()) else {
									continue;
								};
								let mut input = VecDeque::new();
								let Ok(_) = input.try_reserve_exact(dtls_mtu) else {
									continue;
								};
								ssl.set_ex_data(addr_index, sender);
								ssl.set_accept_state();
								let Ok(context) = SslStream::new(
									ssl,
									Wrapper {
										init_addr: sender,
										data_addr: sender,
										input,
										last_recv: Instant::now(),
										pid: None,
										sock: &sock,
										sctp_data: None,
									},
								) else {
									continue;
								};

								// Good, insert the new connection
								connections.insert(i, context);
							}

							// Give the packet to every context: Update the address of the first connection that reads data from the packet.
							for j in 0..connections.len() {
								let context = &mut connections[j];

								// Copy the packet into the recv buffer:
								context.get_mut().input.extend(data.iter().cloned());

								// New buffer I guess
								let mut buffer = [0; 2048];

								// Read SSL data until it wants more data, then clear the input just to be sure
								loop {
									match context.ssl_read(&mut buffer) {
										// SCTP packets are at least 12 bytes and my code will panic when checking the crc if n < 12
										Ok(n) if n > 12 => {
											// Update the pid if needed:
											if context.get_ref().pid.is_none() {
												let Some(peer_cert) =
													context.ssl().peer_certificate()
												else {
													connections.remove(j);
													continue 'packet_loop;
												};
												let Ok(mut fingerprint) =
													peer_cert.digest(MessageDigest::sha256())
												else {
													connections.remove(j);
													continue 'packet_loop;
												};
												let Some(pid) = to_base62(&mut fingerprint) else {
													connections.remove(j);
													continue 'packet_loop;
												};
												println!("Connected: {pid}");
												context.get_mut().pid = Some(pid);
											}

											let wrapper = context.get_mut();
											wrapper.last_recv = Instant::now();
											wrapper.data_addr = sender;

											let recv = Sctp {
												buffer: &mut buffer,
											};
											if recv.sport() != 5000 || recv.dport() != 5000 {
												continue 'packet_loop;
											}
											if recv.chksum() != recv.expected_chksum(n) {
												continue 'packet_loop;
											}

											// Gather info for a response:
											let mut sack = None;
											let mut init_ack = false;
											let mut cookie_ack = false;
											// TODO: Heartbeat ack and such

											// Work through the chunks in the SCTP packet and reply with appropriate chunks of our own (We you don't know how to allocate memory like me, this is vastly harder then it sounds *sobs* *screams* *inflicts self torture*):
											let mut offset = 12;
											while offset + Chunk::min_len() <= n {
												let chunk = Chunk {
													buffer: &mut buffer[offset..],
												};
												if chunk.len() < Chunk::min_len() {
													break;
												}

												// Check that the chunk fits within the data we've received
												offset += chunk.len();
												if offset > n {
													break;
												}

												// Handle the chunk:
												match chunk.typ() {
													// Data Chunk
													0 if chunk.len() >= Data::min_len() => {
														let data = Data { chunk };

														// Update our cumtsn to acknowledge this data (if needed)
														if sack.is_none_or(|cumtsn| {
															cumtsn < data.tsn()
														}) {
															sack = Some(data.tsn());
														}

														// Print the data to the logs:
														let bytes = &data.chunk.buffer
															[16..data.chunk.length() as usize];
														if let Ok(s) = std::str::from_utf8(bytes) {
															println!(
																"peer data {:?} {} {}: {:?}",
																wrapper.pid,
																data.stream(),
																data.ppid(),
																s
															)
														} else {
															println!(
																"peer data {:?} {} {}: {:?}",
																wrapper.pid,
																data.stream(),
																data.ppid(),
																bytes
															)
														}
													}
													// Init Chunk
													1 if chunk.len() >= Init::min_len() => {
														let tsn = random();
														let init = Init { chunk };
														wrapper.sctp_data =
															Some((init.vtag(), tsn));
														init_ack = true;
													}
													// Selective Acknowledgements
													3 if chunk.len() >= Sack::min_len() => {
														let sack = Sack { chunk };
														let Some((_, ref mut tsn)) =
															wrapper.sctp_data
														else {
															continue;
														};
														*tsn = sack.cum_tsn().wrapping_add(1);
													}
													// Cookie Chunk
													10 => {
														cookie_ack = true;
													}
													// Heartbeat request (We just drop them)
													4 => {}
													// Print unrecognized chunks
													_ => {
														// Unknown Chunk
														println!(
															"unknown sctp chunk {} {} {}",
															chunk.typ(),
															chunk.flags(),
															chunk.length()
														);
													}
												}
											}

											// Construct + write the response packet
											let Some((rvtag, tsn)) = wrapper.sctp_data else {
												continue;
											};

											// Check if we need to acknowledge an init:
											let mut ret_len = Sctp::min_len();
											if init_ack {
												let mut ack = Init {
													chunk: Chunk {
														buffer: &mut buffer[ret_len..],
													},
												};
												ack.chunk.set_typ(2);
												ack.chunk.set_flags(0);
												ack.chunk.set_length(
													(Init::min_len() + Param::min_len()) as u16,
												);
												ack.set_vtag(random());
												ack.set_arwnd(6000);
												ack.set_num_in(u16::MAX);
												ack.set_num_out(u16::MAX);
												ack.set_tsn(tsn);

												// Set the Cookie parameter thing (zero length cus fuck that mechanism):
												let mut cookie = Param {
													buffer: &mut ack.chunk.buffer
														[Init::min_len()..],
												};
												cookie.set_typ(7);
												cookie.set_length(Param::min_len() as u16);

												ret_len += ack.chunk.len();
											}

											// Check if we need to ack a cookie
											if cookie_ack {
												let mut ack = Chunk {
													buffer: &mut buffer[ret_len..],
												};
												ack.set_typ(11);
												ack.set_flags(0);
												ack.set_length(4);

												ret_len += ack.len();
											}

											// Check if we need to acknowledge any data messages
											if let Some(cum_tsn) = sack {
												let mut ack = Sack {
													chunk: Chunk {
														buffer: &mut buffer[ret_len..],
													},
												};
												ack.chunk.set_typ(3);
												ack.chunk.set_flags(0);
												ack.chunk.set_length(16);
												ack.set_cum_tsn(cum_tsn);
												ack.set_arwnd(6000);
												ack.set_gaps(0);
												ack.set_dups(0);

												ret_len += ack.chunk.len();
											}

											// If we any chunks then send an SCTP packet:
											if ret_len > 12 {
												let mut ret = Sctp {
													buffer: &mut buffer,
												};
												ret.set_sport(5000);
												ret.set_dport(5000);
												ret.set_vtag(rvtag);
												ret.set_chksum(ret.expected_chksum(ret_len));

												let ret = &buffer[..ret_len];
												let _ = context.ssl_write(ret);
											}
										}
										// Handle want read
										Err(e) if e.code() == ErrorCode::WANT_READ => break,
										// Handle any dtls close
										Ok(0) | Err(_) => {
											println!("Disconnected: {:?}", context.get_ref().pid);
											connections.remove(j);
											continue 'packet_loop;
										}
										// Short SCTP packets?
										_ => {}
									}
								}
							}

							// Don't send a response packet (the DTLS stream does this internally)
							continue 'packet_loop;
						}

						// Hosted (SRTP, etc.)
						(HOSTED, _) => continue,

						// Non-hosted: relay
						_ => {}
					}

					// Zero out the padding bytes:
					let padding = (4 - len % 4) % 4;
					msg.buffer[48 + len..][..padding].fill(0);

					// Write the length of the Data attribute and update the length of the STUN packet
					msg.buffer[46..48].copy_from_slice(&u16::to_be_bytes(len as u16));
					msg.set_length(28 + (len + padding) as u16);
				} else {
					continue;
				}
			}

			_ => continue,
		}

		// Send the TURN packet:
		let _ = send(&sock, &msg.buffer[..msg.len()], receiver);
	}
}
