use std::{
	io::{Error, ErrorKind, IoSlice, IoSliceMut},
	mem::{transmute, zeroed},
	net::{Ipv6Addr, SocketAddrV6},
	os::{fd::AsRawFd, raw::c_int},
	ptr::{NonNull, from_mut, from_ref, read_unaligned, write_unaligned},
	str::from_utf8,
};

use clap::Parser;
use eyre::Result;
use libc::{
	CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_NXTHDR, CMSG_SPACE, IPPROTO_SCTP, MSG_EOR,
	MSG_NOTIFICATION, MSG_TRUNC, SCTP_ALL_ASSOC, SCTP_ENABLE_CHANGE_ASSOC_REQ,
	SCTP_ENABLE_RESET_ASSOC_REQ, SCTP_ENABLE_RESET_STREAM_REQ, SCTP_PR_SCTP_RTX, SCTP_PRINFO,
	SCTP_RECVRCVINFO, SCTP_SENDALL, SCTP_SNDINFO, SCTP_UNORDERED, cmsghdr, getsockopt, msghdr,
	recvmsg, sctp_prinfo, sctp_rcvinfo, sctp_sndinfo, sendmsg, setsockopt, sockaddr_storage,
	socklen_t,
};
use masquerade::{
	sctp::linux::{
		SCTP_ENABLE_STREAM_RESET, SCTP_REMOTE_UDP_ENCAPS_PORT, sctp_assoc_change, sctp_assoc_value,
		sctp_event, sctp_sac_state, sctp_shutdown_event, sctp_sn_type, sctp_udpencaps, sn_header,
	},
	wire::{DcepOpenHeader, EtherHeader},
};
use mio::{Events, Interest, Poll, Token, unix::SourceFd};
use openssl::rand::rand_bytes;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tappers::{Interface, Tap};
use tracing::{debug, error, trace};
use tracing_subscriber::EnvFilter;
use zerocopy::{FromBytes, IntoBytes};

type Never = core::convert::Infallible;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value_t = 5000)]
	port: u16,

	#[arg(long, short)]
	if_name: Option<String>,
}

fn fmt_mac(mac: &[u8; 6]) -> String {
	let [a, b, c, d, e, f] = mac;
	format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

const TAP: Token = Token(usize::MAX);
const SCTP: Token = Token(usize::MAX - 1);

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;

	let mut oui = [0; 6];
	rand_bytes(&mut oui[0..3])?;
	// Clear the Multicast bit
	oui[0] &= !0b01;
	// Set the locally administered bit
	oui[0] |= 0b10;
	trace!("OUI: {}", fmt_mac(&oui));

	// Setup the TAP interface
	let mut network = if let Some(if_name) = args.if_name {
		Tap::new_named(Interface::new(if_name)?)?
	} else {
		Tap::new()?
	};
	network.set_nonblocking(true)?;

	// Bind the SCTP socket
	let socket = Socket::new(Domain::IPV6, Type::SEQPACKET, Some(Protocol::SCTP))?;
	socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, args.port, 0, 0).into())?;
	socket.listen(128)?;
	socket.set_nonblocking(true)?;

	// Enable receiving SCTP message information
	let value: c_int = 1;
	let res = unsafe {
		setsockopt(
			socket.as_raw_fd(),
			IPPROTO_SCTP,
			SCTP_RECVRCVINFO,
			from_ref(&value).cast(),
			size_of_val(&value) as socklen_t,
		)
	};
	assert_eq!(res, 0, "Failed to enable recv info");

	// Enable stream/assoc resets and changes to the association
	let value = sctp_assoc_value {
		assoc_id: SCTP_ALL_ASSOC,
		assoc_value: (SCTP_ENABLE_RESET_STREAM_REQ
			| SCTP_ENABLE_RESET_ASSOC_REQ
			| SCTP_ENABLE_CHANGE_ASSOC_REQ) as u32,
	};
	let res = unsafe {
		setsockopt(
			socket.as_raw_fd(),
			IPPROTO_SCTP,
			SCTP_ENABLE_STREAM_RESET,
			from_ref(&value).cast(),
			size_of_val(&value) as socklen_t,
		)
	};
	assert_eq!(res, 0, "Failed to enable stream resets");

	// Configure the init message to increase ostreams to 65535
	// let value = sctp_initmsg {
	// 	sinit_max_instreams: 65535,
	// 	sinit_num_ostreams: 65535,
	// 	sinit_max_attempts: 0,
	// 	sinit_max_init_timeo: 0,
	// };
	// let res = unsafe {
	// 	setsockopt(
	// 		socket.as_raw_fd(),
	// 		IPPROTO_SCTP,
	// 		SCTP_INITMSG,
	// 		from_ref(&value).cast(),
	// 		size_of_val(&value) as socklen_t,
	// 	)
	// };
	// assert_eq!(res, 0, "Failed to set init message params");

	// Enable association change messages
	let value = sctp_event {
		se_assoc_id: SCTP_ALL_ASSOC,
		se_type: sctp_sn_type::SCTP_ASSOC_CHANGE as u16,
		se_on: 1,
	};
	const SCTP_EVENT: c_int = 127;
	let res = unsafe {
		setsockopt(
			socket.as_raw_fd(),
			IPPROTO_SCTP,
			SCTP_EVENT,
			from_ref(&value).cast(),
			size_of_val(&value) as socklen_t,
		)
	};
	assert_eq!(res, 0, "Failed to enable assoc change message");

	// Enable shutdown events
	let value = sctp_event {
		se_assoc_id: SCTP_ALL_ASSOC,
		se_type: sctp_sn_type::SCTP_SHUTDOWN_EVENT as u16,
		se_on: 1,
	};
	let res = unsafe {
		setsockopt(
			socket.as_raw_fd(),
			IPPROTO_SCTP,
			SCTP_EVENT,
			from_ref(&value).cast(),
			size_of_val(&value) as socklen_t,
		)
	};
	assert_eq!(res, 0, "Failed to enable shutdown message");

	let mut events = Events::with_capacity(128);
	let mut poll = Poll::new()?;
	poll.registry()
		.register(&mut SourceFd(&network.as_raw_fd()), TAP, Interest::READABLE)?;
	poll.registry()
		.register(&mut SourceFd(&socket.as_raw_fd()), SCTP, Interest::READABLE)?;

	// TODO: Figure out buffer lengths and stuff.
	let mut buffer = [0; 65535];

	loop {
		for e in events.into_iter() {
			match e.token() {
				TAP => loop {
					let Ok(length) = network.recv(&mut buffer) else {
						break;
					};
					if length < size_of::<EtherHeader>() {
						panic!("WAT?");
					}
					let (eth, _) = EtherHeader::ref_from_prefix(buffer.as_slice()).unwrap();

					let assoc_id;
					let mut snd_flags = SCTP_UNORDERED as u16;
					if (eth.dst[0] & 0b01) != 0 {
						assoc_id = SCTP_ALL_ASSOC;
						snd_flags |= SCTP_SENDALL as u16;
					} else if eth.dst[0..3] == oui[0..3] {
						assoc_id = i32::from_be_bytes([0, eth.dst[3], eth.dst[4], eth.dst[5]]);
					} else {
						trace!(?eth, "Mac address didn't match our oui");
						continue;
					};

					// Tunnel the packet
					let mut control = [0u8; unsafe {
						CMSG_SPACE(size_of::<sctp_sndinfo>() as socklen_t)
							+ CMSG_SPACE(size_of::<sctp_prinfo>() as socklen_t)
					} as usize];
					let mut iov = [IoSlice::new(&buffer[..length])];
					let mut msg: msghdr;
					let res = unsafe {
						msg = zeroed();
						msg.msg_control = control.as_mut_ptr().cast();
						msg.msg_controllen = control.len();
						let cmsg = CMSG_FIRSTHDR(&msg);
						write_unaligned(
							cmsg,
							cmsghdr {
								cmsg_level: IPPROTO_SCTP,
								cmsg_type: SCTP_SNDINFO,
								cmsg_len: CMSG_LEN(size_of::<sctp_sndinfo>() as socklen_t) as usize,
							},
						);
						write_unaligned(
							CMSG_DATA(cmsg).cast(),
							sctp_sndinfo {
								snd_sid: 1,
								snd_flags,
								snd_ppid: 53u32.to_be(),
								snd_context: 0,
								snd_assoc_id: assoc_id,
							},
						);
						let cmsg = CMSG_NXTHDR(&msg, cmsg);
						write_unaligned(
							cmsg,
							cmsghdr {
								cmsg_level: IPPROTO_SCTP,
								cmsg_type: SCTP_PRINFO,
								cmsg_len: CMSG_LEN(size_of::<sctp_prinfo>() as socklen_t) as usize,
							},
						);
						write_unaligned(
							CMSG_DATA(cmsg).cast(),
							sctp_prinfo {
								pr_policy: SCTP_PR_SCTP_RTX as u16,
								pr_value: 0,
							},
						);

						msg.msg_iov = iov.as_mut_ptr().cast();
						msg.msg_iovlen = iov.len();
						sendmsg(socket.as_raw_fd(), &msg, MSG_EOR)
					};
					if res < 0 {
						let error = Error::last_os_error();
						if error.kind() != ErrorKind::WouldBlock {
							trace!(?res, ?error, "sendmsg failed");
						}
					}
				},
				SCTP => loop {
					let mut iov = [IoSliceMut::new(&mut buffer)];
					let mut addr: sockaddr_storage = unsafe { zeroed() };
					let mut control =
						[0u8; unsafe { CMSG_SPACE(size_of::<sctp_rcvinfo>() as socklen_t) }
							as usize];
					let mut msg: msghdr;
					let res = unsafe {
						// https://github.com/sctp/lksctp-tools/blob/37d5f1225573b91d706a5e547d081f79963a9deb/src/lib/recvmsg.c#L65
						msg = zeroed();
						msg.msg_namelen = size_of_val(&addr) as socklen_t;
						msg.msg_name = from_mut(&mut addr).cast();
						msg.msg_iovlen = iov.len();
						msg.msg_iov = iov.as_mut_ptr().cast();
						msg.msg_controllen = control.len();
						msg.msg_control = from_mut(&mut control).cast();

						recvmsg(socket.as_raw_fd(), &mut msg, 0)
					};
					if res == -1 {
						let error = Error::last_os_error();
						if error.kind() == ErrorKind::WouldBlock {
							break;
						}
						debug!(?res, ?error, "recvmsg error");
						continue;
					}
					assert!(res >= 0, "recvmsg error/close");
					let length = res as usize;

					if msg.msg_flags & MSG_TRUNC != 0 {
						error!("recvmsg truncated");
						continue;
					}
					if msg.msg_flags & MSG_EOR == 0 {
						error!("incomplete message received");
						continue;
					}
					let Some(data) = buffer.get(..length) else {
						debug!(?length, "SCTP Receive buffer too small for message");
						continue;
					};

					// Handle notifications / events (new associations)
					if msg.msg_flags & MSG_NOTIFICATION != 0 {
						// Figure out what type of message this is (Spoiler, it's an association change event):
						assert!(data.len() > size_of::<sn_header>(), "");
						let header: sn_header = unsafe { read_unaligned(data.as_ptr().cast()) };
						// assoc change
						if header.sn_type == sctp_sn_type::SCTP_ASSOC_CHANGE as u16 {
							assert!(data.len() >= size_of::<sctp_assoc_change>(), "wtf?");
							let change: sctp_assoc_change =
								unsafe { read_unaligned(data.as_ptr().cast()) };
							let info = &data[size_of_val(&change)..];
							trace!(?change, ?info, "assoc change");

							if change.sac_state != sctp_sac_state::SCTP_COMM_UP as u16 {
								continue;
							}

							// Open a datachannel
							let assoc_id = change.sac_assoc_id;
							let mut mac = [0; 6];
							mac[0..3].copy_from_slice(&oui[0..3]);
							mac[3..].copy_from_slice(&assoc_id.to_be_bytes()[1..]);
							let label = fmt_mac(&mac);
							let protocol = "ETHER";
							let dcep = DcepOpenHeader {
								msg_typ: 0x03,         /* DCEP_CHANNEL_OPEN */
								channel_typ: 0x81,     /* CHANNEL_TYPE_PARTIAL_RELIABLE_REXMIT_UNORDERED */
								priority: 1024.into(), /* extra high */
								reliability_parameter: 0.into(),
								label_len: (label.len() as u16).into(),
								protocol_len: (protocol.len() as u16).into(),
							};

							let mut iov = [
								IoSlice::new(dcep.as_bytes()),
								IoSlice::new(label.as_bytes()),
								IoSlice::new(protocol.as_bytes()),
							];
							// let mut addr: sockaddr_storage = unsafe { zeroed() };
							let mut control =
								[0u8;
									unsafe { CMSG_SPACE(size_of::<sctp_sndinfo>() as socklen_t) }
										as usize];
							let mut msg: msghdr;
							let res = unsafe {
								msg = zeroed();
								msg.msg_control = control.as_mut_ptr().cast();
								msg.msg_controllen = control.len();
								let cmsg = CMSG_FIRSTHDR(&msg);
								write_unaligned(
									cmsg,
									cmsghdr {
										cmsg_level: IPPROTO_SCTP,
										cmsg_type: SCTP_SNDINFO,
										cmsg_len: CMSG_LEN(size_of::<sctp_sndinfo>() as socklen_t)
											as usize,
									},
								);
								write_unaligned(
									CMSG_DATA(cmsg).cast(),
									sctp_sndinfo {
										snd_sid: 1,
										snd_flags: 0,
										snd_ppid: 50u32.to_be(),
										snd_context: 0,
										snd_assoc_id: change.sac_assoc_id,
									},
								);

								msg.msg_iov = iov.as_mut_ptr().cast();
								msg.msg_iovlen = iov.len();
								sendmsg(socket.as_raw_fd(), &msg, MSG_EOR)
							};
							if res < 0 {
								let error = Error::last_os_error();
								if error.kind() != ErrorKind::WouldBlock {
									trace!(?res, ?error, "sendmsg (dcep) failed");
								}
							}
						}
						// Shutdown
						else if header.sn_type == sctp_sn_type::SCTP_SHUTDOWN_EVENT as u16 {
							assert!(data.len() >= size_of::<sctp_shutdown_event>(), "wtf?");
							let shutdown: sctp_shutdown_event =
								unsafe { read_unaligned(buffer.as_ptr().cast()) };
							trace!(?shutdown, "shutdown");
						}
						// Any other messages
						else {
							trace!(?header, "msg_notification");
						}
					}
					// Handle SCTP messages
					else {
						let mut recvinfo = None;
						let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
						while let Some(mut ptr) = NonNull::new(cmsg) {
							let libc::cmsghdr {
								cmsg_level,
								cmsg_type,
								..
							} = unsafe { ptr.read_unaligned() };
							trace!(?cmsg_level, ?cmsg_type, "CMSG");
							if let (libc::IPPROTO_SCTP, libc::SCTP_RCVINFO) =
								(cmsg_level, cmsg_type)
							{
								let inner = unsafe {
									libc::CMSG_DATA(ptr.as_mut())
										.cast::<libc::sctp_rcvinfo>()
										.read_unaligned()
								};
								recvinfo = Some(inner);
								break;
							}
							cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
						}

						let Some(addr6) =
							unsafe { SockAddr::new(transmute(addr), msg.msg_namelen) }
								.as_socket_ipv6()
						else {
							continue;
						};
						let Some(recvinfo) = recvinfo else { continue };

						let stream = recvinfo.rcv_sid;
						let ppid = u32::from_be(recvinfo.rcv_ppid);

						let assoc_id = recvinfo.rcv_assoc_id;
						let mut mac = oui.clone();
						mac[3..].copy_from_slice(&assoc_id.to_be_bytes()[1..]);

						match (ppid, stream) {
							(50, _) => trace!(?assoc_id, ?addr6, ?stream, ?data, "DCEP message"),
							(51, _) => {
								let Ok(data) = from_utf8(data) else { continue };
								// I'm expecting that most commands will come as JSON messages.
								// If those commands involve dstnat or other network commands, then knowing the precise sender's UDP port is important
								let mut encaps = sctp_udpencaps {
									sue_assoc_id: assoc_id,
									sue_address: addr,
									sue_port: 0,
								};
								let len = size_of_val(&encaps) as socklen_t;
								let mut out_len = len;
								let res = unsafe {
									getsockopt(
										socket.as_raw_fd(),
										IPPROTO_SCTP,
										SCTP_REMOTE_UDP_ENCAPS_PORT,
										from_mut(&mut encaps).cast(),
										&mut out_len,
									)
								};
								assert_eq!(res, 0, "Failed to getsockopt UDP encapsulation");
								assert_eq!(
									len, out_len,
									"UDP_ENCAPS_PORT output unexpected length"
								);

								let udp_port = encaps.sue_port;

								trace!(
									?assoc_id,
									?addr6,
									?udp_port,
									?stream,
									?data,
									"String message"
								);
							}
							// VPN traffic
							(53, 1) => {
								let Ok((eth, _)) = EtherHeader::ref_from_prefix(data) else {
									continue;
								};
								if eth.src != mac {
									trace!(?eth, "Wrong MAC src");
									continue;
								}
								let _ = network.send(data);
							}
							_ => trace!(?assoc_id, ?addr6, ?stream, ?ppid, ?data, "Other message"),
						}
					}
				},
				_ => unreachable!("Unrecognized Token"),
			}
		}

		poll.poll(&mut events, None)?;
	}
}
