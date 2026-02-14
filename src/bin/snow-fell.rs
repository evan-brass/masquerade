use std::{
	io::{Error, ErrorKind, IoSlice, IoSliceMut},
	mem::{transmute, zeroed},
	net::{Ipv6Addr, SocketAddrV6, UdpSocket},
	os::{fd::AsRawFd, raw::c_int},
	ptr::{NonNull, from_mut, from_ref, read_unaligned, write_unaligned},
	str::{FromStr, from_utf8},
	usize,
};

use clap::Parser;
use eyre::{Result, eyre};
use gio::Socket as GSocket;
use gstreamer::{
	ElementFactory, Pipeline,
	glib::object::ObjectExt,
	prelude::{ElementExt, ElementExtManual, GstBinExtManual, UnixBusExtManual},
};
use ipnet::Ipv6Net;
use libc::{
	CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_NXTHDR, CMSG_SPACE, IPPROTO_SCTP, MSG_EOR,
	MSG_NOTIFICATION, MSG_TRUNC, SCTP_ALL_ASSOC, SCTP_ENABLE_CHANGE_ASSOC_REQ,
	SCTP_ENABLE_RESET_ASSOC_REQ, SCTP_ENABLE_RESET_STREAM_REQ, SCTP_INITMSG, SCTP_PR_SCTP_RTX,
	SCTP_PRINFO, SCTP_RECVRCVINFO, SCTP_SNDINFO, SCTP_UNORDERED, cmsghdr, getsockopt, msghdr,
	recvmsg, sctp_assoc_t, sctp_initmsg, sctp_prinfo, sctp_rcvinfo, sctp_sndinfo, sendmsg,
	setsockopt, sockaddr_storage, socklen_t,
};
use masquerade::{
	sctp::linux::{
		SCTP_ENABLE_STREAM_RESET, SCTP_REMOTE_UDP_ENCAPS_PORT, sctp_assoc_change, sctp_assoc_value,
		sctp_event, sctp_sac_state, sctp_shutdown_event, sctp_sn_type, sctp_udpencaps, sn_header,
	},
	wire::{DcepOpenHeader, Ip6Header},
};
use mio::{Events, Interest, Poll, Token, unix::SourceFd};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tappers::{Interface, Tun};
use tracing::{debug, error, trace};
use tracing_subscriber::EnvFilter;
use zerocopy::{FromBytes, IntoBytes};

type Never = core::convert::Infallible;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value_t = 5000)]
	port: u16,

	#[arg(long, short, default_value_t = 4666)]
	rtp_port: u16,

	#[arg(long, short, default_value = "fd00::1:0:0/96")]
	subnet: String,

	#[arg(long, short)]
	if_name: Option<String>,
}

struct Mapping {
	subnet: Ipv6Net,
}
impl Mapping {
	fn new(subnet: Ipv6Net) -> Result<Self> {
		let min_prefix_len = 128 - sctp_assoc_t::BITS;
		if min_prefix_len > subnet.prefix_len() as u32 {
			return Err(eyre!(
				"Need at most /{min_prefix_len} subnet for a system with {} sctp_assoc_t bits, found /{}",
				sctp_assoc_t::BITS,
				subnet.prefix_len()
			));
		}
		Ok(Self { subnet })
	}
	fn from_index(&self, index: sctp_assoc_t) -> Option<Ipv6Addr> {
		// The remaining 17 or 49 bits are the host
		let host = Ipv6Addr::from_bits(index as u128);
		let ip = self.subnet.network() | host;

		// Check if we've exceeded our subnet
		if !self.subnet.contains(&ip) {
			return None;
		}

		Some(ip)
	}
	fn to_index(&self, addr: Ipv6Addr) -> Option<sctp_assoc_t> {
		if !self.subnet.contains(&addr) {
			return None;
		};
		let host = addr & self.subnet.hostmask();
		Some(host.to_bits() as sctp_assoc_t)
	}
}

const TUN: Token = Token(usize::MAX);
const SCTP: Token = Token(usize::MAX - 1);
const BUS: Token = Token(usize::MAX - 2);

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;

	let mapping = Mapping::new(Ipv6Net::from_str(&args.subnet)?)?;

	// Setup the TUN interface
	let mut network = if let Some(if_name) = args.if_name {
		Tun::new_named(Interface::new(if_name)?)?
	} else {
		Tun::new()?
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
	let value = sctp_initmsg {
		sinit_max_instreams: 65535,
		sinit_num_ostreams: 65535,
		sinit_max_attempts: 0,
		sinit_max_init_timeo: 0,
	};
	let res = unsafe {
		setsockopt(
			socket.as_raw_fd(),
			IPPROTO_SCTP,
			SCTP_INITMSG,
			from_ref(&value).cast(),
			size_of_val(&value) as socklen_t,
		)
	};
	assert_eq!(res, 0, "Failed to set init message params");

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

	// Bind a UDP socket to serve as the entry/exit point for our gstreamer stuff
	let rtp_udp = UdpSocket::bind(SocketAddrV6::new(
		Ipv6Addr::UNSPECIFIED,
		args.rtp_port,
		0,
		0,
	))?;
	let rtp_udp = GSocket::from_fd(rtp_udp.into())?;

	// setup a gstreamer pipeline
	gstreamer::init()?;
	let pipeline = Pipeline::new();
	let bus = pipeline.bus().ok_or(eyre!("No bus on pipeline?"))?;

	let udpsrc = ElementFactory::make("udpsrc").build()?;
	udpsrc.set_property("socket", rtp_udp);

	let rtpbin = ElementFactory::make("rtpbin").build()?;
	rtpbin.set_property("autoremove", true);
	let _ = rtpbin.connect("on-new-sender-ssrc", false, |args| {
		trace!(?args, "new sender SSRC");
		None
	});

	pipeline.add_many(&[&udpsrc, &rtpbin])?;

	udpsrc.link(&rtpbin)?;

	pipeline.set_state(gstreamer::State::Playing)?;

	let mut events = Events::with_capacity(128);
	let mut poll = Poll::new()?;
	poll.registry()
		.register(&mut SourceFd(&bus.pollfd()), BUS, Interest::READABLE)?;
	poll.registry()
		.register(&mut SourceFd(&network.as_raw_fd()), TUN, Interest::READABLE)?;
	poll.registry()
		.register(&mut SourceFd(&socket.as_raw_fd()), SCTP, Interest::READABLE)?;

	// TODO: Figure out buffer lengths and stuff.
	let mut buffer = [0; 65535];

	loop {
		for e in events.into_iter() {
			match e.token() {
				BUS => loop {
					let Some(msg) = bus.pop() else { break };
					trace!(?msg, "gst bus message");
				},
				TUN => loop {
					let Ok(length) = network.recv(&mut buffer) else {
						break;
					};
					let (ip, _) = Ip6Header::ref_from_prefix(buffer.as_slice()).unwrap();
					if ip.flags.version() != 6 {
						continue;
					}
					if ip.len() != length {
						continue;
					}

					let Some(assoc_id) = mapping.to_index(ip.dst.into()) else {
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
								snd_flags: SCTP_UNORDERED as u16,
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
							let Some(addr) = mapping.from_index(change.sac_assoc_id) else {
								continue;
							};
							let label = format!("{addr}");
							let protocol = "INET6";
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
							match (cmsg_level, cmsg_type) {
								(libc::IPPROTO_SCTP, libc::SCTP_RCVINFO) => {
									let inner = unsafe {
										libc::CMSG_DATA(ptr.as_mut())
											.cast::<libc::sctp_rcvinfo>()
											.read_unaligned()
									};
									recvinfo = Some(inner);
									break;
								}
								_ => {}
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
								let Ok((ip6, _)) = Ip6Header::ref_from_prefix(data) else {
									continue;
								};
								if ip6.flags.version() != 6 {
									continue;
								}
								if ip6.len() != data.len() {
									continue;
								}
								let Some(expected) = mapping.from_index(assoc_id) else {
									continue;
								};
								if ip6.src != expected.octets() {
									continue;
								};
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
