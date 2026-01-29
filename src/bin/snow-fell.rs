use std::{io::{IoSlice, IoSliceMut}, mem::{transmute, zeroed}, net::{Ipv6Addr, SocketAddrV6}, os::{fd::AsRawFd, raw::c_int}, ptr::{NonNull, from_mut, from_ref, read_unaligned, write_unaligned}, str::from_utf8};

use eyre::Result;
use clap::Parser;
use libc::{CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_SPACE, IPPROTO_SCTP, MSG_EOR, MSG_NOTIFICATION, MSG_TRUNC, SCTP_ALL_ASSOC, SCTP_ENABLE_CHANGE_ASSOC_REQ, SCTP_ENABLE_RESET_ASSOC_REQ, SCTP_ENABLE_RESET_STREAM_REQ, SCTP_INITMSG, SCTP_RECVRCVINFO, SCTP_SENDALL, SCTP_SNDINFO, cmsghdr, getsockopt, msghdr, recvmsg, sctp_initmsg, sctp_rcvinfo, sctp_sndinfo, sendmsg, setsockopt, sockaddr_storage, socklen_t};
use masquerade::sctp::linux::{SCTP_ENABLE_STREAM_RESET, SCTP_REMOTE_UDP_ENCAPS_PORT, sctp_assoc_change, sctp_assoc_value, sctp_event, sctp_shutdown_event, sctp_sn_type, sctp_udpencaps, sn_header};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing_subscriber::EnvFilter;
use tracing::{error, trace};

type Never = core::convert::Infallible;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value_t = 5000)]
	port: u16
}

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;
	
	// Bind the SCTP socket
	let socket = Socket::new(Domain::IPV6, Type::SEQPACKET, Some(Protocol::SCTP))?;
	socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, args.port, 0, 0).into())?;
	socket.listen(128)?;

	// Enable receiving SCTP message information
	let value: c_int = 1;
	let res = unsafe {
		setsockopt(socket.as_raw_fd(), IPPROTO_SCTP, SCTP_RECVRCVINFO, from_ref(&value).cast(), size_of_val(&value) as socklen_t)
	};
	assert_eq!(res, 0, "Failed to enable recv info");

	// Enable stream/assoc resets and changes to the association
	let value = sctp_assoc_value {
		assoc_id: SCTP_ALL_ASSOC,
		assoc_value: (SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_RESET_ASSOC_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ) as u32,
	};
	let res = unsafe {
		setsockopt(socket.as_raw_fd(), IPPROTO_SCTP,SCTP_ENABLE_STREAM_RESET, from_ref(&value).cast(), size_of_val(&value) as socklen_t)
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
		setsockopt(socket.as_raw_fd(), IPPROTO_SCTP,SCTP_INITMSG, from_ref(&value).cast(), size_of_val(&value) as socklen_t)
	};
	assert_eq!(res, 0, "Failed to set init message params");

	// Enable association change messages
	let value = sctp_event {
		se_assoc_id: SCTP_ALL_ASSOC,
		se_type: sctp_sn_type::SCTP_ASSOC_CHANGE as u16,
		se_on: 1
	};
	const SCTP_EVENT: c_int = 127;
	let res = unsafe {
		setsockopt(socket.as_raw_fd(), IPPROTO_SCTP, SCTP_EVENT, from_ref(&value).cast(), size_of_val(&value) as socklen_t)
	};
	assert_eq!(res, 0, "Failed to enable assoc change message");

	// Enable shutdown events
	let value = sctp_event {
		se_assoc_id: SCTP_ALL_ASSOC,
		se_type: sctp_sn_type::SCTP_SHUTDOWN_EVENT as u16,
		se_on: 1,
	};
	let res = unsafe {
		setsockopt(socket.as_raw_fd(), IPPROTO_SCTP, SCTP_EVENT, from_ref(&value).cast(), size_of_val(&value) as socklen_t)
	};
	assert_eq!(res, 0, "Failed to enable shutdown message");

	// TODO: Figure out buffer lengths and stuff.
	let mut buffer = [0; 4096];

	loop {
		let mut iov = [IoSliceMut::new(&mut buffer)];
		let mut addr: sockaddr_storage = unsafe { zeroed() };
		let mut control = [0u8; unsafe { CMSG_SPACE(size_of::<sctp_rcvinfo>() as socklen_t) } as usize];
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
		assert!(res > 0, "recvmsg error/close");
		let length = res as usize;

		if msg.msg_flags & MSG_TRUNC != 0 {
			error!("recvmsg truncated");
			continue;
		}
		if msg.msg_flags & MSG_EOR == 0 {
			error!("incomplete message received");
			continue;
		}
		
		// Handle notifications / events (new associations)
		if msg.msg_flags & MSG_NOTIFICATION != 0 {
			// Figure out what type of message this is (Spoiler, it's an association change event):
			assert!(length as usize > size_of::<sn_header>(), "");
			let header: sn_header = unsafe { read_unaligned(buffer.as_ptr().cast()) };
			// assoc change
			if header.sn_type == sctp_sn_type::SCTP_ASSOC_CHANGE as u16 {
				assert!(length >= size_of::<sctp_assoc_change>(), "wtf?");
				let change: sctp_assoc_change = unsafe { read_unaligned(buffer.as_ptr().cast()) };
				let info = &buffer[size_of_val(&change)..length];
				trace!(?change, ?info, "assoc change");
			}
			// Shutdown
			else if header.sn_type == sctp_sn_type::SCTP_SHUTDOWN_EVENT as u16 {
				assert!(length >= size_of::<sctp_shutdown_event>(), "wtf?");
				let shutdown: sctp_shutdown_event = unsafe { read_unaligned(buffer.as_ptr().cast()) };
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
						let inner = unsafe { libc::CMSG_DATA(ptr.as_mut()).cast::<libc::sctp_rcvinfo>().read_unaligned() };
						recvinfo = Some(inner);
						break;
					}
					_ => {}
				}
				cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
			}
			let data = &buffer[..length];
			let Some(recvinfo) = recvinfo else  { continue };
			
			let stream = u16::from_be(recvinfo.rcv_sid);
			let ppid = u32::from_be(recvinfo.rcv_ppid);
			let assoc_id = recvinfo.rcv_assoc_id;

			// Retreive the UDP encapsulation information (Important if commands must be authorized to a specific UDP port (as would be the case for modifying a dstnat/fullnat for that socket address))
			let mut encaps = sctp_udpencaps {
				sue_assoc_id: assoc_id,
				sue_address: addr,
				sue_port: 0,
			};
			let len = size_of_val(&encaps) as socklen_t;
			let mut out_len = len;
			let res = unsafe {
				getsockopt(socket.as_raw_fd(), IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, from_mut(&mut encaps).cast(), &mut out_len)
			};
			assert_eq!(res, 0, "Failed to getsockopt UDP encapsulation");
			assert_eq!(len, out_len, "UDP_ENCAPS_PORT output unexpected length");

			let udp_port = encaps.sue_port;
			let addr = unsafe { SockAddr::new(transmute(addr), msg.msg_namelen) };
			let Some(addr) = addr.as_socket_ipv6() else { continue };

			let info_prefix = format!("{{\"assoc_id\":{assoc_id},\"ip\":\"{}\",\"sctp_port\":{},\"udp_port\":{udp_port},\"ssn\":{}}}\n", addr.ip(), addr.port(), recvinfo.rcv_ssn);

			match (ppid, stream) {
				(50, _) => trace!(?assoc_id, ?addr, ?udp_port, ?stream, ?data, "DCEP message"),
				(51, _) => match from_utf8(data) {
					Ok(data) => {
						trace!(?assoc_id, ?addr, ?udp_port, ?stream, ?data, "String message");

						// TODO: Echo the message to all associations on the socket
						let mut control = [0u8; unsafe { CMSG_SPACE(size_of::<sctp_sndinfo>() as socklen_t) } as usize];
						let mut iov = [
							IoSlice::new(info_prefix.as_bytes()),
							IoSlice::new(data.as_bytes()),
						];
						let mut msg: msghdr;
						let res = unsafe {
							msg = zeroed();
							msg.msg_control = control.as_mut_ptr().cast();
							msg.msg_controllen = control.len();
							let cmsg = CMSG_FIRSTHDR(&msg);
							write_unaligned(cmsg, cmsghdr {
								cmsg_level: IPPROTO_SCTP,
								cmsg_type: SCTP_SNDINFO,
								cmsg_len: CMSG_LEN(size_of::<sctp_sndinfo>() as socklen_t) as usize,
							});
							write_unaligned(CMSG_DATA(cmsg).cast(), sctp_sndinfo {
								snd_sid: stream,
								snd_flags: SCTP_SENDALL as u16,
								snd_ppid: recvinfo.rcv_ppid,
								snd_context: 0,
								snd_assoc_id: SCTP_ALL_ASSOC,
							});
							msg.msg_iov = iov.as_mut_ptr().cast();
							msg.msg_iovlen = iov.len();
							sendmsg(socket.as_raw_fd(), &msg, MSG_EOR)
						};
						trace!(res, "sendmsg");
					}
					Err(reason) => error!(?assoc_id, ?addr, ?udp_port, ?stream, ?reason, "utf8 error"),
				}
				(53, _) => trace!(?assoc_id, ?addr, ?udp_port, ?stream, ?data, "Binary message"),
				_ => trace!(?assoc_id, ?addr, ?udp_port, ?stream, ?ppid, ?data, "Other message"),
			}
		}
	}
}