use std::ffi::c_void;
use std::{net::SocketAddrV6, os::fd::AsRawFd, str::FromStr, usize};
use std::io::{Read, Write, ErrorKind};
use std::ptr::from_ref;

use eyre::Result;
use mio::{
	Events, Interest, Poll, Token,
	unix::SourceFd,
};
use tappers::{Interface, Tun};
use slab::Slab;
use socket2::{Domain, Protocol, Type};
use tracing::{debug, trace};
use clap::Parser;
use tracing_subscriber::EnvFilter;
use wire::{FromBytes, Ip6Header};

type Never = core::convert::Infallible;
const SCTP: Token = Token(usize::MAX);
const TUN: Token = Token(usize::MAX - 1);

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "[::]:5000")]
	sctp: String,

	#[arg(long, short, default_value_t = 0x01)]
	site: u16,

	#[arg(long, short)]
	if_name: Option<String>,
}

// We assign a link-local ip for each SCTP Association u64 <-> Link local ip
fn to_ip(site: u16, index: u64) -> [u8; 16] {
	let mut octets = [0xfd, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	octets[2..4].copy_from_slice(&site.to_be_bytes());
	octets[8..].copy_from_slice(&index.to_be_bytes());
	octets
}
fn from_ip(octets: [u8; 16]) -> Option<(u16, u64)> {
	if octets[0..2] != [0xfd, 0x04] {
		return None;
	}
	let site = u16::from_be_bytes(octets[2..4].try_into().unwrap());
	if octets[4..8] != [0, 0, 0, 0] {
		return None;
	}
	let index = u64::from_be_bytes(octets[8..].try_into().unwrap());
	Some((site, index))
}

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;
	let addr = SocketAddrV6::from_str(&args.sctp)?;

	// Bind our SCTP socket
	let listen = socket2::Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::SCTP))?;
	listen.bind(&addr.into())?;
	listen.listen(128)?;
	listen.set_nonblocking(true)?;

	// Setup the TUN interface
	let mut network = if let Some(if_name) = args.if_name {
		Tun::new_named(Interface::new(if_name)?)?
	} else {
		Tun::new()?
	};
	network.set_nonblocking(true)?;

	// Async setup
	let mut poll = Poll::new()?;
	let mut events = Events::with_capacity(128);
	poll.registry()
		.register(&mut SourceFd(&listen.as_raw_fd()), SCTP, Interest::READABLE)?;
	poll.registry()
		.register(&mut SourceFd(&network.as_raw_fd()), TUN, Interest::READABLE)?;

	// SCTP Associations
	let mut connections = Slab::new();

	// Shared buffer
	let mut buffer = [0; 65535];
	loop {
		for e in events.into_iter() {
			trace!(?e, "Event");
			loop {
				match e.token() {
					SCTP => {
						let Ok((assoc, addr)) = listen.accept() else {
							break;
						};
						trace!(?addr, "SCTP Open");
						let entry = connections.vacant_entry();

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
							assoc.as_raw_fd(),
							libc::IPPROTO_SCTP,
							libc::SCTP_DEFAULT_SNDINFO,
							from_ref(&snd_info).cast::<c_void>(),
							size_of_val(&snd_info) as libc::socklen_t
						) } {
							continue
						}
						poll.registry().register(
							&mut SourceFd(&assoc.as_raw_fd()),
							Token(entry.key()),
							Interest::READABLE,
						)?;
						// TODO: Set the socket options to configure default partially reliable information (=unreliable) and send information (stream 1, unordered, endof record, sendall, etc.)
						entry.insert(assoc);
					}
					TUN => {
						let Ok(length) = network.recv(&mut buffer) else { break };
						let (ip, _) = Ip6Header::ref_from_prefix(&buffer).unwrap();
						if ip.flags.get() >> 28 != 6 { continue }
						if ip.len() != length { continue }
						let Some((site, index)) = from_ip(ip.dst) else { continue };
						if site != args.site {
							debug!(?site, "Mis-Routed packet");
							continue
						}

						// <&mut &Socket as Read>
						let Some(mut assoc) = connections.get(index as usize) else { continue };

						trace!(packet = &buffer[..length], ?index, "In");
						let _ = assoc.write(&buffer[..length]);
					}
					Token(index) => {
						let Some(assoc) = connections.get_mut(index) else {
							break;
						};
						match assoc.read(&mut buffer) {
							Ok(length) => {
								let (ip, _) = Ip6Header::mut_from_prefix(&mut buffer).unwrap();
								if ip.flags.get() >> 28 != 6 { continue }
								if ip.len() != length { continue }
								let exp_src = to_ip(args.site, index as u64);
								if ip.src != exp_src {
									ip.dst = exp_src;
									ip.src = [0; 16];
									ip.payload_length.set(0);
									ip.next_header = 0xff;
									let len = ip.len();

									trace!(packet = &buffer[..len], "Discover");
									assoc.write(&buffer[..len])?;
									continue
								}
								trace!(packet = &buffer[..length], "Out");
								let _ = network.send(&buffer[..length]);
							}
							Err(e) if e.kind() == ErrorKind::WouldBlock => break,
							Err(reason) => {
								trace!(?reason, "SCTP Close");
								let assoc = connections.remove(index);
								poll.registry().deregister(&mut SourceFd(&assoc.as_raw_fd()))?;
								break;
							}
						}
					}
				}
			}
		}
		poll.poll(&mut events, None)?;
	}
}
