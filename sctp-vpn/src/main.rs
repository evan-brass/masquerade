use std::{net::SocketAddrV6, str::FromStr};

use eyre::Result;
use socket2::{Domain, MaybeUninitSlice, MsgHdrMut, Protocol, Type};
use tracing::trace;
use clap::Parser;
use tracing_subscriber::EnvFilter;

type Never = core::convert::Infallible;

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

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;
	let addr = SocketAddrV6::from_str(&args.sctp)?;

	// Bind our SCTP socket
	let sock = socket2::Socket::new(Domain::IPV6, Type::SEQPACKET, Some(Protocol::SCTP))?;
	sock.bind(&addr.into())?;
	sock.listen(128)?;

	let mut buffer = Vec::with_capacity(4096);
	let mut control = Vec::with_capacity(2048);
	loop {
		buffer.clear();
		control.clear();
		let mut buffers = [
			MaybeUninitSlice::new(buffer.spare_capacity_mut())
		];
		let mut msg = MsgHdrMut::new()
			.with_buffers(&mut buffers)
			.with_control(control.spare_capacity_mut());
		// Listen for messages on the socket:
		let Ok(len) = sock.recvmsg(&mut msg, 0) else { continue };

		let flags = msg.flags();
		let control_len = msg.control_len();

		unsafe { buffer.set_len(len); }
		unsafe { control.set_len(control_len); }

		trace!(?flags, ?buffer, ?control, "SCTP Message");
	}
}
