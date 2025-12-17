use eyre::Result;
use clap::Parser;
use sctp::SctpEndpoint;
use tracing_subscriber::EnvFilter;

type Never = core::convert::Infallible;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "[::]:5000")]
	address: String,
}

fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;
	
	// Bind the SCTP socket
	let endpoint = SctpEndpoint::bind(args.address)?;
	
	let mut buffer = [0; 65536];

	loop {
		let Ok((len, stream, sender)) = endpoint.recv_from(buffer.as_mut_slice()) else { continue };
		let data = &buffer[..len];
		// TODO: I think I wrote a custom sctp lib because I wanted ppid, and shit.

		println!("{sender} {stream} {data:?}");
	}
}