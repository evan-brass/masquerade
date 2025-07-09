use nix::libc;
use nix::sys::socket::SockaddrIn6;
use nix::{setsockopt_impl, getsockopt_impl, sockopt_impl};

const SCTP_SOCKOPT_BINDX_ADD: libc::c_int = 100;
const SCTP_SOCKOPT_BINDX_REM: libc::c_int = 101;

sockopt_impl!(
	SctpAddrAdd,
	SetOnly,
	libc::IPPROTO_SCTP,
	SCTP_SOCKOPT_BINDX_ADD,
	SockaddrIn6
);
sockopt_impl!(
	SctpAddrDel,
	SetOnly,
	libc::IPPROTO_SCTP,
	SCTP_SOCKOPT_BINDX_REM,
	SockaddrIn6
);
sockopt_impl!(
	SctpRecvRcvInfo,
	Both,
	libc::IPPROTO_SCTP,
	libc::SCTP_RECVRCVINFO,
	bool
);
