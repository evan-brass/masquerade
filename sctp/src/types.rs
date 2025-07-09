use nix::libc;
use zerocopy::{FromBytes, Immutable, KnownLayout};

// Re-define libc::sctp_rcvinfo and libc::sctp_nxtinfo so that we can derive the zero copy stuff.
#[repr(C)]
#[derive(Clone, Copy, Debug, KnownLayout, Immutable, FromBytes)]
pub struct SndInfo {
	snd_sid: u16,
	snd_flags: u16,
	snd_ppid: u32,
	snd_context: u32,
	snd_assoc_id: libc::sctp_assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, KnownLayout, Immutable, FromBytes)]
pub struct RcvInfo {
	rcv_sid: u16,
	rcv_ssn: u16,
	rcv_flags: u16,
	rcv_ppid: u32,
	rcv_tsn: u32,
	rcv_cumtsn: u32,
	rcv_context: u32,
	rcv_assoc_id: libc::sctp_assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, KnownLayout, Immutable, FromBytes)]
pub struct PrInfo {
	pr_policy: u16,
	pr_value: u32,
}

