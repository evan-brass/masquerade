#![allow(nonstandard_style)]
/// Definitions arising out of linux/sctp.h, but pruned to fit our usages.

use std::ffi::c_int;
use libc::sockaddr_storage;
use libc::sctp_assoc_t;

/* The following symbols come from the Sockets API Extensions for
 * SCTP <draft-ietf-tsvwg-sctpsocket-07.txt>.
 */
pub const SCTP_RTOINFO: c_int =	0;
pub const SCTP_ASSOCINFO: c_int =  1;
pub const SCTP_INITMSG: c_int =	2;
pub const SCTP_NODELAY: c_int =	3;		/* Get/set nodelay option. */
pub const SCTP_AUTOCLOSE: c_int =	4;
pub const SCTP_SET_PEER_PRIMARY_ADDR: c_int = 5;
pub const SCTP_PRIMARY_ADDR: c_int =	6;
pub const SCTP_ADAPTATION_LAYER: c_int =	7;
pub const SCTP_DISABLE_FRAGMENTS: c_int =	8;
pub const SCTP_PEER_ADDR_PARAMS: c_int =	9;
pub const SCTP_DEFAULT_SEND_PARAM: c_int =	10;
pub const SCTP_EVENTS: c_int =	11;
pub const SCTP_I_WANT_MAPPED_V4_ADDR: c_int = 12;	/* Turn on/off mapped v4 addresses  */
pub const SCTP_MAXSEG: c_int =	13;		/* Get/set maximum fragment. */
pub const SCTP_STATUS: c_int =	14;
pub const SCTP_GET_PEER_ADDR_INFO: c_int =	15;
pub const SCTP_DELAYED_ACK_TIME: c_int =	16;
pub const SCTP_DELAYED_ACK: c_int = SCTP_DELAYED_ACK_TIME;
pub const SCTP_DELAYED_SACK: c_int = SCTP_DELAYED_ACK_TIME;
pub const SCTP_CONTEXT: c_int =	17;
pub const SCTP_FRAGMENT_INTERLEAVE: c_int =	18;
pub const SCTP_PARTIAL_DELIVERY_POINT: c_int =	19; /* Set/Get partial delivery point */
pub const SCTP_MAX_BURST: c_int =	20;		/* Set/Get max burst */
pub const SCTP_AUTH_CHUNK: c_int =	21;	/* Set only: add a chunk type to authenticate */
pub const SCTP_HMAC_IDENT: c_int =	22;
pub const SCTP_AUTH_KEY: c_int =	23;
pub const SCTP_AUTH_ACTIVE_KEY: c_int =	24;
pub const SCTP_AUTH_DELETE_KEY: c_int =	25;
pub const SCTP_PEER_AUTH_CHUNKS: c_int =	26;	/* Read only */
pub const SCTP_LOCAL_AUTH_CHUNKS: c_int =	27;	/* Read only */
pub const SCTP_GET_ASSOC_NUMBER: c_int =	28;	/* Read only */
pub const SCTP_GET_ASSOC_ID_LIST: c_int =	29;	/* Read only */
pub const SCTP_AUTO_ASCONF: c_int =       30;
pub const SCTP_PEER_ADDR_THLDS: c_int =	31;
pub const SCTP_RECVRCVINFO: c_int =	32;
pub const SCTP_RECVNXTINFO: c_int =	33;
pub const SCTP_DEFAULT_SNDINFO: c_int =	34;
pub const SCTP_AUTH_DEACTIVATE_KEY: c_int =	35;
pub const SCTP_REUSE_PORT: c_int =		36;
pub const SCTP_PEER_ADDR_THLDS_V2: c_int =	37;

/* Internal Socket Options. Some of the sctp library functions are
 * implemented using these socket options.
 */
pub const SCTP_SOCKOPT_BINDX_ADD: c_int =	100;	/* BINDX requests for adding addrs */
pub const SCTP_SOCKOPT_BINDX_REM: c_int =	101;	/* BINDX requests for removing addrs. */
pub const SCTP_SOCKOPT_PEELOFF: c_int =	102;	/* peel off association. */

/* Options 104-106 are deprecated and removed. Do not use this space */
pub const SCTP_SOCKOPT_CONNECTX_OLD: c_int = 	107;	/* CONNECTX old requests. */
pub const SCTP_GET_PEER_ADDRS: c_int = 	108;		/* Get all peer address. */
pub const SCTP_GET_LOCAL_ADDRS: c_int = 	109;		/* Get all local address. */
pub const SCTP_SOCKOPT_CONNECTX: c_int = 	110;		/* CONNECTX requests. */
pub const SCTP_SOCKOPT_CONNECTX3: c_int = 	111;	/* CONNECTX requests (updated) */
pub const SCTP_GET_ASSOC_STATS: c_int = 	112;	/* Read only */
pub const SCTP_PR_SUPPORTED: c_int = 	113;
pub const SCTP_DEFAULT_PRINFO: c_int = 	114;
pub const SCTP_PR_ASSOC_STATUS: c_int = 	115;
pub const SCTP_PR_STREAM_STATUS: c_int = 	116;
pub const SCTP_RECONFIG_SUPPORTED: c_int = 	117;
pub const SCTP_ENABLE_STREAM_RESET: c_int = 	118;
pub const SCTP_RESET_STREAMS: c_int = 	119;
pub const SCTP_RESET_ASSOC: c_int = 	120;
pub const SCTP_ADD_STREAMS: c_int = 	121;
pub const SCTP_SOCKOPT_PEELOFF_FLAGS: c_int =  122;
pub const SCTP_STREAM_SCHEDULER: c_int = 	123;
pub const SCTP_STREAM_SCHEDULER_VALUE: c_int = 	124;
pub const SCTP_INTERLEAVING_SUPPORTED: c_int = 	125;
pub const SCTP_SENDMSG_CONNECT: c_int = 	126;
pub const SCTP_EVENT: c_int = 	127;
pub const SCTP_ASCONF_SUPPORTED: c_int = 	128;
pub const SCTP_AUTH_SUPPORTED: c_int = 	129;
pub const SCTP_ECN_SUPPORTED: c_int = 	130;
pub const SCTP_EXPOSE_POTENTIALLY_FAILED_STATE: c_int = 	131;
pub const SCTP_EXPOSE_PF_STATE: c_int = 	SCTP_EXPOSE_POTENTIALLY_FAILED_STATE;
pub const SCTP_REMOTE_UDP_ENCAPS_PORT: c_int = 	132;
pub const SCTP_PLPMTUD_PROBE_INTERVAL: c_int = 	133;

/*
 * 5.3.1.1 SCTP_ASSOC_CHANGE
 *
 *   Communication notifications inform the ULP that an SCTP association
 *   has either begun or ended. The identifier for a new association is
 *   provided by this notificaion. The notification information has the
 *   following format:
 *
 */
#[repr(C)]
#[derive(Clone, Copy, Debug)]
 pub struct sctp_assoc_change {
	pub sac_type: u16,
	pub sac_flags: u16,
	pub sac_length: u32,
	pub sac_state: u16,
	pub sac_error: u16,
	pub sac_outbound_streams: u16,
	pub sac_inbound_streams: u16,
	pub sac_assoc_id: sctp_assoc_t,
	// pub sac_info: [u8],
}

/*
 *   sac_state: 32 bits (signed integer)
 *
 *   This field holds one of a number of values that communicate the
 *   event that happened to the association.  They include:
 *
 *   Note:  The following state names deviate from the API draft as
 *   the names clash too easily with other kernel symbols.
 */
#[repr(C)]
 pub enum sctp_sac_state {
	SCTP_COMM_UP,
	SCTP_COMM_LOST,
	SCTP_RESTART,
	SCTP_SHUTDOWN_COMP,
	SCTP_CANT_STR_ASSOC,
}

/*
 * 5.3.1.5 SCTP_SHUTDOWN_EVENT
 *
 *   When a peer sends a SHUTDOWN, SCTP delivers this notification to
 *   inform the application that it should cease sending data.
 */
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sctp_shutdown_event {
	pub sse_type: u16,
	pub sse_flags: u16,
	pub sse_length: u32,
	pub sse_assoc_id: sctp_assoc_t,
}

/*
 * 6.1.9. SCTP_SENDER_DRY_EVENT
 *
 * When the SCTP stack has no more user data to send or retransmit, this
 * notification is given to the user. Also, at the time when a user app
 * subscribes to this event, if there is no data to be sent or
 * retransmit, the stack will immediately send up this notification.
 */
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sctp_sender_dry_event {
	pub sender_dry_type: u16,
	pub sender_dry_flags: u16,
	pub sender_dry_length: u32,
	pub sender_dry_assoc_id: sctp_assoc_t,
}

#[repr(C)]
pub struct sctp_stream_reset_event {
	pub strreset_type: u16,
	pub strreset_flags: u16,
	pub strreset_length: u32,
	pub strreset_assoc_id: sctp_assoc_t,
	pub strreset_stream_list: [u16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sctp_assoc_reset_event {
	pub assocreset_type: u16,
	pub assocreset_flags: u16,
	pub assocreset_length: u32,
	pub assocreset_assoc_id: sctp_assoc_t,
	pub assocreset_local_tsn: u32,
	pub assocreset_remote_tsn: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sctp_stream_change_event {
	pub strchange_type: u16,
	pub strchange_flags: u16,
	pub strchange_length: u32,
	pub strchange_assoc_id: sctp_assoc_t,
	pub strchange_instrms: u16,
	pub strchange_outstrms: u16,
}

/*
 * 5.3.1 SCTP Notification Structure
 *
 *   The notification structure is defined as the union of all
 *   notification types.
 *
 */
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sn_header {
	pub sn_type: u16,             /* Notification type. */
	pub sn_flags: u16,
	pub sn_length: u32,
}

/* Section 5.3.1
 * All standard values for sn_type flags are greater than 2^15.
 * Values from 2^15 and down are reserved.
 */
#[repr(u16)]
pub enum sctp_sn_type {
	SCTP_DATA_IO_EVENT	= (1<<15),
	SCTP_ASSOC_CHANGE,
	SCTP_PEER_ADDR_CHANGE,
	SCTP_SEND_FAILED,
	SCTP_REMOTE_ERROR,
	SCTP_SHUTDOWN_EVENT,
	SCTP_PARTIAL_DELIVERY_EVENT,
	SCTP_ADAPTATION_INDICATION,
	SCTP_AUTHENTICATION_EVENT,
	SCTP_SENDER_DRY_EVENT,
	SCTP_STREAM_RESET_EVENT,
	SCTP_ASSOC_RESET_EVENT,
	SCTP_STREAM_CHANGE_EVENT,
	SCTP_SEND_FAILED_EVENT,
}

#[repr(C)]
pub struct sctp_assoc_value {
	pub assoc_id: sctp_assoc_t,
	pub assoc_value: u32,
}

#[repr(C)]
pub struct sctp_stream_value {
	pub assoc_id: sctp_assoc_t,
	pub stream_id: u16,
	pub stream_value: u16,
}

#[repr(C)]
pub struct sctp_default_prinfo {
	pub pr_assoc_id: sctp_assoc_t,
	pub pr_value: u32,
	pub pr_policy: u16,
}

#[repr(C)]
pub struct sctp_reset_streams {
	pub srs_assoc_id: sctp_assoc_t,
	pub srs_flags: u16,
	pub srs_number_streams: u16,	/* 0 == ALL */
	pub srs_stream_list: [u16],	/* list if srs_num_streams is not 0 */
}

#[repr(C)]
pub struct sctp_add_streams {
	pub sas_assoc_id: sctp_assoc_t,
	pub sas_instrms: u16,
	pub sas_outstrms: u16,
}

#[repr(C)]
pub struct sctp_event {
	pub se_assoc_id: sctp_assoc_t,
	pub se_type: u16,
	pub se_on: u8,
}

#[repr(C)]
pub struct sctp_udpencaps {
	pub sue_assoc_id: sctp_assoc_t,
	pub sue_address: sockaddr_storage,
	pub sue_port: u16,
}
