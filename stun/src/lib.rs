#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod attr;
mod stun;
mod error;
mod rfc8489;
mod rfc8656;
mod rfc8445;

#[macro_use]
mod util;

#[cfg(test)]
mod rfc5769;

const MAGIC_COOKIE: u32 = 0x2112A442;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
	Request,
	Indication,
	Success,
	Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Method {
	#[doc(hidden)]
	Unknown = -1,

	Binding = 0x001,
	Allocate = 0x003,
	Refresh = 0x004,
	Send = 0x006,
	Data = 0x007,
	CreatePermission = 0x008,
	ChannelBind = 0x009,
}

declare!(Stun {
	u16 typ,
	u16 length,
	u32 cookie,
	[u8; 12] txid,
	len(20),
});

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Error {
	NotStun,
	TooShort(usize),
}
