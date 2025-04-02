#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod attr;
mod error;
mod rfc8445;
mod rfc8489;
mod rfc8656;
mod stun;

#[macro_use]
mod util;

#[cfg(test)]
mod rfc5769;

pub const MAGIC_COOKIE: u32 = 0x2112A442;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
	Request,
	Indication,
	Success,
	Error,
}

spec_enum!(Method:u16 {
	Binding = 0x001 "RFC8489",
	Allocate = 0x003 "RFC8656",
	Refresh = 0x004 "RFC8656",
	Send = 0x006 "RFC8656",
	Data = 0x007 "RFC8656",
	CreatePermission = 0x008 "RFC8656",
	ChannelBind = 0x009 "RFC8656",
});

declare!(Stun {
	u16 typ,
	len(Self::MIN_LEN, u16 length),
	u32 cookie,
	[u8; 12] txid,
});

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Error {
	NotStun,
	TooShort(usize),
}
