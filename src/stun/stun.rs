use attr::Prefix;

use crate::stun::*;
use core::borrow::{Borrow, BorrowMut};

impl<B: Borrow<[u8]>> Stun<B> {
	pub fn decode(&self, len: usize) -> Result<(), Error> {
		// len is supposed to mean how much of the internal buffer is filled with data from the network
		assert!(self.buffer.borrow().len() >= len);

		// Check first 2 bits of the typ
		if len < 2 {
			return Err(Error::TooShort(2));
		}
		if self.typ() >> 14 != 0 {
			return Err(Error::NotStun);
		}

		// Check the length
		if len < 4 {
			return Err(Error::TooShort(4));
		}
		let length = self.length();
		if !length.is_multiple_of(4) {
			return Err(Error::NotStun);
		}

		// Check the cookie
		if len < 8 {
			return Err(Error::TooShort(8));
		}
		if self.cookie() != MAGIC_COOKIE {
			return Err(Error::NotStun);
		}

		// Check if the buffer contains enough data for this size STUN message
		let exp_len = 20 + self.length() as usize;
		if len < exp_len {
			return Err(Error::TooShort(exp_len));
		}

		Ok(())
	}
	pub fn class(&self) -> Class {
		match self.typ() & 0x0110 {
			0x0000 => Class::Request,
			0x0010 => Class::Indication,
			0x0100 => Class::Success,
			0x0110 => Class::Error,
			_ => unreachable!(),
		}
	}
	#[doc(hidden)]
	pub fn raw_method(&self) -> u16 /* u12 */ {
		let typ = self.typ();
		(typ & 0x3E00) >> 2 | (typ & 0x00E0) >> 1 | (typ & 0x000F)
	}
	pub fn method(&self) -> Method {
		self.raw_method().into()
	}
}

impl<B: BorrowMut<[u8]>> Stun<B> {
	pub fn set_class(&mut self, class: Class) {
		let typ = self.typ();
		self.set_typ(
			typ & !0x0110
				| match class {
					Class::Request => 0x0000,
					Class::Indication => 0x0010,
					Class::Success => 0x0100,
					Class::Error => 0x0110,
				},
		);
	}
	#[doc(hidden)]
	pub fn set_raw_method(&mut self, method: u16) {
		assert!(method <= 0xFFF);
		let class = self.typ() & 0x0110;
		self.set_typ(class | (method & 0x1F80) << 2 | (method & 0x0070) << 1 | (method & 0x000F));
	}
	pub fn set_method(&mut self, method: Method) {
		self.set_raw_method(method as u16);
	}

	pub fn append<const T: u16, A: attr::AttrEnc<T>>(&mut self, attr: &A) -> Result<(), Error> {
		let attr_len = attr.length();
		let padd_len = (4 - attr_len % 4) % 4;
		let test = u16::MAX - 4 - padd_len;

		let buf = self.buffer.borrow_mut();
		let len = buf.len();

		// Check if the attribute's length is too big
		if test < attr_len {
			return Err(Error::NotStun);
		}
		let test = test - attr_len;

		// Check if we can read the current length
		if len < 4 {
			return Err(Error::TooShort(
				20 + 4 + attr_len as usize + padd_len as usize,
			));
		}
		let offset = u16::from_be_bytes(buf[2..4].try_into().unwrap());

		// Check if the attribute is too big to exist at this offset
		if test < offset {
			return Err(Error::NotStun);
		}

		let new_length = offset + 4 + attr_len + padd_len;
		let new_len = 20 + new_length as usize;

		// Check if the buffer is big enough to contain the new attribute
		if len < new_len {
			return Err(Error::TooShort(new_len));
		}

		// All checks complete
		let i = 20 + offset as usize;
		let (prefix, rest) = buf.split_at_mut(i);
		// Write the STUN length into the header
		prefix[2..4].copy_from_slice(&new_length.to_be_bytes());
		// Write the attribute type
		rest[0..2].copy_from_slice(&T.to_be_bytes());
		// Write the attribute length
		rest[2..4].copy_from_slice(&attr_len.to_be_bytes());
		// Write zeros to the padding bytes
		rest[4 + attr_len as usize..][..padd_len as usize].fill(0);
		// Create the prefix:
		let first_four = core::array::from_fn(|i| prefix[i]);
		let prefix = Prefix {
			first_four,
			prefix: &prefix[4..],
		};

		attr.encode(prefix, &mut rest[4..][..attr_len as usize]);

		Ok(())
	}
}

impl<B: Borrow<[u8]>> core::fmt::Debug for Stun<B> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("Stun")
			.field("class", &self.class())
			.field("method", &self.method())
			.field("txid", self.txid())
			.field("length", &self.length())
			.finish()
	}
}
