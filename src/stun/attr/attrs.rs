use crate::stun::Stun;
use core::borrow::Borrow;

pub struct Attrs<'i> {
	typ: [u8; 2],
	length: u16,
	rest: &'i [u8],
	offset: u16,
}
impl<'i> Iterator for Attrs<'i> {
	type Item = (super::Prefix<'i>, u16, &'i [u8]);
	fn next(&mut self) -> Option<Self::Item> {
		// Check the offset against the STUN length
		if self.offset >= self.length {
			return None;
		}
		let remaining = self.length - self.offset;
		if remaining < 4 {
			return None;
		}

		// Check the offset against the buffer's length
		let i = 16 + self.offset as usize;
		if self.rest.len() < i + 4 {
			return None;
		}

		// Read the attribute's header
		let attr_typ = u16::from_be_bytes(self.rest[i..][..2].try_into().unwrap());
		let attr_len = u16::from_be_bytes(self.rest[i + 2..][..2].try_into().unwrap());
		let attr_pad = (4 - attr_len % 4) % 4;

		// Consume the attribute header:
		let remaining = remaining - 4;
		let prefix = &self.rest[..i];
		let i = i + 4;

		// Check the attribute's length against the STUN header
		if remaining < attr_len {
			return None;
		}
		if remaining - attr_len < attr_pad {
			return None;
		}

		// Check the attribute's length against the buffer's length
		let end = i + attr_len as usize;
		if self.rest.len() < end {
			return None;
		}

		// Everything's good, construct the attribute
		let length_at = self.offset + 4 + attr_len + attr_pad;
		let mut first_four = [0; 4];
		first_four[..2].copy_from_slice(&self.typ);
		first_four[2..].copy_from_slice(&length_at.to_be_bytes());

		let value = &self.rest[i..end];

		self.offset = length_at;

		Some((super::Prefix { first_four, prefix }, attr_typ, value))
	}
}

impl<'i, B: Borrow<[u8]>> IntoIterator for &'i Stun<B> {
	type IntoIter = Attrs<'i>;
	type Item = (super::Prefix<'i>, u16, &'i [u8]);
	fn into_iter(self) -> Self::IntoIter {
		let buffer = self.buffer.borrow();
		let typ = if buffer.len() < 2 {
			[0, 0]
		} else {
			buffer[0..2].try_into().unwrap()
		};
		let length = if buffer.len() < 4 {
			0
		} else {
			u16::from_be_bytes(buffer[2..4].try_into().unwrap())
		};
		let rest = if buffer.len() < 4 { &[] } else { &buffer[4..] };

		Self::IntoIter {
			typ,
			length,
			rest,
			offset: 0,
		}
	}
}
