#[allow(unused)]
pub struct VarIter<'i, C, I> {
	pub buffer: &'i [u8],
	container: core::marker::PhantomData<C>,
	item: core::marker::PhantomData<I>,
}
#[allow(unused)]
impl<'i, C, I> VarIter<'i, C, I> {
	pub fn new(buffer: &'i [u8]) -> Self {
		Self {
			buffer,
			container: core::marker::PhantomData,
			item: core::marker::PhantomData,
		}
	}
}

macro_rules! declare_be_field {
	($name:ident, $offset:expr, $field:ident, $typ:ty, $len:literal) => {
		impl<B: ::core::borrow::Borrow<[u8]>> $name<B> {
			pub fn $field(&self) -> $typ {
				<$typ>::from_be_bytes(self.buffer.borrow()[$offset..][..$len].try_into().unwrap())
			}
		}
		paste::paste! {
			impl<B: ::core::borrow::BorrowMut<[u8]>> $name<B> {
				pub fn [<set_ $field>](&mut self, value: $typ) {
					self.buffer.borrow_mut()[$offset..][..$len].copy_from_slice(
						&value.to_be_bytes()
					);
				}
			}
		}
	};
}

macro_rules! declare_fields {
	($name:ident, $offset:expr, $align:literal, $len_offset:expr, $len_field:ident, ) => {
		impl<B: ::core::borrow::Borrow<[u8]>> $name<B> {
			pub const ALIGN: usize = $align;
			pub const MIN_LEN: usize = $offset;
			pub fn new(buffer: B) -> Self {
				assert!(buffer.borrow().len() >= Self::MIN_LEN);
				Self { buffer }
			}
			#[doc(hidden)]
			pub fn fakededed_length(&self) -> usize {
				self.buffer.borrow().len() - $len_offset
			}
			pub fn len(&self) -> usize {
				self.$len_field() as usize + $len_offset
			}
		}
	};
	($name:ident, $offset:expr, $align:literal, $len_offset:expr, $len_field:ident, ...$typ:ident,) => {
		impl<'i, B> Iterator for crate::stun::util::VarIter<'i, $name<B>, $typ<&'i [u8]>> {
			type Item = $typ<&'i [u8]>;
			fn next(&mut self) -> Option<Self::Item> {
				if self.buffer.len() < $typ::<&'i [u8]>::MIN_LEN { return None }
				let ret = $typ { buffer: self.buffer };
				let align = $typ::<&'i [u8]>::ALIGN;
				let len = ret.len();
				if self.buffer.len() < len { return None }
				let ret = $typ { buffer: &self.buffer[..len] };
				let padding = (align - len % align) % align;
				let total = len + padding;

				self.buffer = if self.buffer.len() >= total { &self.buffer[total..] } else { &[] };

				Some(ret)
			}
		}
		paste::paste! {
			impl<'i, B: ::core::borrow::Borrow<[u8]>> $name<B> {
				pub fn [<$typ:lower s>](&self) -> crate::stun::util::VarIter<'_, $name<B>, $typ<&[u8]>> {
					crate::stun::util::VarIter::new(&self.buffer.borrow()[$name::<B>::MIN_LEN..][..self.len()])
				}
			}
		}
		declare_fields!($name, $offset, $align, $len_offset, $len_field, );
	};
	($name:ident, $offset:expr, $align:literal, $_1:expr, $_2:ident, len($len_offset:expr, $typ:ident $field:ident), $($fields:tt)*) => {
		declare_fields!($name, $offset, $align, $len_offset, $field, $typ $field, $($fields)*);
	};
	($name:ident, $offset:expr, $_:literal, $len_offset:expr, $len_field:ident, align($align:literal), $($fields:tt)*) => {
		declare_fields!($name, $offset, $align, $len_offset, $len_field, $($fields)*);
	};
	($name:ident, $offset:expr, $align:literal, $len_offset:expr, $len_field:ident, u8 $field:ident, $($fields:tt)*) => {
		impl<B: ::core::borrow::Borrow<[u8]>> $name<B> {
			pub fn $field(&self) -> u8 {
				self.buffer.borrow()[$offset]
			}
		}
		paste::paste! {
			impl<B: ::core::borrow::BorrowMut<[u8]>> $name<B> {
				pub fn [<set_ $field>](&mut self, value: u8) {
					self.buffer.borrow_mut()[$offset] = value;
				}
			}
		}
		declare_fields!($name, $offset + 1, $align, $len_offset, $len_field, $($fields)*);
	};
	($name:ident, $offset:expr, $align:literal, $len_offset:expr, $len_field:ident, u16 $field:ident, $($fields:tt)*) => {
		declare_be_field!($name, $offset, $field, u16, 2);
		declare_fields!($name, $offset + 2, $align, $len_offset, $len_field, $($fields)*);
	};
	($name:ident, $offset:expr, $align:literal, $len_offset:expr, $len_field:ident, u32 $field:ident, $($fields:tt)*) => {
		declare_be_field!($name, $offset, $field, u32, 4);
		declare_fields!($name, $offset + 4, $align, $len_offset, $len_field, $($fields)*);
	};
	($name:ident, $offset:expr, $align:literal, $len_offset:expr, $len_field:ident, [u8; $n:literal] $field:ident, $($fields:tt)*) => {
		impl<B: ::core::borrow::Borrow<[u8]>> $name<B> {
			pub fn $field(&self) -> &[u8; $n] {
				self.buffer.borrow()[$offset..][..$n].try_into().unwrap()
			}
		}
		paste::paste! {
			impl<B: ::core::borrow::BorrowMut<[u8]>> $name<B> {
				pub fn [<set_ $field>](&mut self) -> &mut [u8; $n] {
					(&mut self.buffer.borrow_mut()[$offset..][..$n]).try_into().unwrap()
				}
			}
		}
		declare_fields!($name, $offset + $n, $align, $len_offset, $len_field, $($fields)*);
	};
}

#[macro_export]
#[doc(hidden)]
macro_rules! declare {
	($name:ident { $($fields:tt)* }) => {
		pub struct $name<B> {
			pub buffer: B
		}
		declare_fields!($name, 0, 1, 0, fakededed_length, $($fields)*);
	};
}

#[macro_export]
#[doc(hidden)]
macro_rules! spec_enum {
	($name:ident:$disc:ty { $($variant:ident = $val:literal $rfc:literal,)*}) => {
		paste::paste! {
			#[derive(Debug, Clone, Copy, PartialEq, Eq)]
			#[non_exhaustive]
			pub enum $name {
				#[doc(hidden)]
				Unknown = -1,

				$(
					#[doc = "Defined in [" $rfc "](https://datatracker.ietf.org/doc/html/" $rfc ")"]
					$variant = $val,
				)*
			}
		}
		impl From<$disc> for $name {
			fn from(value: $disc) -> Self {
				match value {
					$($val => Self::$variant,)*

					_ => Self::Unknown
				}
			}
		}
	};
}
