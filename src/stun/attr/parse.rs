use super::{Attr, Prefix};

pub fn comprehension_required(typ: u16) -> bool {
	typ < 0x8000
}

pub trait AttrIter<'i>: Iterator<Item = (Prefix<'i>, u16, &'i [u8])> + Sized {
	fn parse_with_err<'d, const T: u16, A: Attr<'i, T>>(
		self,
		dest: &'d mut Option<Result<A, A::Error>>,
	) -> impl AttrIter<'i> {
		AttrParser::new::<'i, T, A>(self, |prefix, value| *dest = Some(A::decode(prefix, value)))
	}
	fn parse<'d, const T: u16, A: Attr<'i, T>>(self, dest: &'d mut Option<A>) -> impl AttrIter<'i> {
		AttrParser::new::<'i, T, A>(self, |prefix, value| *dest = A::decode(prefix, value).ok())
	}

	#[cfg(feature = "std")]
	fn collect_unknown_all(self) -> std::vec::Vec<u16> {
		self.map(|(_, typ, _)| typ)
			.filter(|t| comprehension_required(*t))
			.collect()
	}
	// Collect the first N unparsed attributes
	fn collect_unknown<const N: usize>(self) -> Option<[u16; N]> {
		let mut ret = [0; N];
		for (_, typ, _) in self {
			if comprehension_required(typ) {
				for d in ret.iter_mut() {
					if *d == typ {
						break;
					}
					if *d == 0 {
						*d = typ;
						break;
					}
				}
			}
		}
		if ret.iter().all(|t| *t == 0) {
			return None;
		}
		Some(ret)
	}
}
impl<'i, T: Iterator<Item = (Prefix<'i>, u16, &'i [u8])>> AttrIter<'i> for T {}

struct AttrParser<I, D> {
	inner: I,
	typ: u16,
	must_precede: fn(u16) -> bool,
	decode: Option<D>,
}
impl<I, D> AttrParser<I, D> {
	fn new<'i, const T: u16, A: Attr<'i, T>>(inner: I, decode: D) -> Self {
		Self {
			inner,
			typ: T,
			must_precede: A::must_precede,
			decode: Some(decode),
		}
	}
}

impl<'i, I: Iterator<Item = (Prefix<'i>, u16, &'i [u8])>, D: FnOnce(Prefix<'i>, &'i [u8])> Iterator
	for AttrParser<I, D>
{
	type Item = (Prefix<'i>, u16, &'i [u8]);
	fn next(&mut self) -> Option<Self::Item> {
		let (prefix, typ, value) = self.inner.next()?;

		if typ == self.typ {
			if let Some(func) = self.decode.take() {
				func(prefix, value);
			}
			return self.next();
		} else if (self.must_precede)(typ) {
			self.decode.take();
		}

		Some((prefix, typ, value))
	}
}
