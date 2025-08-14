use super::Error;

impl core::fmt::Display for Error {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::NotStun => f.write_str(""),
			Self::TooShort(needed) => f.write_fmt(format_args!("Buffer too small or not filled with enough data. The operation can be retried with at least {needed} bytes."))
		}
	}
}
impl std::error::Error for Error {}

impl From<Error> for std::io::Error {
	fn from(value: Error) -> Self {
		std::io::Error::new(
			match value {
				Error::NotStun => std::io::ErrorKind::InvalidInput,
				Error::TooShort(_needed) => std::io::ErrorKind::UnexpectedEof,
			},
			value,
		)
	}
}
