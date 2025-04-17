use crc::Crc;

pub struct Sctp<B> {
	pub buffer: B,
}
impl Sctp<()> {
	pub const fn min_len() -> usize {
		12
	}
}
impl<B: AsRef<[u8]>> Sctp<B> {
	pub fn sport(&self) -> u16 {
		u16::from_be_bytes(self.buffer.as_ref()[0..2].try_into().unwrap())
	}
	pub fn dport(&self) -> u16 {
		u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
	}
	pub fn vtag(&self) -> u32 {
		u32::from_be_bytes(self.buffer.as_ref()[4..8].try_into().unwrap())
	}
	pub fn chksum(&self) -> u32 {
		u32::from_le_bytes(self.buffer.as_ref()[8..12].try_into().unwrap())
	}
	pub fn expected_chksum(&self, len: usize) -> u32 {
		const CRC: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_ISCSI);
		let mut hasher = CRC.digest();
		hasher.update(&self.buffer.as_ref()[0..8]);
		hasher.update(&[0, 0, 0, 0]);
		hasher.update(&self.buffer.as_ref()[12..len]);
		hasher.finalize()
	}
}
impl<B: AsMut<[u8]>> Sctp<B> {
	pub fn set_sport(&mut self, val: u16) {
		self.buffer.as_mut()[0..2].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_dport(&mut self, val: u16) {
		self.buffer.as_mut()[2..4].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_vtag(&mut self, val: u32) {
		self.buffer.as_mut()[4..8].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_chksum(&mut self, val: u32) {
		// Evan - you fucking dumbass - did you forget that the checksum on SCTP is little endian again?
		self.buffer.as_mut()[8..12].copy_from_slice(&val.to_le_bytes());
	}
}

pub struct Chunk<B> {
	pub buffer: B,
}
impl Chunk<()> {
	pub const fn min_len() -> usize {
		4
	}
}
impl<B: AsRef<[u8]>> Chunk<B> {
	pub fn typ(&self) -> u8 {
		self.buffer.as_ref()[0]
	}
	pub fn flags(&self) -> u8 {
		self.buffer.as_ref()[1]
	}
	pub fn length(&self) -> u16 {
		u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
	}

	pub fn len(&self) -> usize {
		self.length() as usize
	}
}
impl<B: AsMut<[u8]>> Chunk<B> {
	pub fn set_typ(&mut self, val: u8) {
		self.buffer.as_mut()[0] = val;
	}
	pub fn set_flags(&mut self, val: u8) {
		self.buffer.as_mut()[1] = val;
	}
	pub fn set_length(&mut self, val: u16) {
		self.buffer.as_mut()[2..4].copy_from_slice(&val.to_be_bytes());
	}
}

pub struct Param<B> {
	pub buffer: B,
}
impl Param<()> {
	pub const fn min_len() -> usize {
		4
	}
}
impl<B: AsRef<[u8]>> Param<B> {
	pub fn typ(&self) -> u16 {
		u16::from_be_bytes(self.buffer.as_ref()[0..2].try_into().unwrap())
	}
	pub fn length(&self) -> u16 {
		u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
	}

	pub fn len(&self) -> usize {
		self.length() as usize
	}
}
impl<B: AsMut<[u8]>> Param<B> {
	pub fn set_typ(&mut self, val: u16) {
		self.buffer.as_mut()[0..2].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_length(&mut self, val: u16) {
		self.buffer.as_mut()[2..4].copy_from_slice(&val.to_be_bytes());
	}
}

pub struct Data<B> {
	pub chunk: Chunk<B>,
}
impl Data<()> {
	pub const fn min_len() -> usize {
		16
	}
}
impl<B: AsRef<[u8]>> Data<B> {
	pub fn tsn(&self) -> u32 {
		u32::from_be_bytes(self.chunk.buffer.as_ref()[4..8].try_into().unwrap())
	}
	pub fn stream(&self) -> u16 {
		u16::from_be_bytes(self.chunk.buffer.as_ref()[8..10].try_into().unwrap())
	}
	pub fn seq(&self) -> u16 {
		u16::from_be_bytes(self.chunk.buffer.as_ref()[10..12].try_into().unwrap())
	}
	pub fn ppid(&self) -> u32 {
		u32::from_be_bytes(self.chunk.buffer.as_ref()[12..16].try_into().unwrap())
	}
}
impl<B: AsMut<[u8]>> Data<B> {
	pub fn set_tsn(&mut self, val: u32) {
		self.chunk.buffer.as_mut()[4..8].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_stream(&mut self, val: u16) {
		self.chunk.buffer.as_mut()[8..10].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_seq(&mut self, val: u16) {
		self.chunk.buffer.as_mut()[10..12].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_ppid(&mut self, val: u32) {
		self.chunk.buffer.as_mut()[12..16].copy_from_slice(&val.to_be_bytes());
	}
}

pub struct Init<B> {
	pub chunk: Chunk<B>,
}
impl Init<()> {
	pub const fn min_len() -> usize {
		20
	}
}
impl<B: AsRef<[u8]>> Init<B> {
	pub fn vtag(&self) -> u32 {
		u32::from_be_bytes(self.chunk.buffer.as_ref()[4..8].try_into().unwrap())
	}
	pub fn arwnd(&self) -> u32 {
		u32::from_be_bytes(self.chunk.buffer.as_ref()[8..12].try_into().unwrap())
	}
	pub fn num_out(&self) -> u16 {
		u16::from_be_bytes(self.chunk.buffer.as_ref()[12..14].try_into().unwrap())
	}
	pub fn num_in(&self) -> u16 {
		u16::from_be_bytes(self.chunk.buffer.as_ref()[14..16].try_into().unwrap())
	}
	pub fn tsn(&self) -> u32 {
		u32::from_be_bytes(self.chunk.buffer.as_ref()[16..20].try_into().unwrap())
	}
}
impl<B: AsMut<[u8]>> Init<B> {
	pub fn set_vtag(&mut self, val: u32) {
		self.chunk.buffer.as_mut()[4..8].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_arwnd(&mut self, val: u32) {
		self.chunk.buffer.as_mut()[8..12].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_num_out(&mut self, val: u16) {
		self.chunk.buffer.as_mut()[12..14].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_num_in(&mut self, val: u16) {
		self.chunk.buffer.as_mut()[14..16].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_tsn(&mut self, val: u32) {
		self.chunk.buffer.as_mut()[16..20].copy_from_slice(&val.to_be_bytes());
	}
}

pub struct Sack<B> {
	pub chunk: Chunk<B>,
}
impl Sack<()> {
	pub const fn min_len() -> usize {
		16
	}
}
impl<B: AsRef<[u8]>> Sack<B> {
	pub fn cum_tsn(&self) -> u32 {
		u32::from_be_bytes(self.chunk.buffer.as_ref()[4..8].try_into().unwrap())
	}
	pub fn arwnd(&self) -> u32 {
		u32::from_be_bytes(self.chunk.buffer.as_ref()[8..12].try_into().unwrap())
	}
	pub fn gaps(&self) -> u16 {
		u16::from_be_bytes(self.chunk.buffer.as_ref()[12..14].try_into().unwrap())
	}
	pub fn dups(&self) -> u16 {
		u16::from_be_bytes(self.chunk.buffer.as_ref()[14..16].try_into().unwrap())
	}
}
impl<B: AsMut<[u8]>> Sack<B> {
	pub fn set_cum_tsn(&mut self, val: u32) {
		self.chunk.buffer.as_mut()[4..8].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_arwnd(&mut self, val: u32) {
		self.chunk.buffer.as_mut()[8..12].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_gaps(&mut self, val: u16) {
		self.chunk.buffer.as_mut()[12..14].copy_from_slice(&val.to_be_bytes());
	}
	pub fn set_dups(&mut self, val: u16) {
		self.chunk.buffer.as_mut()[14..16].copy_from_slice(&val.to_be_bytes());
	}
}
