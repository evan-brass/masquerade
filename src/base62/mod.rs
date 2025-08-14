const B62_CHARSET: &[char] = &[
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
	'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
	'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
	'5', '6', '7', '8', '9',
];
pub fn to_base62(fingerprint: &mut [u8]) -> String {
	let mut res = [0; 43];
	for j in 0..43 {
		let mut remainder = 0;
		for i in 0..32 {
			let v = 256 * remainder + fingerprint[i] as u32;
			remainder = v % 62;
			fingerprint[i] = (v / 62) as u8;
		}
		res[j] = remainder as u8;
	}
	res.reverse();

	let mut ret = String::with_capacity(43);

	for i in res {
		if ret.is_empty() && i == 0 {
			continue;
		}
		ret.push(B62_CHARSET[i as usize]);
	}
	if ret.is_empty() {
		ret.push('A');
	}

	ret
}
