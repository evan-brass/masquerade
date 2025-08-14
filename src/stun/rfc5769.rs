//! Test Vectors for STUN
//!
use super::*;
use attr::{integrity::Integrity, parse::AttrIter};
// use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};

const VECTOR_2_1: &[u8] = &[
	0x00, 0x01, 0x00, 0x58, //     Request type and message length
	0x21, 0x12, 0xa4, 0x42, //     Magic cookie
	0xb7, 0xe7, 0xa7, 0x01, //  }
	0xbc, 0x34, 0xd6, 0x86, //  }  Transaction ID
	0xfa, 0x87, 0xdf, 0xae, //  }
	0x80, 0x22, 0x00, 0x10, //     SOFTWARE attribute header
	0x53, 0x54, 0x55, 0x4e, //  }
	0x20, 0x74, 0x65, 0x73, //  }  User-agent...
	0x74, 0x20, 0x63, 0x6c, //  }  ...name
	0x69, 0x65, 0x6e, 0x74, //  }
	0x00, 0x24, 0x00, 0x04, //     PRIORITY attribute header
	0x6e, 0x00, 0x01, 0xff, //     ICE priority value
	0x80, 0x29, 0x00, 0x08, //     ICE-CONTROLLED attribute header
	0x93, 0x2f, 0xf9, 0xb1, //  }  Pseudo-random tie breaker...
	0x51, 0x26, 0x3b, 0x36, //  }   ...for ICE control
	0x00, 0x06, 0x00, 0x09, //     USERNAME attribute header
	0x65, 0x76, 0x74, 0x6a, //  }
	0x3a, 0x68, 0x36, 0x76, //  }  Username (9 bytes) and padding (3 bytes)
	0x59, 0x20, 0x20, 0x20, //  }
	0x00, 0x08, 0x00, 0x14, //     MESSAGE-INTEGRITY attribute header
	0x9a, 0xea, 0xa7, 0x0c, //  }
	0xbf, 0xd8, 0xcb, 0x56, //  }
	0x78, 0x1e, 0xf2, 0xb5, //  }  HMAC-SHA1 fingerprint
	0xb2, 0xd3, 0xf2, 0x49, //  }
	0xc1, 0xb5, 0x71, 0xa2, //  }
	0x80, 0x28, 0x00, 0x04, //     FINGERPRINT attribute header
	0xe5, 0x7a, 0x3b, 0xcf, //     CRC32 fingerprint
];

#[test]
fn decode_vector_2_1() {
	let msg = Stun::new(VECTOR_2_1);
	assert_eq!(msg.decode(VECTOR_2_1.len()), Ok(()));
	assert_eq!(msg.class(), Class::Request);
	assert_eq!(msg.method(), Method::Binding);

	let mut software = None;
	let mut priority = None;
	let mut ice_controlled = None;
	let mut username = None;
	let mut integrity = None;
	let mut fingerprint = None;

	let unknown: Option<[u16; 4]> = msg
		.into_iter()
		.parse::<{ attr::SOFTWARE }, &str>(&mut software)
		.parse::<{ attr::PRIORITY }, u32>(&mut priority)
		.parse::<{ attr::ICE_CONTROLLED }, u64>(&mut ice_controlled)
		.parse::<{ attr::USERNAME }, &str>(&mut username)
		.parse::<{ attr::MESSAGE_INTEGRITY }, Integrity<20>>(&mut integrity)
		.parse::<{ attr::FINGERPRINT }, ()>(&mut fingerprint)
		.collect_unknown();

	assert_eq!(unknown, None);
	assert_eq!(software, Some("STUN test client"));
	assert_eq!(priority, Some(0x6e0001ff));
	assert_eq!(ice_controlled, Some(0x932ff9b151263b36));
	assert_eq!(username, Some("evtj:h6vY"));
	let key = "VOkJxbRl1RmTxUk/WvJxBt".as_bytes();
	assert_eq!(integrity.as_ref().map(|a| a.verify(key)), Some(true));
	let key = "wrong password".as_bytes();
	assert_eq!(integrity.map(|a| a.verify(key)), Some(false));
	assert_eq!(fingerprint, Some(()));
}

// TODO: Add an encoding test. for vector 2_1 and tests for the other vectors.
