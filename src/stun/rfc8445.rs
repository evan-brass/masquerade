//! The ICE protocol
//! We only implement part of it

use super::attr::values::{empty_attr, numeric_attr};

numeric_attr!(PRIORITY, u32);
numeric_attr!(ICE_CONTROLLED, u64);
numeric_attr!(ICE_CONTROLLING, u64);
empty_attr!(USE_CANDIDATE);
