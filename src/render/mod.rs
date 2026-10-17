//! Subscription renderers.
//!
//! Each format module turns one group into the body a client expects. They
//! share nothing but the resolved `(node, display name)` pairs, so a new format
//! is one new file plus a match arm in `routes`.

pub mod clash;
pub mod v2ray;
