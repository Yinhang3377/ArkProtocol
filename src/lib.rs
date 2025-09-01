#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::items_after_test_module
    )
)]

pub mod common;
pub mod crypto;
pub mod wallet;

#[cfg(feature = "hd")]
pub mod hd;

pub mod errors; // 新增

// Prefer a single source for each symbol to avoid ambiguity:
pub use crate::crypto::{
    generate_keypair, public_key_to_address, sign_message_sha256, verify_message_sha256,
};
pub use crate::wallet::Wallet;
