//! 简单 HD 钱包（BIP39 + BIP32(secp256k1)）
//!
//! 用法（需启用 feature="hd"）：
//! let hd = HdWallet::new_12()?; // 或 new_24()
//! let xprv = hd.derive_xprv("m/44'/0'/0'/0/0")?;

use anyhow::{Context, Result};
use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic};
use rand::{rngs::OsRng, RngCore};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::str::FromStr;

pub struct HdWallet {
    mnemonic: Mnemonic,
}

impl HdWallet {
    // 生成 12 词助记词（16 字节熵）
    pub fn new_12() -> Result<Self> {
        let mut entropy = [0u8; 16];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .context("generate 12-word mnemonic")?;
        Ok(Self { mnemonic })
    }

    // 生成 24 词助记词（32 字节熵）
    pub fn new_24() -> Result<Self> {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .context("generate 24-word mnemonic")?;
        Ok(Self { mnemonic })
    }

    // 从短语构建（自动规范化）
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let mnemonic =
            Mnemonic::parse_in_normalized(Language::English, phrase).context("parse mnemonic")?;
        Ok(Self { mnemonic })
    }

    // 返回助记词短语
    pub fn phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    // 从路径派生 XPrv（空口令）
    pub fn derive_xprv(&self, path: &str) -> Result<XPrv> {
        let dp = DerivationPath::from_str(path).context("parse derivation path")?;
        // bip39 1.x：产生 64 字节种子
        let seed: [u8; 64] = self.mnemonic.to_seed_normalized("");
        let xprv = XPrv::derive_from_path(seed, &dp).context("derive xprv from path")?;
        Ok(xprv)
    }

    // 示例：从路径派生 secp256k1 密钥对
    pub fn derive_secp256k1_keypair(&self, path: &str) -> Result<(SecretKey, PublicKey)> {
        let xprv = self.derive_xprv(path)?;
        let sk_bytes = xprv.private_key().to_bytes();
        let sk = SecretKey::from_slice(&sk_bytes).context("secp256k1 secret key")?;
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        Ok((sk, pk))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn test_mnemonic12_generate_and_parse() {
        let hd = HdWallet::new_12().unwrap();
        let phrase = hd.phrase();
        let hd2 = HdWallet::from_phrase(&phrase).unwrap();
        assert_eq!(phrase, hd2.phrase());
    }

    #[test]
    fn test_derive_xprv() {
        let hd = HdWallet::new_12().unwrap();
        let xprv = hd.derive_xprv("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(xprv.private_key().to_bytes().len(), 32);
    }
}
