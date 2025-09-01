use crate::common::{Result, CHECKSUM_LEN, MAINNET_P2PKH_VERSION};
use anyhow::{anyhow, Context}; // 删掉 anyhow::Result，避免重名
use bs58;
use rand::rngs::OsRng;
use rand::RngCore;
use ripemd::Ripemd160;
use secp256k1::{ecdsa::Signature, PublicKey, Secp256k1, SecretKey}; // 移除 Message
use sha2::{Digest, Sha256}; // 新增：Digest trait 与 Sha256
use zeroize::Zeroize;

/// 生成新的 secp256k1 密钥对（兼容 secp256k1 v0.27）
pub fn generate_keypair() -> Result<(SecretKey, PublicKey)> {
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    loop {
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        if let Ok(secret_key) = SecretKey::from_slice(&sk_bytes) {
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            sk_bytes.zeroize(); // 清除内存中的随机种子
            return Ok((secret_key, public_key));
        }
        sk_bytes.zeroize();
    }
}

/// 生成 Base58Check P2PKH 地址（非压缩公钥）。默认主网版本字节 0x00。
pub fn public_key_to_address(public_key: &PublicKey) -> Result<String> {
    public_key_to_address_with_version(public_key, MAINNET_P2PKH_VERSION)
}

/// 生成 Base58Check P2PKH 地址（非压缩公钥），自定义版本字节（主网=0x00，测试网=0x6f）。
pub fn public_key_to_address_with_version(public_key: &PublicKey, version: u8) -> Result<String> {
    // 非压缩公钥（65字节，前缀 0x04）
    let pub_key_uncompressed = public_key.serialize_uncompressed();

    // HASH160(pubkey) = RIPEMD160(SHA256(pubkey))
    let sha256_hash = Sha256::digest(pub_key_uncompressed);
    let ripemd160_hash = Ripemd160::digest(sha256_hash);

    // 版本字节 + HASH160
    let mut versioned_payload = vec![version];
    versioned_payload.extend_from_slice(&ripemd160_hash);

    // 校验和（双 SHA-256 前4字节）
    let first_hash = Sha256::digest(&versioned_payload);
    let second_hash = Sha256::digest(first_hash);
    let checksum = &second_hash[..CHECKSUM_LEN];

    // 拼接后 Base58 编码
    let mut final_payload = versioned_payload;
    final_payload.extend_from_slice(checksum);
    Ok(bs58::encode(final_payload).into_string())
}

/// 对消息做 SHA-256 后进行 ECDSA 签名
pub fn sign_message_sha256(sk: &SecretKey, msg: &[u8]) -> Result<Signature> {
    use sha2::Digest; // 确保 trait 在作用域
    let hash = Sha256::digest(msg);
    let m =
        secp256k1::Message::from_digest_slice(&hash).context("sha256 digest must be 32 bytes")?;
    let secp = Secp256k1::new();
    Ok(secp.sign_ecdsa(&m, sk))
}

/// 验证签名（消息先做 SHA-256）
pub fn verify_message_sha256(pk: &PublicKey, sig: &Signature, msg: &[u8]) -> Result<bool> {
    use sha2::Digest;
    let hash = Sha256::digest(msg);
    let m =
        secp256k1::Message::from_digest_slice(&hash).context("sha256 digest must be 32 bytes")?;
    let secp = Secp256k1::new();
    match secp.verify_ecdsa(&m, sig, pk) {
        Ok(()) => Ok(true),
        Err(e @ (secp256k1::Error::InvalidSignature | secp256k1::Error::IncorrectSignature)) => {
            let _ = e;
            Ok(false)
        }
        Err(e) => Err(anyhow!(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_address_generation_from_known_key() -> Result<()> {
        // 私钥: E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262
        // 非压缩公钥 P2PKH 地址: 1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_str(
            "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262",
        )?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = public_key_to_address(&public_key)?;
        assert_eq!(address, "1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj");
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_sha256() -> Result<()> {
        let (sk, pk) = generate_keypair()?;
        let msg = b"ark-protocol";
        let sig = sign_message_sha256(&sk, msg)?;
        assert!(verify_message_sha256(&pk, &sig, msg)?);
        assert!(!verify_message_sha256(&pk, &sig, b"ark-protocol!")?);
        Ok(())
    }
}
