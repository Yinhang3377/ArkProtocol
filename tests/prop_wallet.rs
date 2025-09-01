use ark_protocol::wallet::Wallet;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

proptest! {
    // 轻量：签名验签
    #![proptest_config(ProptestConfig { cases: 32, .. ProptestConfig::default() })]
    #[test]
    fn sign_verify_roundtrip(msg in proptest::collection::vec(any::<u8>(), 0..512)) {
        let w = Wallet::new().unwrap();
        let sig = w.sign_sha256(&msg)
            .map_err(|e| TestCaseError::fail(format!("sign failed: {e}")))?;
        prop_assert!(matches!(w.verify_sha256(&msg, &sig), Ok(true)));
    }
}

proptest! {
    // 轻量：加密/解密需要磁盘与 KDF，减少用例数
    #![proptest_config(ProptestConfig { cases: 8, .. ProptestConfig::default() })]
    #[test]
    fn encrypted_wallet_requires_same_password(pass in "\\PC{12,24}") {
        let w = Wallet::new().unwrap();
        let path = std::env::temp_dir().join(format!("ark_pw_{}.json", rand::random::<u64>()));
        w.save_encrypted(&path, pass.as_bytes()).unwrap();
        let ok = Wallet::load_encrypted(&path, pass.as_bytes());
        prop_assert!(ok.is_ok());
        let bad = Wallet::load_encrypted(&path, b"wrong_password");
        prop_assert!(bad.is_err());
        let _ = std::fs::remove_file(path);
    }
}

proptest! {
    #[test]
    fn verify_own_signature(msg in any::<Vec<u8>>()) {
        let w = Wallet::new().unwrap(); // 若也想去掉 unwrap，可改为 map_err(...)? 形式

        // 先把签名从 Result 提取为 Signature，避免 &Result 传参
        let sig = w.sign_sha256(&msg)
            .map_err(|e| TestCaseError::fail(format!("sign failed: {e}")))?;

        // verify_sha256 返回 Result<bool>，用 matches! 转成 bool 断言，避免 unwrap/expect
        prop_assert!(matches!(w.verify_sha256(&msg, &sig), Ok(true)));
    }
}
