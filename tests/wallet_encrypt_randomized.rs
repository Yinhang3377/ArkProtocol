use ark_protocol::wallet::Wallet;
use serde_json::Value;
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn saving_twice_produces_different_ciphertext_and_nonce() {
    let w = Wallet::new().unwrap();
    let pwd = b"a_very_strong_password";

    let ts = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    };

    let p1 = std::env::temp_dir().join(format!("ark_wallet_random_{}_1.json", ts()));
    let p2 = std::env::temp_dir().join(format!("ark_wallet_random_{}_2.json", ts()));

    w.save_encrypted(&p1, pwd).unwrap();
    w.save_encrypted(&p2, pwd).unwrap();

    let j1: Value = serde_json::from_slice(&fs::read(&p1).unwrap()).unwrap();
    let j2: Value = serde_json::from_slice(&fs::read(&p2).unwrap()).unwrap();

    let c1 = j1["ciphertext_hex"].as_str().unwrap();
    let c2 = j2["ciphertext_hex"].as_str().unwrap();
    let s1 = j1["salt_hex"].as_str().unwrap();
    let s2 = j2["salt_hex"].as_str().unwrap();
    let n1 = j1["nonce_hex"].as_str().unwrap();
    let n2 = j2["nonce_hex"].as_str().unwrap();

    assert_ne!(c1, c2, "ciphertext should differ");
    assert_ne!(s1, s2, "salt should differ");
    assert_ne!(n1, n2, "nonce should differ");

    // 都能成功解密加载
    let _ = Wallet::load_encrypted(&p1, pwd).unwrap();
    let _ = Wallet::load_encrypted(&p2, pwd).unwrap();

    let _ = fs::remove_file(p1);
    let _ = fs::remove_file(p2);
}
