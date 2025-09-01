#![cfg(feature = "hd")]

use assert_cmd::prelude::*;
use serde_json::Value;
use std::process::Command;

fn is_valid_word_count(n: usize) -> bool {
    matches!(n, 12 | 15 | 18 | 21 | 24)
}

#[test]
fn mnemonic_plaintext_has_valid_word_count() {
    let mut cmd = Command::cargo_bin("ark_protocol").unwrap();
    let assert = cmd
        .args(["mnemonic", "--lang", "english"])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let wc = out.split_whitespace().count();
    assert!(is_valid_word_count(wc), "invalid word count: {wc}");
}

#[test]
fn mnemonic_json_ok() {
    let mut cmd = Command::cargo_bin("ark_protocol").unwrap();
    let assert = cmd
        .args(["--json", "mnemonic", "--lang", "english"])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(&out).expect("valid JSON");
    let m = v
        .get("mnemonic")
        .and_then(|x| x.as_str())
        .expect("mnemonic string");
    let wc = m.split_whitespace().count();
    assert!(is_valid_word_count(wc), "invalid word count: {wc}");
}

#[test]
fn recover_json_has_address_and_pubkey() {
    // 使用你刚才验证过的 12 词助记词
    let phrase = "elite usual scrap left mercy gesture sure tree hammer turtle toss coral";

    let mut cmd = Command::cargo_bin("ark_protocol").unwrap();
    let assert = cmd
        .args([
            "--json",
            "recover",
            "--phrase",
            phrase,
            "--lang",
            "english",
            "--passphrase=",
            "--path",
            "m/44'/60'/0'/0/0",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(&out).expect("valid JSON");
    let addr = v.get("address").and_then(|x| x.as_str()).expect("address");
    let pk = v
        .get("public_key")
        .and_then(|x| x.as_str())
        .expect("public_key");

    // 轻量校验：非空且格式大致正确
    assert!(!addr.is_empty(), "address should not be empty");
    assert!(
        addr.len() >= 26 && addr.len() <= 62,
        "address length looks wrong"
    );
    assert!(bs58::decode(addr).into_vec().is_ok(), "address not base58");

    assert!(!pk.is_empty(), "public_key should not be empty");
    assert!(hex::decode(pk).is_ok(), "public_key not hex");
}
