#![cfg(feature = "hd")]

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt; // 若使用 .or/.and 需要
use predicates::str::{contains, is_match};

#[test]
fn shows_help() {
    Command::cargo_bin("ark_protocol")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Ark Protocol CLI"));
}

#[cfg(feature = "hd")]
#[test]
fn mnemonic_english() {
    Command::cargo_bin("ark_protocol")
        .unwrap()
        .args(["mnemonic", "--lang", "english"])
        .assert()
        .success()
        .stdout(is_match(r"(?:^Mnemonic:\s+)?\w+( \w+){11}").unwrap());
}

#[test]
fn mnemonic_en_and_cn_and_json() {
    // 英文：既接受纯助记词也接受带前缀
    Command::cargo_bin("ark_protocol")
        .unwrap()
        .args(["mnemonic", "--lang", "english"])
        .assert()
        .success()
        .stdout(is_match(r"(?:^Mnemonic:\s+)?\w+( \w+){11}").unwrap());

    // 中文（别名 chinese-simplified）
    Command::cargo_bin("ark_protocol")
        .unwrap()
        .args(["mnemonic", "--lang", "chinese-simplified"])
        .assert()
        .success()
        .stdout(is_match(r"(?:^Mnemonic:\s+)?.+").unwrap());

    // JSON 输出
    Command::cargo_bin("ark_protocol")
        .unwrap()
        .args(["--json", "mnemonic", "--lang", "english"])
        .assert()
        .success()
        .stdout(is_match(r#"\{\s*"mnemonic"\s*:\s*".+"\s*\}"#).unwrap());
}

#[test]
fn recover_roundtrip_cn() {
    // 先生成中文助记词
    let out = Command::cargo_bin("ark_protocol")
        .unwrap()
        .args(["mnemonic", "--lang", "chinese-simplified"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let phrase = String::from_utf8_lossy(&out)
        .trim()
        .trim_start_matches("Mnemonic: ")
        .to_string();

    // 用同一助记词恢复，校验输出里有地址
    Command::cargo_bin("ark_protocol")
        .unwrap()
        .args([
            "recover",
            "--phrase",
            &phrase,
            "--lang",
            "chinese-simplified",
            "--path",
            "m/44'/60'/0'/0/0",
        ])
        .assert()
        .success()
        .stdout(
            contains("address")
                .or(contains("Recovered address"))
                .or(contains("Address")),
        );
}
