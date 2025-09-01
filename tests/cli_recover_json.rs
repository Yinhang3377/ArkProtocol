#![cfg(feature = "hd")]

use assert_cmd::Command;
use predicates::str; // 新增导入

#[test]
fn recover_outputs_json_when_flag_set() {
    // 先拿一组英文助记词
    let out = Command::cargo_bin("ark_protocol")
        .unwrap()
        .args(["mnemonic", "--lang", "english"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let phrase = String::from_utf8_lossy(&out)
        .trim()
        .trim_start_matches("Mnemonic: ")
        .to_string();

    // 使用 --json 恢复，检查 JSON 结构
    Command::cargo_bin("ark_protocol")
        .unwrap()
        .args([
            "--json",
            "recover",
            "--phrase",
            &phrase,
            "--lang",
            "english",
            "--path",
            "m/44'/60'/0'/0/0",
        ])
        .assert()
        .success()
        .stdout(str::is_match(r#"\{\s*"address"\s*:\s*".+"\s*\}"#).unwrap());
}

#[test]
fn recover_outputs_json_address() {
    let phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut cmd = Command::cargo_bin("ark_protocol").unwrap();
    cmd.arg("recover")
        .arg("--phrase")
        .arg(phrase)
        .arg("--lang")
        .arg("english")
        .arg("--passphrase")
        .arg("")
        .arg("--path")
        .arg("m/44'/60'/0'/0/0")
        .arg("--json");

    cmd.assert()
        .success()
        .stdout(str::is_match(r#"\{\s*"address"\s*:\s*".+"\s*\}"#).unwrap());
}
