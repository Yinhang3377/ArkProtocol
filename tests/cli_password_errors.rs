#[cfg(feature = "backup")]
use assert_cmd::prelude::*;
#[cfg(feature = "backup")]
use predicates::str::contains;
#[cfg(feature = "backup")]
use std::process::Command;

#[test]
#[cfg(feature = "backup")]
fn save_encrypted_without_password_should_fail() {
    Command::cargo_bin("ark_protocol")
        .unwrap()
        .args(["save-encrypted", "--file", "dummy.json"])
        .assert()
        .failure()
        .stderr(contains("no password provided"));
}

#[test]
#[cfg(feature = "backup")]
fn load_encrypted_with_wrong_password_should_fail() {
    let mut p = std::env::temp_dir();
    p.push(format!("ark_cli_wrong_pwd_{}.json", uuid::Uuid::new_v4()));
    let p_str = p.to_string_lossy().to_string();

    Command::cargo_bin("ark_protocol")
        .unwrap()
        .args([
            "save-encrypted",
            "--file",
            &p_str,
            "--password",
            "CorrectPwd_123!",
        ])
        .assert()
        .success();

    Command::cargo_bin("ark_protocol")
        .unwrap()
        .args([
            "load-encrypted",
            "--file",
            &p_str,
            "--password",
            "WrongPwd_123!",
        ])
        .assert()
        .failure()
        .stderr(contains("E_AUTH"));

    let _ = std::fs::remove_file(p);
}
