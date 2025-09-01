#![cfg(feature = "backup")]

use assert_cmd::Command;
use uuid::Uuid;

#[test]
fn save_then_load_encrypted_via_cli() {
    let mut path = std::env::temp_dir();
    path.push(format!("ark_cli_{}.json", Uuid::new_v4()));

    let pwd = "StrongPwd_123456!";
    // save
    let assert = Command::cargo_bin("ark_protocol")
        .unwrap()
        .arg("save-encrypted")
        .arg("--file")
        .arg(path.to_string_lossy().to_string())
        .arg("--password-stdin")
        .write_stdin(format!("{pwd}\n"))
        .assert();
    assert
        .success()
        .stdout(predicates::str::contains("Saved wallet:"));

    // load
    let assert2 = Command::cargo_bin("ark_protocol")
        .unwrap()
        .arg("load-encrypted")
        .arg("--file")
        .arg(path.to_string_lossy().to_string())
        .arg("--password-stdin")
        .write_stdin(format!("{pwd}\n"))
        .assert();
    assert2
        .success()
        .stdout(predicates::str::contains("Address:"));

    let _ = std::fs::remove_file(&path);
}
