use assert_cmd::prelude::*;
use predicates::prelude::*;
use serde_json::Value;
use std::process::Command;

#[test]
fn shows_help() {
    let mut cmd = Command::cargo_bin("ark_protocol").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Commands:"));
}

#[test]
fn new_prints_address_plaintext() {
    let mut cmd = Command::cargo_bin("ark_protocol").unwrap();
    cmd.arg("new")
        .assert()
        .success()
        .stdout(predicate::str::contains("Address:"));
}

#[test]
fn new_outputs_valid_json() {
    let mut cmd = Command::cargo_bin("ark_protocol").unwrap();
    let assert = cmd.arg("--json").arg("new").assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(&out).expect("output should be valid JSON");
    assert!(v.get("address").is_some(), "json must contain 'address'");
}
