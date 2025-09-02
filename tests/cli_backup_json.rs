#![cfg(feature = "backup")]

use assert_cmd::prelude::*;
use serde_json::Value;
use std::process::Command;

#[test]
fn backup_and_cleanup_emit_valid_json() {
    // 目录与文件
    let dir = std::env::temp_dir().join(format!("ark_cli_json_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("wallet.dat");
    let file_str = file.to_string_lossy().to_string();

    // 先保存
    Command::cargo_bin("ark_protocol")
        .unwrap()
        .args([
            "save-encrypted",
            "--file",
            &file_str,
            "--password",
            "StrongPwd_123!",
        ])
        .assert()
        .success();

    // 备份（--json），解析 { "backup": "<path>" }
    let assert = Command::cargo_bin("ark_protocol")
        .unwrap()
        .args(["--json", "backup-create", "--file", &file_str])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(&out).expect("valid json");
    let backup_path = v
        .get("backup")
        .and_then(|x| x.as_str())
        .expect("backup path");
    assert!(backup_path.contains(".bak."));

    // 清理（--json），解析 { "removed": N }
    let assert2 = Command::cargo_bin("ark_protocol")
        .unwrap()
        .args([
            "--json",
            "backup-cleanup",
            "--dir",
            &dir.to_string_lossy(),
            "--base",
            "wallet.dat",
            "--keep-last",
            "1",
        ])
        .assert()
        .success();
    let out2 = String::from_utf8(assert2.get_output().stdout.clone()).unwrap();
    let v2: Value = serde_json::from_str(&out2).expect("valid json");
    let removed = v2.get("removed").and_then(|x| x.as_u64()).expect("removed");
    // 只创建了一个备份，keep-last=1 时应该不删除
    assert_eq!(removed, 0);

    let _ = std::fs::remove_dir_all(&dir);
}
