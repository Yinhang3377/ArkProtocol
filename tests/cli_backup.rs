use assert_cmd::prelude::*;
use serde_json::Value;
use std::{fs, path::PathBuf, process::Command, thread, time::Duration};
use uuid::Uuid;

fn tmp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("arkproto_test_{}_{}", name, Uuid::new_v4()))
}

#[test]
#[cfg(feature = "backup")]
fn save_and_load_encrypted_roundtrip_json() {
    let dir = tmp_path("roundtrip");
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("wallet.dat");
    let file_str = file.to_string_lossy().to_string();

    // 保存（--json）
    Command::cargo_bin("ark_protocol")
        .unwrap()
        .args([
            "--json",
            "save-encrypted",
            "--file",
            &file_str,
            "--password",
            "a_very_strong_password",
        ])
        .assert()
        .success();

    assert!(file.exists(), "wallet file should be created");

    // 加载（--json）
    let assert = Command::cargo_bin("ark_protocol")
        .unwrap()
        .args([
            "--json",
            "load-encrypted",
            "--file",
            &file_str,
            "--password",
            "a_very_strong_password",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(&out).expect("valid JSON");
    assert!(v.get("address").is_some(), "json must contain 'address'");
    assert!(
        v.get("public_key").is_some(),
        "json must contain 'public_key'"
    );

    // 清理
    let _ = fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "backup")]
fn backup_create_and_cleanup_keeps_last_two() {
    let dir = tmp_path("backup");
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("wallet.dat");
    let file_str = file.to_string_lossy().to_string();

    // 先保存一个加密钱包
    Command::cargo_bin("ark_protocol")
        .unwrap()
        .args([
            "save-encrypted",
            "--file",
            &file_str,
            "--password",
            "a_very_strong_password",
        ])
        .assert()
        .success();

    // 连续创建 3 个备份（确保时间戳不同）
    for _ in 0..3 {
        Command::cargo_bin("ark_protocol")
            .unwrap()
            .args(["--json", "backup-create", "--file", &file_str])
            .assert()
            .success();
        thread::sleep(Duration::from_millis(1100));
    }

    // 清理，仅保留最近 2 个
    let dir_str = dir.to_string_lossy().to_string();
    let assert = Command::cargo_bin("ark_protocol")
        .unwrap()
        .args([
            "--json",
            "backup-cleanup",
            "--dir",
            &dir_str,
            "--base",
            "wallet.dat",
            "--keep-last",
            "2",
        ])
        .assert()
        .success();

    // 校验 JSON 返回 removed 数量
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(&out).expect("valid JSON");
    let removed = v.get("removed").and_then(|x| x.as_u64()).unwrap_or(0);
    assert!(removed >= 1, "should remove at least one old backup");

    // 校验目录中只剩 2 个备份文件
    let mut left = 0usize;
    for e in fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if name.starts_with("wallet.dat.bak.") {
                left += 1;
            }
        }
    }
    assert_eq!(left, 2, "should keep last 2 backups");

    // 清理
    let _ = fs::remove_dir_all(&dir);
}
