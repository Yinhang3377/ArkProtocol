#![cfg(feature = "backup")]
use ark_protocol::wallet::{cleanup_backups, create_encrypted_backup, Wallet};
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn backup_keep_zero_and_large_keep() {
    let dir = std::env::temp_dir();
    let name = format!(
        "wallet_edge_{}.json",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let path = dir.join(&name);
    let w = Wallet::new().unwrap();
    w.save_encrypted(&path, b"VeryStrongPwd_123!").unwrap();

    for _ in 0..3 {
        let _ = create_encrypted_backup(&path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let removed_all = cleanup_backups(&dir, &name, 0).unwrap();
    assert!(removed_all >= 3);

    for _ in 0..2 {
        let _ = create_encrypted_backup(&path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let removed_none = cleanup_backups(&dir, &name, 9999).unwrap();
    assert_eq!(removed_none, 0);

    let _ = fs::remove_file(&path);
}

#[test]
fn backup_rejects_invalid_base_name() {
    let dir = std::env::temp_dir();
    let err = cleanup_backups(&dir, "bad:name.json", 1).unwrap_err();
    assert!(format!("{err}")
        .to_lowercase()
        .contains("invalid base name"));
}
