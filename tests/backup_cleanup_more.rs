#![cfg(feature = "backup")]

use ark_protocol::wallet::{cleanup_backups, create_encrypted_backup, Wallet};
use std::{
    fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[test]
fn cleanup_with_keep_last_zero_removes_all_backups() {
    let dir = std::env::temp_dir();
    let name = format!(
        "wallet_{}.json",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let path = dir.join(&name);
    let pwd = b"VeryStrongPwd_123!";

    let w = Wallet::new().unwrap();
    w.save_encrypted(&path, pwd).unwrap();

    let _ = create_encrypted_backup(&path).unwrap();
    std::thread::sleep(Duration::from_millis(2));
    let _ = create_encrypted_backup(&path).unwrap();
    std::thread::sleep(Duration::from_millis(2));
    let _ = create_encrypted_backup(&path).unwrap();

    let removed = cleanup_backups(&dir, &name, 0).unwrap();
    assert!(removed >= 3, "should remove all backups, removed={removed}");

    let prefix = format!("{name}.bak-");
    let any_bak = fs::read_dir(&dir).unwrap().any(|e| {
        e.ok()
            .and_then(|x| x.file_name().into_string().ok())
            .map(|s| s.starts_with(&prefix))
            .unwrap_or(false)
    });
    assert!(!any_bak, "no backup files should remain");

    let _ = fs::remove_file(path);
}
