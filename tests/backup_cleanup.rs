#![cfg(feature = "backup")]

use ark_protocol::wallet::Wallet;
use ark_protocol::wallet::{cleanup_backups, create_encrypted_backup};
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn create_and_cleanup_backups() {
    // 1. 先保存一个加密钱包文件
    let w = Wallet::new().unwrap();
    let pwd = b"a_very_strong_password";
    let dir = std::env::temp_dir();
    let name = format!(
        "wallet_{}.json",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let target = dir.join(&name);
    w.save_encrypted(&target, pwd).unwrap();

    // 2. 生成多个备份
    let _b1 = create_encrypted_backup(&target).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2)); // 保证时间戳顺序
    let _b2 = create_encrypted_backup(&target).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    let _b3 = create_encrypted_backup(&target).unwrap();

    // 3. 只保留最近 1 个备份，清理其余
    let removed = cleanup_backups(&dir, &name, 1).unwrap();
    assert!(
        removed >= 2,
        "should remove at least 2 old backups, removed={removed}"
    );

    // 4. 清理原文件
    let _ = fs::remove_file(target);
}
