#![cfg(feature = "hd")]

use ark_protocol::wallet::Wallet;
use bip39::Language;

#[test]
fn hd_same_path_same_key() {
    let phrase = Wallet::generate_mnemonic_with_lang(Language::English).unwrap();
    let a = Wallet::from_mnemonic_with_path(&phrase, Language::English, "", "m/44'/60'/0'/0/0")
        .unwrap();
    let b = Wallet::from_mnemonic_with_path(&phrase, Language::English, "", "m/44'/60'/0'/0/0")
        .unwrap();
    assert_eq!(a.public_key, b.public_key);
    assert_eq!(a.address, b.address);
}

#[test]
fn hd_diff_path_diff_key() {
    let phrase = Wallet::generate_mnemonic_with_lang(Language::English).unwrap();
    let a = Wallet::from_mnemonic_with_path(&phrase, Language::English, "", "m/44'/60'/0'/0/0")
        .unwrap();
    let b = Wallet::from_mnemonic_with_path(&phrase, Language::English, "", "m/44'/60'/0'/0/1")
        .unwrap();
    assert_ne!(a.public_key, b.public_key);
    assert_ne!(a.address, b.address);
}

#[test]
fn hd_passphrase_changes_result() {
    let phrase = Wallet::generate_mnemonic_with_lang(Language::English).unwrap();
    let a = Wallet::from_mnemonic_with_path(&phrase, Language::English, "", "m/44'/60'/0'/0/0")
        .unwrap();
    let b = Wallet::from_mnemonic_with_path(&phrase, Language::English, "x", "m/44'/60'/0'/0/0")
        .unwrap();
    assert_ne!(a.public_key, b.public_key);
    assert_ne!(a.address, b.address);
}
