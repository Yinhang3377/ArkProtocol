#![cfg(feature = "hd")]

use ark_protocol::wallet::Wallet;
use bip39::Language;

#[test]
fn different_passphrase_changes_address() {
    let phrase = Wallet::generate_mnemonic_with_lang(Language::English).unwrap();

    let w1 = Wallet::from_mnemonic_with_path(&phrase, Language::English, "", "m/44'/60'/0'/0/0")
        .unwrap();
    let w2 = Wallet::from_mnemonic_with_path(&phrase, Language::English, "x", "m/44'/60'/0'/0/0")
        .unwrap();

    assert_ne!(w1.address, w2.address);
}
