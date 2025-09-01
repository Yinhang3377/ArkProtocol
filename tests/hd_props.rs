#![cfg(feature = "hd")]

use ark_protocol::wallet::Wallet;
use bip39::Language;

#[test]
fn first_two_indices_should_differ() {
    let phrase = Wallet::generate_mnemonic_with_lang(Language::English).unwrap();
    let a0 = Wallet::from_mnemonic_with_path(&phrase, Language::English, "", "m/44'/60'/0'/0/0")
        .unwrap();
    let a1 = Wallet::from_mnemonic_with_path(&phrase, Language::English, "", "m/44'/60'/0'/0/1")
        .unwrap();
    assert_ne!(a0.public_key, a1.public_key);
    assert_ne!(a0.address, a1.address);
}
