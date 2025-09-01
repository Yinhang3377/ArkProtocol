#![cfg(feature = "hd")]

use ark_protocol::wallet::Wallet;
use bip39::Language;

#[test]
fn invalid_derivation_path_should_fail() {
    let phrase = Wallet::generate_mnemonic_with_lang(Language::English).unwrap();
    let err = Wallet::from_mnemonic_with_path(&phrase, Language::English, "", "m/44'/60'/X/0/0")
        .expect_err("should error");
    assert!(err
        .to_string()
        .to_lowercase()
        .contains("invalid derivation path"));
}

#[test]
fn invalid_mnemonic_word_should_fail() {
    // 明显错误的词，不在词表里
    let bad = "foo bar baz qux quux corge grault garply waldo fred plugh xyzzy";
    let err = Wallet::from_mnemonic_with_path(bad, Language::English, "", "m/44'/60'/0'/0/0")
        .expect_err("should error");
    assert!(err.to_string().to_lowercase().contains("invalid mnemonic"));
}

#[test]
fn test_invalid_mnemonic_handling() {
    let res = Wallet::from_mnemonic("bad phrase");
    res.expect_err("should error");

    let r2 = Wallet::from_mnemonic_with_lang("bad", bip39::Language::English);
    r2.expect_err("should error");
}
