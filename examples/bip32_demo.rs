fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "hd")]
    {
        use ark_protocol::wallet::Wallet;
        use bip39::Language;
        let phrase = Wallet::generate_mnemonic_with_lang(Language::English)?;
        let wallet =
            Wallet::from_mnemonic_with_path(&phrase, Language::English, "", "m/44'/60'/0'/0/0")?;
        println!("Mnemonic: {phrase}");
        println!("Address: {}", wallet.address);
    }
    #[cfg(not(feature = "hd"))]
    {
        eprintln!("Enable feature 'hd': cargo run --example bip32_demo --features hd");
    }
    Ok(())
}
