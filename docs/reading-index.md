# Ark Protocol Reading Index

- Generated: 2025-08-26 15:46:12
- Tip: Ctrl+Click links to open in VS Code

## .\src\common.rs
### const
- [MAINNET_P2PKH_VERSION](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/common.rs:3)  src\common.rs:3
- [CHECKSUM_LEN](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/common.rs:4)  src\common.rs:4

## .\src\crypto.rs
### fn
- [generate_keypair](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/crypto.rs:11)  src\crypto.rs:11
- [public_key_to_address](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/crypto.rs:28)  src\crypto.rs:28
- [public_key_to_address_with_version](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/crypto.rs:33)  src\crypto.rs:33
- [sign_message_sha256](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/crypto.rs:57)  src\crypto.rs:57
- [verify_message_sha256](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/crypto.rs:65)  src\crypto.rs:65
- [test_address_generation_from_known_key](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/crypto.rs:78)  src\crypto.rs:78
- [test_sign_and_verify_sha256](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/crypto.rs:92)  src\crypto.rs:92

## .\src\errors.rs

## .\src\hd.rs
### fn
- [new_12](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/hd.rs:20)  src\hd.rs:20
- [new_24](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/hd.rs:29)  src\hd.rs:29
- [from_phrase](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/hd.rs:38)  src\hd.rs:38
- [phrase](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/hd.rs:45)  src\hd.rs:45
- [derive_xprv](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/hd.rs:50)  src\hd.rs:50
- [derive_secp256k1_keypair](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/hd.rs:59)  src\hd.rs:59
- [test_mnemonic12_generate_and_parse](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/hd.rs:74)  src\hd.rs:74
- [test_derive_xprv](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/hd.rs:82)  src\hd.rs:82

## .\src\lib.rs

## .\src\wallet.rs
### const
- [WALLET_VERSION](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:68)  src\wallet.rs:68
- [WALLET_MAGIC](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:70)  src\wallet.rs:70
- [SALT_LEN](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:73)  src\wallet.rs:73
- [NONCE_LEN](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:75)  src\wallet.rs:75
- [MAX_WALLET_FILE_SIZE](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:77)  src\wallet.rs:77
- [MIN_PASSWORD_LEN](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:79)  src\wallet.rs:79
- [PBKDF2_ITERATIONS](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:84)  src\wallet.rs:84
- [MIN_PBKDF2_ITERATIONS](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:85)  src\wallet.rs:85
- [MAX_PBKDF2_ITERATIONS](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:86)  src\wallet.rs:86
- [TEST_MIN_PBKDF2](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:90)  src\wallet.rs:90
- [TEST_MIN_PBKDF2](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:92)  src\wallet.rs:92
- [DEFAULT_PBKDF2_ITERS](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:97)  src\wallet.rs:97
- [DEFAULT_PBKDF2_ITERS](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:100)  src\wallet.rs:100
- [ARGON2_DEFAULT_M_COST_KIB](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:184)  src\wallet.rs:184
- [ARGON2_DEFAULT_T_COST](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:186)  src\wallet.rs:186
- [ARGON2_DEFAULT_PARALLELISM](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:188)  src\wallet.rs:188
- [MIN_MS](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:776)  src\wallet.rs:776
- [MAX_MS](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:777)  src\wallet.rs:777
- [ROUNDS](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1342)  src\wallet.rs:1342
### fn
- [to_wide_null](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:61)  src\wallet.rs:61
- [validate_password_strength](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:103)  src\wallet.rs:103
- [fill_random_nonzero](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:110)  src\wallet.rs:110
- [validate_base_name](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:119)  src\wallet.rs:119
- [lock](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:130)  src\wallet.rs:130
- [unlock](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:138)  src\wallet.rs:138
- [lock](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:146)  src\wallet.rs:146
- [unlock](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:150)  src\wallet.rs:150
- [new](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:163)  src\wallet.rs:163
- [drop](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:173)  src\wallet.rs:173
- [fmt](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:197)  src\wallet.rs:197
- [label](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:220)  src\wallet.rs:220
- [parse_kdf](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:230)  src\wallet.rs:230
- [new](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:250)  src\wallet.rs:250
- [from_secret_key](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:264)  src\wallet.rs:264
- [sign_sha256](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:276)  src\wallet.rs:276
- [verify_sha256](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:281)  src\wallet.rs:281
- [save_encrypted](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:286)  src\wallet.rs:286
- [save_encrypted_argon2](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:305)  src\wallet.rs:305
- [save_encrypted_argon2_with_params](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:315)  src\wallet.rs:315
- [save_encrypted_with_kdf](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:331)  src\wallet.rs:331
- [load_encrypted](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:403)  src\wallet.rs:403
- [upgrade_encryption_in_place](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:523)  src\wallet.rs:523
- [change_password](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:531)  src\wallet.rs:531
- [upgrade_to_argon2_in_place](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:548)  src\wallet.rs:548
- [change_password_to_argon2](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:557)  src\wallet.rs:557
- [cleanup_stale_wallet_temps](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:573)  src\wallet.rs:573
- [calibrate_pbkdf2_iterations](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:618)  src\wallet.rs:618
- [recommend_argon2_params](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:637)  src\wallet.rs:637
- [default_version](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:667)  src\wallet.rs:667
- [make_aad](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:671)  src\wallet.rs:671
- [create_encrypted_backup](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:676)  src\wallet.rs:676
- [cleanup_backups](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:692)  src\wallet.rs:692
- [write_file_atomically](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:726)  src\wallet.rs:726
- [uniform_delay_on_auth_failure](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:773)  src\wallet.rs:773
- [unix_is_symlink](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:791)  src\wallet.rs:791
- [validate_parent_dir](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:797)  src\wallet.rs:797
- [validate_target_path_for_write](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:820)  src\wallet.rs:820
- [final_pre_replace_check](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:842)  src\wallet.rs:842
- [atomic_replace_with_retry](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:855)  src\wallet.rs:855
- [atomic_replace_with_retry](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:889)  src\wallet.rs:889
- [sync_dir](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:894)  src\wallet.rs:894
- [create_temp_exclusive](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:899)  src\wallet.rs:899
- [read_wallet_file_secure](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:928)  src\wallet.rs:928
- [read_wallet_file_secure](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:952)  src\wallet.rs:952
- [windows_has_reparse_point](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:969)  src\wallet.rs:969
- [windows_path_has_ads](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:982)  src\wallet.rs:982
- [validate_salt_nonce](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:995)  src\wallet.rs:995
- [derive_key_into](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1006)  src\wallet.rs:1006
- [set_windows_attrs](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1036)  src\wallet.rs:1036
- [derive_key_argon2id](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1058)  src\wallet.rs:1058
- [parse_argon2_params_from_kdf](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1083)  src\wallet.rs:1083
- [test_temp_path](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1109)  src\wallet.rs:1109
- [test_new_wallet_and_address](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1117)  src\wallet.rs:1117
- [test_from_secret_key_and_sign](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1125)  src\wallet.rs:1125
- [test_save_and_load_encrypted_wallet](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1140)  src\wallet.rs:1140
- [test_overwrite_existing_wallet_file](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1158)  src\wallet.rs:1158
- [test_load_legacy_v1_wallet](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1172)  src\wallet.rs:1172
- [test_corrupted_ciphertext_fails_auth](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1214)  src\wallet.rs:1214
- [test_short_password_is_rejected_on_load_v2](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1230)  src\wallet.rs:1230
- [test_large_file_rejected](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1243)  src\wallet.rs:1243
- [test_symlink_read_is_rejected](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1256)  src\wallet.rs:1256
- [test_symlink_parent_dir_is_rejected_on_save](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1271)  src\wallet.rs:1271
- [test_magic_mismatch_rejected](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1292)  src\wallet.rs:1292
- [test_unknown_kdf_rejected](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1308)  src\wallet.rs:1308
- [test_truncated_nonce_or_salt_rejected](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1323)  src\wallet.rs:1323
- [test_calibrate_pbkdf2_iterations](vscode://file/C%3A/Users/plant/Desktop/Rust%E5%8C%BA%E5%9D%97%E9%93%BE/ArkProtocol/src/wallet.rs:1339)  src\wallet.rs:1339

