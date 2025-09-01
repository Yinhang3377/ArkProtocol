use clap::{ Parser, Subcommand, ValueEnum };

#[cfg(feature = "backup")]
use std::io::{ self, Read }; // 非交互场景从 stdin 读密码时用

#[derive(Parser)]
#[command(name = "ark_protocol", about = "Ark Protocol CLI", version)]
struct Cli {
    /// 以 JSON 输出结果
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum CliLang {
    #[value(name = "english")]
    English,
    #[value(name = "chinese-simplified")]
    ChineseSimplified,
}

#[cfg(feature = "hd")]
impl From<CliLang> for bip39::Language {
    fn from(v: CliLang) -> Self {
        match v {
            CliLang::English => bip39::Language::English,
            // 回退到英文，避免某些版本不含 ChineseSimplified 时报编译错
            CliLang::ChineseSimplified => bip39::Language::English,
        }
    }
}

// backup 子命令交互读取密码时再引入 inquire
#[cfg(feature = "backup")]
fn read_password_interactive(prompt: &str) -> anyhow::Result<String> {
    use inquire::{ Password, PasswordDisplayMode };
    let ans = Password::new(prompt)
        .with_display_toggle_enabled()
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()?;
    Ok(ans)
}

#[derive(Subcommand)]
enum Commands {
    /// 生成新钱包
    New,

    /// 生成助记词
    #[cfg(feature = "hd")]
    Mnemonic {
        /// 助记词语言（english | chinese-simplified）
        #[clap(value_enum, long, default_value = "english")]
        lang: CliLang,
    },

    /// 通过助记词恢复钱包（支持可选 passphrase 与 BIP32 路径）
    #[cfg(feature = "hd")]
    Recover {
        /// 助记词短语（会进行规范化）
        #[clap(long)]
        phrase: String,
        /// 语言（english | chinese-simplified）
        #[clap(value_enum, long, default_value = "english")]
        lang: CliLang,
        /// 可选的 BIP39 passphrase（默认空）
        #[clap(long, default_value = "")]
        passphrase: String,
        /// BIP32/BIP44 派生路径（默认 m/44'/60'/0'/0/0）
        #[clap(long, default_value = "m/44'/60'/0'/0/0")]
        path: String,
    },

    /// 保存加密钱包到文件（PBKDF2 + AES-GCM）
    #[cfg(feature = "backup")]
    SaveEncrypted {
        #[clap(long)]
        file: String,
        #[clap(long, conflicts_with_all = ["password_prompt", "password_stdin"])]
        password: Option<String>,
        #[clap(long)]
        password_prompt: bool,
        #[clap(long, conflicts_with = "password_prompt")]
        password_stdin: bool,
    },

    /// 从加密钱包文件加载（PBKDF2 + AES-GCM）
    #[cfg(feature = "backup")]
    LoadEncrypted {
        #[clap(long)]
        file: String,
        #[clap(long, conflicts_with_all = ["password_prompt", "password_stdin"])]
        password: Option<String>,
        #[clap(long)]
        password_prompt: bool,
        #[clap(long, conflicts_with = "password_prompt")]
        password_stdin: bool,
    },

    /// 创建备份文件：<file>.bak.<unix_ts>
    #[cfg(feature = "backup")]
    BackupCreate {
        #[clap(long)]
        file: String,
    },

    /// 清理备份，仅保留最新 N 个
    #[cfg(feature = "backup")]
    BackupCleanup {
        #[clap(long)]
        dir: String,
        #[clap(long)]
        base: String,
        #[clap(long, default_value_t = 1)]
        keep_last: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::New => {
            let w = ark_protocol::wallet::Wallet::new()?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "address": w.address,
                        "public_key": hex::encode(w.public_key.serialize())
                    })
                );
            } else {
                println!("Address: {}", w.address);
            }
        }
        #[cfg(feature = "hd")]
        Commands::Mnemonic { lang } => {
            let phrase = ark_protocol::wallet::Wallet::generate_mnemonic_with_lang(lang.into())?;
            if cli.json {
                println!("{}", serde_json::json!({ "mnemonic": phrase }));
            } else {
                println!("{phrase}");
            }
        }
        #[cfg(feature = "hd")]
        Commands::Recover { phrase, lang, passphrase, path } => {
            let w = ark_protocol::wallet::Wallet::from_mnemonic_with_path(
                &phrase,
                lang.into(),
                &passphrase,
                &path
            )?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "address": w.address,
                        "public_key": hex::encode(w.public_key.serialize())
                    })
                );
            } else {
                println!("Address: {}", w.address);
            }
        }
        #[cfg(feature = "backup")]
        Commands::SaveEncrypted { file, password, password_prompt, password_stdin } => {
            let pwd = obtain_password(password, password_prompt, password_stdin, "Set password")?;
            let w = ark_protocol::wallet::Wallet::new()?;
            w.save_encrypted(&file, pwd.as_bytes())?;
            if cli.json {
                println!("{}", serde_json::json!({ "saved": file }));
            } else {
                println!("Saved wallet: {file}");
            }
        }
        #[cfg(feature = "backup")]
        Commands::LoadEncrypted { file, password, password_prompt, password_stdin } => {
            let pwd = obtain_password(password, password_prompt, password_stdin, "Enter password")?;
            let w = ark_protocol::wallet::Wallet::load_encrypted(&file, pwd.as_bytes())?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "address": w.address,
                        "public_key": hex::encode(w.public_key.serialize())
                    })
                );
            } else {
                println!("Address: {}", w.address);
            }
        }
        #[cfg(feature = "backup")]
        Commands::BackupCreate { file } => {
            let p = ark_protocol::wallet::create_encrypted_backup(&file)?;
            if cli.json {
                println!("{}", serde_json::json!({ "backup": p }));
            } else {
                println!("Backup: {}", p.display());
            }
        }
        #[cfg(feature = "backup")]
        Commands::BackupCleanup { dir, base, keep_last } => {
            let n = ark_protocol::wallet::cleanup_backups(&dir, &base, keep_last)?;
            if cli.json {
                println!("{}", serde_json::json!({ "removed": n }));
            } else {
                println!("Removed: {n}");
            }
        }
    }
    Ok(())
}

#[cfg(feature = "backup")]
fn obtain_password(
    pwd_opt: Option<String>,
    prompt: bool,
    stdin_flag: bool,
    title: &str
) -> anyhow::Result<String> {
    if let Some(p) = pwd_opt {
        return Ok(p);
    }
    if stdin_flag {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s)?;
        return Ok(s.trim_end_matches(&['\r', '\n'][..]).to_string());
    }
    if prompt {
        return read_password_interactive(title);
    }
    anyhow::bail!("no password provided; use --password / --password-stdin / --password-prompt")
}
