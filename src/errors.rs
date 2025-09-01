use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("E_AUTH: wallet decrypt failed")]
    Auth,
    #[error("E_VERSION: unsupported wallet file version: {0}")]
    Version(u32),
    #[error("E_MAGIC: unsupported wallet magic")]
    Magic,
    #[error("password too short")]
    PasswordTooShort,
    #[error("wallet path is not a regular file")]
    NotRegularFile,
    #[error("wallet file too large: {0} bytes")]
    FileTooLarge(u64),
    #[error("refuse to read wallet via reparse/symlink")]
    ReparsePoint,
}
