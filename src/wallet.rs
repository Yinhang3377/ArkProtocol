//! Ark Protocol 钱包与加密存储模块。
//! 主要功能：钱包密钥生成、加密保存、解密加载、安全校验、原子写入等。
//! 支持 PBKDF2/Argon2 密钥派生，AES-GCM 加密，支持多平台安全特性。
//! 钱包文件格式为 JSON，包含 magic/version/kdf/iterations/salt/nonce/ciphertext 等字段。
//! 特性开关（可选）：`adaptive_pbkdf2`、`argon2`、`memlock`、`timing_harden`、`backup`、`sysinfo_params`、`win_harden`。
//!
//! 地址算法（Base58Check，兼容比特币 P2PKH 风格）
//! - 输入：secp256k1 压缩公钥(33B)；H1 = SHA-256(pubkey)；H2 = RIPEMD-160(H1) -> 20B。
//! - 版本前缀：0x00 || H2 -> 21B。
//! - 校验和：C = first4(SHA-256(SHA-256(版本||H2)))，最终编码：Base58(版本||H2||C)。
//!
//! 加密钱包文件格式（JSON，v2 版本）
//! - magic: 固定 "ArkWallet"（绑定到 AAD）。
//! - version: 文件版本，目前为 2（v1 为历史兼容，无 AAD）。
//! - kdf: "PBKDF2-SHA256" 或 "Argon2id-v1:m=...,p=..."。
//! - iterations: KDF 的 t_cost/迭代次数（PBKDF2: iterations；Argon2: t_cost）。
//! - salt_hex: 16 字节盐（hex 字符串，非全零）。
//! - nonce_hex: 12 字节随机数（hex 字符串，非全零，AES-GCM Nonce）。
//! - ciphertext_hex: AES-256-GCM 的密文（hex；AAD 绑定 magic/version/kdf/iterations）。
use crate::crypto::{public_key_to_address, sign_message_sha256, verify_message_sha256};
use crate::errors::WalletError;
use anyhow::{anyhow, Context, Result};
#[cfg(unix)]
use libc;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
#[cfg(feature = "hd")]
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, Payload},
    Aes256Gcm, KeyInit,
};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "argon2")]
use argon2::{Algorithm, Argon2, Params, Version};

#[cfg(windows)]
use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    GetFileAttributesW, MoveFileExW, ReplaceFileW, SetFileAttributesW,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES,
    INVALID_FILE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    REPLACEFILE_WRITE_THROUGH,
};

#[cfg(windows)]
#[allow(dead_code)]
/// 将 OsStr（操作系统字符串）转换为以 0 结尾的宽字节（UTF-16）数组，
/// 用于 Windows API 调用（如文件操作等需要 LPCWSTR 参数）。
/// 例如：Rust 的 Path/OsStr 转为 Windows API 需要的 `*const u16` 字符串。
fn to_wide_null(s: &OsStr) -> Vec<u16> {
    // 将 OsStr 编码为 UTF-16 宽字节序列，并链上一个包含 null 终止符 (0) 的迭代器，
    // 最后收集成一个 Vec<u16>。这是更惯用的写法。
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// 钱包文件格式版本（当前 v2）。写入文件并参与 AES-GCM AAD 绑定。
const WALLET_VERSION: u32 = 2;
/// 钱包文件魔术字串（类型标识）。与版本/kdf/迭代一起进入 AAD。
const WALLET_MAGIC: &str = "ArkWallet";
/// KDF 盐长度（字节）。固定 16，且要求非全零。
const SALT_LEN: usize = 16;
/// AES-GCM Nonce 长度（字节）。固定 12，且要求非全零。
const NONCE_LEN: usize = 12;
/// 可加载钱包文件的最大字节数（防止大文件 DoS）。
const MAX_WALLET_FILE_SIZE: u64 = 1024 * 1024;
/// v2 文件要求的最小口令长度（过短会被拒绝）。
const MIN_PASSWORD_LEN: usize = 12;
const MAX_PASSWORD_LEN: usize = 128;
// PBKDF2 参数（默认/最小/最大迭代）
// 在库目标中可能只作为别的常量的值来源，给它放宽 dead_code 即可。
#[cfg_attr(not(test), allow(dead_code))]
const PBKDF2_ITERATIONS: u32 = 200_000;
const MIN_PBKDF2_ITERATIONS: u32 = 100_000;
const MAX_PBKDF2_ITERATIONS: u32 = 5_000_000;
// 为测试/CI 降低最小迭代（feature = "test_kdf_fast"），否则使用正常最小值
#[cfg(feature = "test_kdf_fast")]
const TEST_MIN_PBKDF2: u32 = 10_000;
#[cfg(not(feature = "test_kdf_fast"))]
const TEST_MIN_PBKDF2: u32 = MIN_PBKDF2_ITERATIONS;
// 测试/CI 可通过 feature=test_kdf_fast 使用更快迭代
#[cfg(feature = "test_kdf_fast")]
#[cfg_attr(feature = "adaptive_pbkdf2", allow(dead_code))]
const DEFAULT_PBKDF2_ITERS: u32 = 50_000;
#[cfg(not(feature = "test_kdf_fast"))]
#[cfg_attr(feature = "adaptive_pbkdf2", allow(dead_code))]
const DEFAULT_PBKDF2_ITERS: u32 = PBKDF2_ITERATIONS;

/// 新增：通用校验/随机助手
fn validate_password_strength(password: &[u8]) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(anyhow!("password too short (min {})", MIN_PASSWORD_LEN));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(anyhow!("password too long (max {})", MAX_PASSWORD_LEN));
    }
    Ok(())
}

/// 用安全随机数生成器填充 buf，确保 buf 至少有一个字节不为 0。
/// 常用于生成加密用的 salt（盐）和 nonce（随机数），避免全 0 导致安全隐患。
/// 如果生成的随机字节全为 0，则重新生成，直到满足条件为止。
fn fill_random_nonzero(buf: &mut [u8]) {
    loop {
        // 用操作系统的安全随机数生成器填充 buf
        OsRng.fill_bytes(buf);
        // 检查 buf 是否至少有一个字节不为 0
        if buf.iter().any(|&b| b != 0) {
            break;
        }
        // 如果全为 0，则继续生成
    }
}

fn validate_base_name(base: &str) -> Result<()> {
    // 校验基础文件名是否合法，防止路径注入和特殊字符带来的安全风险。
    // - 文件名不能为空；
    // - 不能包含 '/'（Unix 路径分隔符）；
    // - 不能包含 '\\'（Windows 路径分隔符）；
    // - 不能包含 ':'（Windows 下的数据流攻击等特殊用法）。
    // 通过这些校验，确保钱包文件只能保存在安全、预期的位置，防止目录穿越、路径注入等攻击。
    if base.is_empty() || base.contains('/') || base.contains('\\') || base.contains(':') {
        return Err(anyhow!("invalid base name"));
    }
    Ok(())
}

#[cfg(feature = "memlock")]
mod memlock {
    #[cfg(unix)]
    pub fn lock(buf: &mut [u8]) -> std::io::Result<()> {
        // 使用 mlock 锁定内存，防止被交换到磁盘
        unsafe {
            let ret = libc::mlock(buf.as_ptr() as *const _, buf.len());
            if ret == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
    }

    #[cfg(unix)]
    pub fn unlock(buf: &mut [u8]) -> std::io::Result<()> {
        unsafe {
            let ret = libc::munlock(buf.as_ptr() as *const _, buf.len());
            if ret == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
    }

    #[cfg(windows)]
    pub fn lock(buf: &mut [u8]) -> std::io::Result<()> {
        use windows::Win32::System::Memory::VirtualLock;
        (unsafe { VirtualLock(buf.as_mut_ptr() as _, buf.len()) })
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    #[cfg(windows)]
    pub fn unlock(buf: &mut [u8]) -> std::io::Result<()> {
        use windows::Win32::System::Memory::VirtualUnlock;
        (unsafe { VirtualUnlock(buf.as_mut_ptr() as _, buf.len()) })
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    // 其它平台（非 Unix/Windows），lock/unlock 为空实现，保证跨平台兼容
    #[cfg(not(any(unix, windows)))]
    pub fn lock(_: &mut [u8]) -> std::io::Result<()> {
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    pub fn unlock(_: &mut [u8]) -> std::io::Result<()> {
        Ok(())
    }
}

// 用原始指针的 RAII，避免借用冲突（E0499/E0502）
#[cfg(feature = "memlock")]
struct LockedBufGuard {
    ptr: *mut u8, // 指向被加锁内存的原始指针
    len: usize,   // 被加锁内存的长度
}

#[cfg(feature = "memlock")]
impl LockedBufGuard {
    /// 创建一个新的 LockedBufGuard，并立即对传入的内存 slice 加锁。
    /// 如果加锁失败，返回错误；否则返回管理该内存的 guard。
    fn new(slice: &mut [u8]) -> std::io::Result<Self> {
        // 调用 memlock::lock 前加条件编译
        #[cfg(any(unix, windows))]
        memlock::lock(slice)?;
        Ok(Self {
            ptr: slice.as_mut_ptr(),
            len: slice.len(),
        })
    }
}

#[cfg(feature = "memlock")]
impl Drop for LockedBufGuard {
    /// 当 LockedBufGuard 离开作用域时自动调用，负责自动解锁内存。
    fn drop(&mut self) {
        if self.len != 0 {
            unsafe {
                // 重新构造出原始 slice，调用 memlock::unlock 解除内存锁定
                let s = std::slice::from_raw_parts_mut(self.ptr, self.len);
                // 调用 memlock::unlock 前加条件编译
                #[cfg(any(unix, windows))]
                let _ = memlock::unlock(s);
            }
        }
    }
}

#[cfg(feature = "argon2")]
const ARGON2_DEFAULT_M_COST_KIB: u32 = 64 * 1024;
#[cfg(feature = "argon2")]
const ARGON2_DEFAULT_T_COST: u32 = 3;
#[cfg(feature = "argon2")]
const ARGON2_DEFAULT_PARALLELISM: u32 = 1;

/// 钱包结构体，包含私钥、公钥和地址
pub struct Wallet {
    pub(crate) secret_key: SecretKey, // 私钥，仅 crate 内部可见，保护安全
    pub public_key: PublicKey,        // 公钥，可公开
    pub address: String,              // 钱包地址，由公钥推导
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 将公钥序列化为压缩格式（33字节），取前4字节做简短展示
        let comp = self.public_key.serialize();
        let pk_short = format!(
            "{:02x}{:02x}{:02x}{:02x}..",
            comp[0], comp[1], comp[2], comp[3]
        );
        // 只显示地址和公钥前缀，避免泄露私钥和完整公钥
        f.debug_struct("Wallet")
            .field("address", &self.address)
            .field("public_key_prefix", &pk_short)
            .finish()
    }
}

/// 密钥派生函数（KDF）类型枚举，表示钱包加密时用的算法和参数
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KdfKind {
    // PBKDF2-SHA256 算法，包含迭代次数参数
    Pbkdf2 {
        iterations: u32, // 迭代次数，越大越安全但越慢
    },
    // Argon2id 算法（可选 feature），包含多项参数
    #[cfg(feature = "argon2")]
    Argon2id {
        t_cost: u32,      // 迭代次数（time cost）
        m_cost_kib: u32,  // 内存消耗（单位 KiB）
        parallelism: u32, // 并行度（线程数）
    },
}

impl KdfKind {
    /// 返回当前 KDF 的字符串标签（用于钱包文件存储和显示）
    fn label(&self) -> String {
        match self {
            // PBKDF2 算法，固定标签
            KdfKind::Pbkdf2 { .. } => "PBKDF2-SHA256".to_string(),
            // Argon2id 算法，带参数的标签
            #[cfg(feature = "argon2")]
            KdfKind::Argon2id {
                m_cost_kib,
                parallelism,
                ..
            } => format!("Argon2id-v1:m={m_cost_kib},p={parallelism}"),
        }
    }
}

/// 解析 KDF 标签和参数，生成对应的 KdfKind 枚举（用于解密钱包时还原加密算法和参数）
/// label: KDF 算法标签字符串（如 "PBKDF2-SHA256" 或 "Argon2id-v1:m=65536,p=1"）
/// iterations: 迭代次数参数（PBKDF2: iterations，Argon2: t_cost）
fn parse_kdf(label: &str, iterations: u32) -> Result<KdfKind> {
    // 如果是 PBKDF2 算法，直接返回对应的结构体变体
    if label == "PBKDF2-SHA256" {
        return Ok(KdfKind::Pbkdf2 { iterations });
    }
    // 如果启用了 argon2 特性，且标签以 "Argon2id-v1" 开头
    #[cfg(feature = "argon2")]
    {
        if label.starts_with("Argon2id-v1") {
            // 解析标签中的 m_cost_kib 和 parallelism 参数
            let (m_cost_kib, parallelism) = parse_argon2_params_from_kdf(label)?;
            // 返回 Argon2id 结构体变体，t_cost 用 iterations 参数
            return Ok(KdfKind::Argon2id {
                t_cost: iterations,
                m_cost_kib,
                parallelism,
            });
        }
    }
    // 如果都不匹配，返回错误，表示不支持的 KDF 算法
    Err(anyhow!("unsupported kdf: {}", label))
}

impl Wallet {
    /// 生成新钱包（secp256k1 随机私钥 + 地址派生）。
    pub fn new() -> Result<Self> {
        // 循环生成一个合法的 secp256k1 私钥
        let secret_key = loop {
            let mut buf = [0u8; 32]; // 创建一个32字节的缓冲区
            OsRng.fill_bytes(&mut buf); // 用操作系统安全随机数填充缓冲区
                                        // 尝试用 buf 创建私钥，如果合法就返回
            if let Ok(sk) = SecretKey::from_slice(&buf) {
                buf.zeroize(); // 用完后立即清除缓冲区，防止泄露
                break sk; // 跳出循环，得到合法私钥
            }
            buf.zeroize(); // 如果不合法也要清除缓冲区
        };
        // 用生成的私钥创建钱包（自动推导公钥和地址）
        Self::from_secret_key(secret_key)
    }

    /// 由既有私钥构造钱包（推导公钥和钱包地址）
    /// 输入：合法的 secp256k1 私钥
    /// 输出：包含私钥、公钥和钱包地址的 Wallet 实例
    pub fn from_secret_key(secret_key: SecretKey) -> Result<Self> {
        // 创建 secp256k1 算法上下文
        let secp = Secp256k1::new();
        // 通过私钥推导出公钥（椭圆曲线点运算，不是哈希）
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        // 通过公钥生成钱包地址（包含 SHA-256、RIPEMD-160 哈希等流程）
        let address = public_key_to_address(&public_key)?;
        // 返回包含私钥、公钥和地址的钱包实例
        Ok(Self {
            secret_key,
            public_key,
            address,
        })
    }

    /// 以 SHA-256 摘要为消息进行 ECDSA 签名。
    pub fn sign_sha256(&self, msg: &[u8]) -> anyhow::Result<secp256k1::ecdsa::Signature> {
        sign_message_sha256(&self.secret_key, msg)
    }

    /// 验证 SHA-256 摘要消息的 ECDSA 签名。
    pub fn verify_sha256(
        &self,
        msg: &[u8],
        sig: &secp256k1::ecdsa::Signature,
    ) -> anyhow::Result<bool> {
        // 注意参数顺序：公钥、签名、消息
        verify_message_sha256(&self.public_key, sig, msg)
    }

    /// 以 PBKDF2 + AES-GCM 保存加密钱包（原子落盘、路径与属性安全校验）。
    pub fn save_encrypted<P: AsRef<Path>>(&self, path: P, password: &[u8]) -> Result<()> {
        // 检查密码长度是否符合最小要求
        if password.len() < MIN_PASSWORD_LEN {
            return Err(WalletError::PasswordTooShort.into());
        }

        // 选择 PBKDF2 的迭代次数
        let iterations = {
            // 如果启用了 adaptive_pbkdf2 特性，根据目标耗时自动校准迭代次数
            #[cfg(feature = "adaptive_pbkdf2")]
            {
                Self::calibrate_pbkdf2_iterations(250)
            }
            // 否则使用默认迭代次数
            #[cfg(not(feature = "adaptive_pbkdf2"))]
            {
                DEFAULT_PBKDF2_ITERS
            }
        };

        // 构造 PBKDF2 KDF 配置
        let kdf = KdfKind::Pbkdf2 { iterations };

        // 调用通用加密保存函数，执行实际的加密和写入流程
        self.save_encrypted_with_kdf(path, password, kdf)
    }
    /// 以 Argon2id + AES-GCM 保存加密钱包（原子落盘，安全校验）。
    /// 适用于需要更高安全性的场景，只有启用 feature = "argon2" 时可用。
    /// 参数说明：
    /// - path: 钱包加密文件保存路径
    /// - password: 用户设置的加密密码
    #[cfg(feature = "argon2")]
    pub fn save_encrypted_argon2<P: AsRef<Path>>(&self, path: P, password: &[u8]) -> Result<()> {
        // 构造 Argon2id KDF 配置，使用默认参数（迭代次数、内存消耗、并行度）
        let kdf = KdfKind::Argon2id {
            t_cost: ARGON2_DEFAULT_T_COST,           // 迭代次数
            m_cost_kib: ARGON2_DEFAULT_M_COST_KIB,   // 内存消耗（KiB）
            parallelism: ARGON2_DEFAULT_PARALLELISM, // 并行度
        };
        // 调用通用加密保存函数，执行实际的加密和写入流程
        self.save_encrypted_with_kdf(path, password, kdf)
    }
    /// 以自定义 Argon2id 参数 + AES-GCM 保存加密钱包（原子落盘，安全校验）。
    /// 适用于需要手动指定 Argon2id 安全参数的高级场景，仅在启用 feature = "argon2" 时可用。
    /// 参数说明：
    /// - path: 钱包加密文件保存路径
    /// - password: 用户设置的加密密码
    /// - t_cost: Argon2id 的迭代次数（time cost）
    /// - m_cost_kib: Argon2id 的内存消耗（单位 KiB）
    /// - parallelism: Argon2id 的并行度（线程数）
    #[cfg(feature = "argon2")]
    pub fn save_encrypted_argon2_with_params<P: AsRef<Path>>(
        &self,
        path: P,
        password: &[u8],
        t_cost: u32,
        m_cost_kib: u32,
        parallelism: u32,
    ) -> Result<()> {
        // 构造带自定义参数的 Argon2id KDF 配置
        let kdf = KdfKind::Argon2id {
            t_cost,
            m_cost_kib,
            parallelism,
        };
        // 调用通用加密保存函数，执行实际的加密和写入流程
        self.save_encrypted_with_kdf(path, password, kdf)
    }
    /// 通用加密保存函数：
    /// 用指定的 KDF 算法（PBKDF2 或 Argon2id）和参数，将钱包私钥加密后保存到指定文件路径。
    /// 支持原子写入、参数校验、内存安全清理等。
    ///
    /// 参数：
    /// - path: 钱包加密文件保存路径
    /// - password: 用户设置的加密密码
    /// - kdf: 密钥派生算法及参数（PBKDF2 或 Argon2id）
    ///
    /// 流程：
    /// 1. 检查密码强度，生成随机盐和随机数（nonce）
    /// 2. 用 KDF 算法（PBKDF2/Argon2id）将密码和盐派生出加密密钥
    /// 3. 用 AES-GCM 算法和派生密钥对私钥进行加密，得到密文
    /// 4. 将加密参数、密文等信息序列化为 JSON 格式
    /// 5. 原子方式写入到指定文件，确保写入安全可靠
    fn save_encrypted_with_kdf<P: AsRef<Path>>(
        &self,
        path: P,
        password: &[u8],
        kdf: KdfKind,
    ) -> Result<()> {
        // 检查密码是否为空
        if password.is_empty() {
            return Err(anyhow!("password must not be empty"));
        }
        // 检查密码强度（长度等要求）
        validate_password_strength(password)?;

        // 生成随机盐（salt），用于KDF，防止同一密码生成相同密钥
        let mut salt = [0u8; SALT_LEN];
        fill_random_nonzero(&mut salt);
        // 生成随机数nonce，用于AES-GCM加密，保证每次加密结果不同
        let mut nonce = [0u8; NONCE_LEN];
        fill_random_nonzero(&mut nonce);

        // 预分配32字节的加密密钥缓冲区
        let mut key = [0u8; 32];
        // 如果启用了memlock特性，尝试锁定key缓冲区，防止被操作系统换出到磁盘
        #[cfg(feature = "memlock")]
        let _key_lock = LockedBufGuard::new(&mut key).ok();

        // 用KDF算法（PBKDF2或Argon2id）将密码和盐派生出加密密钥
        derive_key_into(kdf, password, &salt, &mut key)?;

        // 获取目标文件路径
        let target = path.as_ref();

        // 生成KDF算法标签字符串（如"PBKDF2-SHA256"或"Argon2id-v1:m=65536,p=1"）
        let kdf_label = kdf.label();
        // 获取存储用的迭代次数（PBKDF2为iterations，Argon2id为t_cost）
        let iterations_for_store = match kdf {
            KdfKind::Pbkdf2 { iterations } => iterations,
            #[cfg(feature = "argon2")]
            KdfKind::Argon2id { t_cost, .. } => t_cost,
        };
        // 生成AES-GCM的AAD（附加认证数据），绑定文件版本、算法、迭代次数和magic
        let aad = make_aad(
            WALLET_VERSION,
            &kdf_label,
            iterations_for_store,
            WALLET_MAGIC,
        );

        let result = (|| -> Result<()> {
            // 用派生密钥初始化AES-256-GCM加密器
            let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
            // 获取私钥原始字节，并用Zeroizing包装，防止内存残留
            let plaintext = Zeroizing::new(self.secret_key.secret_bytes().to_vec());
            // 执行AES-GCM加密，得到密文
            let ciphertext = cipher
                .encrypt(
                    GenericArray::from_slice(&nonce),
                    Payload {
                        msg: &plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow!("AES-GCM encrypt failed"))?;

            // 构造加密钱包文件结构体，准备序列化为JSON
            let enc = EncryptedWallet {
                magic: Some(WALLET_MAGIC.into()), // 魔法字串，标识这是Ark钱包文件
                version: WALLET_VERSION,          // 钱包文件版本号
                kdf: kdf_label,                   // 加密算法标签（比如PBKDF2-SHA256）
                iterations: iterations_for_store, // 迭代次数（加密算法参数）
                salt_hex: hex::encode(salt),      // 盐（16字节，转成16进制字符串）
                nonce_hex: hex::encode(nonce),    // 随机数（12字节，转成16进制字符串）
                ciphertext_hex: hex::encode(ciphertext), // 密文（加密后的私钥，转成16进制字符串）
            };
            // 根据编译模式选择是否美化JSON
            let json_bytes = (if cfg!(debug_assertions) {
                serde_json::to_vec_pretty(&enc)
            } else {
                serde_json::to_vec(&enc)
            })
            .context("serialize encrypted wallet")?;
            // 用Zeroizing包装JSON数据，防止内存残留
            let data = Zeroizing::new(json_bytes);
            // 原子方式写入到目标文件，确保写入安全
            write_file_atomically(target, &data)
        })();

        // 加密密钥、盐、nonce用完后立即清零，防止敏感数据泄露
        key.zeroize();
        salt.zeroize();
        nonce.zeroize();

        // 返回加密保存结果
        result
    }

    /// 从加密文件加载钱包。支持 v1 兼容模式与 AAD 绑定校验。
    pub fn load_encrypted<P: AsRef<Path>>(path: P, password: &[u8]) -> Result<Self> {
        // 检查密码是否为空
        if password.is_empty() {
            return Err(anyhow!("password must not be empty"));
        }

        // Unix 平台：拒绝通过符号链接读取钱包文件，防止路径攻击
        #[cfg(unix)]
        if unix_is_symlink(path.as_ref()) {
            return Err(anyhow!("refuse to read wallet via symlink"));
        }
        // Windows 平台：拒绝通过重解析点读取钱包文件，防止路径攻击
        #[cfg(windows)]
        if windows_has_reparse_point(path.as_ref()) {
            return Err(anyhow!("refuse to read wallet via reparse point"));
        }

        // 读取钱包文件内容（安全读取，防止大文件攻击）
        let data = read_wallet_file_secure(path.as_ref())?;
        // 反序列化 JSON，解析为 EncryptedWallet 结构体
        let enc: EncryptedWallet =
            serde_json::from_slice(&data).context("parse encrypted wallet json")?;

        // v2 及以上版本：校验 magic 字段，防止伪造钱包文件
        if enc.version >= 2 && enc.magic.as_deref() != Some(WALLET_MAGIC) {
            return Err(WalletError::Magic.into());
        }
        // v2 及以上版本：校验密码长度
        if enc.version >= 2 && password.len() < MIN_PASSWORD_LEN {
            #[cfg(feature = "timing_harden")]
            uniform_delay_on_auth_failure();
            return Err(anyhow!("password too short (min {})", MIN_PASSWORD_LEN));
        }
        // 只允许加载 v1 或当前版本的钱包文件
        if !(enc.version == 1 || enc.version == WALLET_VERSION) {
            return Err(WalletError::Version(enc.version).into());
        }

        // 解析 KDF 算法和参数
        let kdf = parse_kdf(&enc.kdf, enc.iterations)?;

        // 解码盐、nonce、密文（hex 字符串转字节数组）
        let mut salt = hex::decode(&enc.salt_hex).context("salt hex invalid")?;
        let mut nonce = hex::decode(&enc.nonce_hex).context("nonce hex invalid")?;
        let mut ciphertext = hex::decode(&enc.ciphertext_hex).context("cipher hex invalid")?;

        // 校验盐和 nonce 的长度与内容
        if let Err(e) = validate_salt_nonce(&salt, &nonce) {
            salt.zeroize();
            nonce.zeroize();
            ciphertext.zeroize();
            return Err(e);
        }
        // 校验密文长度（至少 16 字节，AES-GCM tag 长度）
        if ciphertext.len() < 16 {
            salt.zeroize();
            nonce.zeroize();
            ciphertext.zeroize();
            return Err(anyhow!("ciphertext too short"));
        }

        // 预分配 32 字节的解密密钥缓冲区
        let mut key = [0u8; 32];
        // 如果启用了 memlock 特性，尝试锁定 key 缓冲区，防止被换出到磁盘
        #[cfg(feature = "memlock")]
        let _key_lock = LockedBufGuard::new(&mut key).ok();

        // 用 KDF 算法（PBKDF2/Argon2id）将密码和盐派生出解密密钥
        derive_key_into(kdf, password, &salt, &mut key)?;

        // 用派生密钥初始化 AES-256-GCM 解密器
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
        // 生成 AAD（附加认证数据），绑定 magic/version/kdf/iterations
        let magic_for_aad = enc.magic.as_deref().unwrap_or(WALLET_MAGIC);
        let aad = make_aad(enc.version, &enc.kdf, enc.iterations, magic_for_aad);
        // v1 兼容模式：允许无 AAD 解密
        let allow_fallback = enc.version == 1;

        // 尝试用 AAD 解密密文，得到私钥明文
        let plaintext = match cipher.decrypt(
            GenericArray::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_ref(), // 要解密的数据（密文）
                aad: &aad,                // 附加认证数据（绑定了magic/version/kdf/iterations）
            },
        ) {
            // 解密成功，包装为 Zeroizing，自动清理内存
            Ok(p) => Zeroizing::new(p),
            // v1 兼容模式下，尝试无 AAD 解密
            Err(_) if allow_fallback => {
                match cipher.decrypt(GenericArray::from_slice(&nonce), ciphertext.as_ref()) {
                    Ok(p2) => Zeroizing::new(p2),
                    // 解密失败，清理敏感数据并返回认证失败
                    Err(_) => {
                        #[cfg(feature = "timing_harden")]
                        uniform_delay_on_auth_failure();
                        key.zeroize();
                        salt.zeroize();
                        nonce.zeroize();
                        ciphertext.zeroize();
                        return Err(WalletError::Auth.into());
                    }
                }
            }
            // 其它情况，解密失败，清理敏感数据并返回认证失败
            Err(_) => {
                #[cfg(feature = "timing_harden")]
                uniform_delay_on_auth_failure();
                key.zeroize();
                salt.zeroize();
                nonce.zeroize();
                ciphertext.zeroize();
                return Err(WalletError::Auth.into());
            }
        };

        // 校验私钥明文长度（必须为 32 字节）
        if plaintext.len() != 32 {
            key.zeroize();
            salt.zeroize();
            nonce.zeroize();
            ciphertext.zeroize();
            return Err(anyhow!("invalid secret key length"));
        }

        // 用私钥明文恢复 SecretKey 对象
        let sk = match SecretKey::from_slice(&plaintext) {
            Ok(sk) => sk,
            Err(e) => {
                key.zeroize();
                salt.zeroize();
                nonce.zeroize();
                ciphertext.zeroize();
                return Err(anyhow!("secret key invalid: {e}"));
            }
        };

        // 用 SecretKey 构造 Wallet 实例（自动推导公钥和地址）
        let wallet = Wallet::from_secret_key(sk)?;
        // 清理所有敏感数据
        key.zeroize();
        salt.zeroize();
        nonce.zeroize();
        ciphertext.zeroize();
        // 返回解密后的钱包
        Ok(wallet)
    }

    /// 原地升级钱包加密格式（如从v1升级到v2，或参数升级）。
    /// 步骤：先用旧密码解密钱包，再用同样密码重新加密并覆盖原文件。
    pub fn upgrade_encryption_in_place<P: AsRef<Path>>(path: P, password: &[u8]) -> Result<()> {
        // 检查密码是否为空
        if password.is_empty() {
            return Err(anyhow!("password must not be empty"));
        }
        // 加载（解密）原有钱包文件
        let w = Wallet::load_encrypted(&path, password)?;
        // 用同样的密码重新加密并保存（覆盖原文件，实现升级）
        w.save_encrypted(path, password)
    }

    /// 修改钱包密码（原地重加密钱包文件）
    /// 步骤：用旧密码解密钱包，再用新密码重新加密并覆盖原文件。
    pub fn change_password<P: AsRef<Path>>(
        path: P,
        old_password: &[u8],
        new_password: &[u8],
    ) -> Result<()> {
        // 检查旧密码和新密码是否为空
        if old_password.is_empty() || new_password.is_empty() {
            return Err(anyhow!("password must not be empty"));
        }
        // 校验新密码强度（长度等要求）
        validate_password_strength(new_password)?;
        // 新密码不能和旧密码相同
        if new_password == old_password {
            return Err(anyhow!("new password must be different"));
        }
        // 用旧密码解密钱包文件
        let w = Wallet::load_encrypted(&path, old_password)?;
        // 用新密码重新加密并保存（覆盖原文件）
        w.save_encrypted(path, new_password)
    }

    /// 原地升级钱包加密算法为 Argon2id（需启用 argon2 特性）。
    /// 步骤：用当前钱包内容和密码，采用 Argon2id 算法重新加密并覆盖原文件，提升安全性。
    #[cfg(feature = "argon2")]
    pub fn upgrade_to_argon2_in_place<P: AsRef<Path>>(
        &self,
        path: P,
        password: &[u8],
    ) -> Result<()> {
        // 用 Argon2id 算法和当前密码重新加密钱包，覆盖原文件
        self.save_encrypted_argon2(path, password)
    }
    /// 修改钱包密码并升级为 Argon2id 加密（需启用 argon2 特性）。
    /// 步骤：用旧密码解密钱包，再用新密码和 Argon2id 算法重新加密并覆盖原文件，提升安全性。
    #[cfg(feature = "argon2")]
    pub fn change_password_to_argon2<P: AsRef<Path>>(
        path: P,
        old_password: &[u8],
        new_password: &[u8],
    ) -> Result<()> {
        // 检查旧密码和新密码是否为空
        if old_password.is_empty() || new_password.is_empty() {
            return Err(anyhow!("password must not be empty"));
        }
        // 校验新密码强度（长度等要求）
        validate_password_strength(new_password)?;
        // 新密码不能和旧密码相同
        if new_password == old_password {
            return Err(anyhow!("new password must be different"));
        }
        // 用旧密码解密钱包文件
        let w = Wallet::load_encrypted(&path, old_password)?;
        // 用新密码和 Argon2id 算法重新加密并保存（覆盖原文件）
        w.save_encrypted_argon2(path, new_password)
    }

    /// 清理指定目录下过期的钱包临时文件（如 wallet.json.*.tmp）
    /// - dir: 目录路径
    /// - base: 钱包基础文件名（如 "wallet.json"）
    /// - max_age_secs: 最大允许的临时文件存活秒数（超过即删除）
    pub fn cleanup_stale_wallet_temps<P: AsRef<Path>>(
        dir: P,
        base: &str,
        max_age_secs: u64,
    ) -> Result<usize> {
        // 校验基础文件名是否合法，防止路径注入等安全风险
        validate_base_name(base)?;
        let dir = dir.as_ref();
        // 获取当前系统时间（秒）
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut removed = 0usize;
        // 遍历目录下所有文件
        for entry in fs::read_dir(dir).with_context(|| format!("read_dir {dir:?}"))? {
            let entry = entry?;
            let path = entry.path();
            // 只处理普通文件，跳过目录等
            if !path.is_file() {
                continue;
            }
            // 获取文件名字符串
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => {
                    continue;
                }
            };
            // 只处理以 "{base}." 开头、".tmp" 结尾的临时文件
            if !name.starts_with(&format!("{base}.")) || !name.ends_with(".tmp") {
                continue;
            }
            // 获取文件元数据
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => {
                    continue;
                }
            };
            // 获取文件的最后修改时间（秒），如果失败则用当前时间
            let secs = meta
                .modified()
                .or_else(|_| meta.created())
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(now);
            // 判断文件是否超过最大存活时间
            if now.saturating_sub(secs) >= max_age_secs {
                // 删除过期临时文件
                let _ = fs::remove_file(&path);
                removed += 1;
            }
        }
        // 返回删除的临时文件数量
        Ok(removed)
    }

    /// 清理指定目录下多余的备份钱包文件，只保留最新的 keep 个备份（按修改时间排序）。
    /// - dir: 备份文件所在目录
    /// - base: 钱包基础文件名（如 "wallet.json"）
    /// - keep: 要保留的最新备份文件数量
    #[cfg(feature = "backup")]
    pub fn cleanup_backups<P: AsRef<Path>>(dir: P, base: &str, keep: usize) -> Result<usize> {
        // 校验基础文件名是否合法，防止路径注入等安全风险
        validate_base_name(base)?;
        let dir = dir.as_ref();
        // 收集所有以 "{base}.bak." 开头的备份文件
        let mut entries: Vec<_> = fs::read_dir(dir)
            .with_context(|| format!("read_dir {dir:?}"))?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.starts_with(&format!("{base}.bak."))
            })
            .collect();
        // 按文件修改时间从新到旧排序
        entries.sort_by(|a, b| {
            let am = a.metadata().and_then(|m| m.modified()).ok();
            let bm = b.metadata().and_then(|m| m.modified()).ok();
            bm.cmp(&am)
        });
        let mut removed = 0usize;
        // 如果备份数量超过 keep，删除较旧的备份
        if entries.len() > keep {
            for e in entries.iter().skip(keep) {
                let _ = fs::remove_file(e.path());
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// 根据目标耗时自动校准 PBKDF2 迭代次数，使 KDF 运算大致耗时 target_ms 毫秒。
    /// 用于自适应调整加密强度，兼容不同硬件性能。
    /// 返回：建议使用的迭代次数（已限制在允许范围内）
    pub fn calibrate_pbkdf2_iterations(target_ms: u64) -> u32 {
        use std::time::Instant;
        // 生成随机盐
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        // 预分配 32 字节密钥缓冲区
        let mut key = [0u8; 32];
        // 使用固定测试密码
        let pw = b"benchmark_password";

        // 先用 1 万次迭代做一次热身，测量耗时
        let warm_iters = 10_000u32;
        let t0 = Instant::now();
        pbkdf2_hmac::<Sha256>(pw, &salt, warm_iters, &mut key);
        let elapsed = t0.elapsed().as_millis().max(1) as u64; // 防止除零
                                                              // 计算每次迭代大约耗时多少纳秒
        let per_iter_ns = (elapsed * 1_000_000) / (warm_iters as u64);

        // 根据目标耗时（毫秒）推算需要多少次迭代
        let desired = (target_ms * 1_000_000) / per_iter_ns;
        // 限制在允许的最小/最大迭代次数范围内
        let clamped = desired.clamp(MIN_PBKDF2_ITERATIONS as u64, MAX_PBKDF2_ITERATIONS as u64);
        clamped as u32
    }

    /// 根据系统内存自动推荐 Argon2id 参数（需启用 argon2 和 sysinfo_params 特性）。
    /// 返回值：(m_kib, p, t)
    /// - m_kib: 内存消耗（单位 KiB）
    /// - p: 并行度（线程数）
    /// - t: 迭代次数（time cost）
    ///
    /// 逻辑：
    /// - 默认内存消耗 64 MiB（65536 KiB）
    /// - 如果系统内存 ≥ 8 GiB，提升到 256 MiB
    /// - 如果系统内存 ≥ 4 GiB，提升到 128 MiB
    /// - 并行度固定为 1，迭代次数固定为 3
    #[cfg(all(feature = "argon2", feature = "sysinfo_params"))]
    pub fn recommend_argon2_params() -> (u32, u32, u32) {
        let p = 1u32; // 并行度
        let t = 3u32; // 迭代次数
        let mut m_kib = 64 * 1024u32; // 默认 64 MiB
        let mut sys = sysinfo::System::new_all();
        sys.refresh_memory();
        let total_mib = sys.total_memory() / 1024;
        if total_mib >= 8 * 1024 {
            m_kib = 256 * 1024; // 8 GiB 及以上，提升到 256 MiB
        } else if total_mib >= 4 * 1024 {
            m_kib = 128 * 1024; // 4 GiB 及以上，提升到 128 MiB
        }
        (m_kib, p, t)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedWallet {
    #[serde(default)]
    /// 魔术字串（类型标识），如 Some("ArkWallet")，用于防伪和 AAD 绑定
    magic: Option<String>,

    #[serde(default = "default_version")]
    /// 钱包文件格式版本号，默认 1，当前主流为 2
    version: u32,

    /// 密钥派生算法标签（如 "PBKDF2-SHA256" 或 "Argon2id-v1:m=65536,p=1"）
    kdf: String,

    /// KDF 的迭代次数（PBKDF2: iterations，Argon2: t_cost）
    iterations: u32,

    /// 盐值（16字节，hex字符串），用于KDF，防止同一密码生成相同密钥
    salt_hex: String,

    /// 随机数（12字节，hex字符串），AES-GCM Nonce，保证每次加密结果不同
    nonce_hex: String,

    /// 加密后的私钥密文（hex字符串），用AES-256-GCM加密得到
    ciphertext_hex: String,
}

/// 返回钱包文件的默认版本号（用于序列化时的默认值）。
fn default_version() -> u32 {
    1
}

/// 生成 AES-GCM 加密用的 AAD（附加认证数据）。
/// AAD 绑定了 magic/version/kdf/iterations，防止钱包文件被篡改。
/// - version: 钱包文件版本号
/// - kdf: 密钥派生算法标签
/// - iterations: KDF 迭代次数
/// - magic: 魔术字串（类型标识）
fn make_aad(version: u32, kdf: &str, iterations: u32, magic: &str) -> Vec<u8> {
    format!("m={magic};v={version};k={kdf};i={iterations}").into_bytes()
}

#[cfg(feature = "backup")]
/// 创建加密钱包文件的备份（带时间戳）。
pub fn create_encrypted_backup<P: AsRef<Path>>(target: P) -> Result<PathBuf> {
    let target = target.as_ref();
    let data = read_wallet_file_secure(target)?;
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let base = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("wallet.json");
    // 使用毫秒级时间戳，避免同一秒内多个备份被覆盖
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let backup = dir.join(format!("{base}.bak.{ts}"));
    write_file_atomically(&backup, &data)?;
    Ok(backup)
}

/// 清理指定目录下多余的备份钱包文件，只保留最新的 keep 个备份（按修改时间排序）。
/// - dir: 备份文件所在目录
/// - base: 钱包基础文件名（如 "wallet.json"）
/// - keep: 要保留的最新备份文件数量
#[cfg(feature = "backup")]
pub fn cleanup_backups<P: AsRef<Path>>(dir: P, base: &str, keep: usize) -> Result<usize> {
    // 校验基础文件名是否合法，防止路径注入等安全风险
    validate_base_name(base)?;
    let dir = dir.as_ref();
    // 收集所有以 "{base}.bak." 开头的备份文件
    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("read_dir {dir:?}"))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with(&format!("{base}.bak."))
        })
        .collect();
    // 按文件修改时间从新到旧排序
    entries.sort_by(|a, b| {
        let am = a.metadata().and_then(|m| m.modified()).ok();
        let bm = b.metadata().and_then(|m| m.modified()).ok();
        bm.cmp(&am)
    });
    let mut removed = 0usize;
    // 如果备份数量超过 keep，删除较旧的备份
    if entries.len() > keep {
        for e in entries.iter().skip(keep) {
            let _ = fs::remove_file(e.path());
            removed += 1;
        }
    }
    Ok(removed)
}

fn write_file_atomically(target: &Path, data: &[u8]) -> Result<()> {
    // 1. 校验并创建父目录，防止路径攻击和写入失败
    if let Some(parent) = target.parent() {
        validate_parent_dir(parent)?; // 检查父目录是否合法（不是符号链接/特殊目录）
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).context("create parent directory")?; // 如不存在则创建
        }
        validate_parent_dir(parent)?; // 再次校验，防止 TOCTOU 攻击
    }
    // 2. 校验目标文件路径是否合法（不是符号链接/特殊文件/ADS）
    validate_target_path_for_write(target)?;

    // 3. 临时文件写入
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let base = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("wallet.json");
    // 在目标目录下创建唯一的临时文件（如 wallet.json.xxxxxxxx.tmp）
    let (mut f, tmp) = create_temp_exclusive(dir, base)?;
    // 写入数据到临时文件
    f.write_all(data).context("write temp file")?;
    // 强制同步数据到磁盘，确保写入不在缓存
    f.sync_all().context("fsync temp file")?;
    drop(f); // 关闭临时文件，为后续原子替换做准备

    // 4. 最终替换前的最后检查与原子替换
    final_pre_replace_check(target)?; // 再次检查目标文件，防止竞态
    if let Err(e) = atomic_replace_with_retry(&tmp, target) {
        let _ = fs::remove_file(&tmp); // 替换失败时清理临时文件
        return Err(e).context("atomic replace tmp -> target");
    }

    // 5. 平台相关的同步和属性设置
    #[cfg(windows)]
    {
        let _ = set_windows_attrs(target); // Windows: 设置文件属性（如隐藏/不参与索引）
    }
    #[cfg(unix)]
    {
        if let Some(parent) = target.parent() {
            sync_dir(parent).context("fsync parent directory")?; // Unix: 强制同步父目录
        }
    }
    Ok(())
}

// 工具函数
#[cfg(feature = "timing_harden")]
/// 在认证失败时，随机延迟一段时间（40~120ms），防止通过响应时间推测密码是否正确。
/// 作用：防御“时序攻击”，让每次认证失败的耗时都接近一致，提升安全性。
/// - MIN_MS: 最小延迟毫秒数（40ms）
/// - MAX_MS: 最大延迟毫秒数（120ms）
/// - 实现：sleep 随机时长后，再自旋补足总时长，保证延迟精度。
fn uniform_delay_on_auth_failure() {
    use std::thread::sleep;
    use std::time::{Duration, Instant};
    const MIN_MS: u64 = 40;
    const MAX_MS: u64 = 120;
    let span = MAX_MS.saturating_sub(MIN_MS);
    let mut rng = OsRng;
    // 生成 [0, span] 范围内的随机抖动
    let jitter = if span > 0 {
        (rng.next_u32() as u64) % (span + 1)
    } else {
        0
    };
    let total = Duration::from_millis(MIN_MS + jitter);
    let start = Instant::now();
    sleep(total); // 线程休眠
                  // 精确补足剩余时间，防止 sleep 不足
    while start.elapsed() < total {
        std::hint::spin_loop();
    }
}

#[cfg(unix)]
#[inline]
/// 判断指定路径是否为符号链接（仅 Unix 平台）
/// 返回 true 表示是符号链接，false 表示不是或获取失败
fn unix_is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// 校验父级目录是否合法和安全
/// - 必须是已存在的普通目录
/// - 不能是符号链接（Unix）
/// - 不能是重解析点或带 ADS 的路径（Windows）
fn validate_parent_dir(parent: &Path) -> Result<()> {
    // 如果父级目录已存在
    if parent.exists() {
        // 获取元数据，判断是否为目录
        if let Ok(meta) = fs::metadata(parent) {
            if !meta.is_dir() {
                // 如果不是目录，返回错误
                return Err(anyhow!("parent is not a directory"));
            }
        }
    }
    // Windows 平台：拒绝带有 ADS (:) 的路径
    #[cfg(windows)]
    if windows_path_has_ads(parent) {
        return Err(anyhow!("refuse to write into path with ADS (:)"));
    }
    // Unix 平台：拒绝符号链接目录
    #[cfg(unix)]
    if unix_is_symlink(parent) {
        return Err(anyhow!("refuse to write into symlinked parent directory"));
    }
    // Windows 平台：拒绝重解析点目录
    #[cfg(windows)]
    if windows_has_reparse_point(parent) {
        return Err(anyhow!("refuse to write into reparse point directory"));
    }
    // 校验通过
    Ok(())
}

fn validate_target_path_for_write(target: &Path) -> Result<()> {
    // 检查目标文件是否为符号链接（symlink），如果是则拒绝覆盖，防止被劫持
    if let Ok(meta) = fs::symlink_metadata(target) {
        if meta.file_type().is_symlink() {
            return Err(anyhow!("refuse to overwrite symlinked wallet file"));
        }
    }
    // Windows 平台：拒绝带有 ADS (:) 的路径，防止数据流攻击
    #[cfg(windows)]
    if windows_path_has_ads(target) {
        return Err(anyhow!("refuse to write wallet to ADS path (:)"));
    }
    // 如果目标文件已存在，必须是普通文件（不是目录、不是特殊文件）
    if let Ok(meta) = fs::metadata(target) {
        if !meta.is_file() {
            return Err(anyhow!("target path is not a regular file"));
        }
    }
    // Windows 平台：拒绝重解析点（特殊目录/文件），防止路径攻击
    #[cfg(windows)]
    if windows_has_reparse_point(target) {
        return Err(anyhow!("refuse to overwrite reparse point"));
    }
    // 校验通过
    Ok(())
}

/// 最终替换前的安全检查，防止竞态攻击（TOCTOU）
/// - Unix：拒绝目标文件是符号链接，防止被劫持
/// - Windows：拒绝目标文件是重解析点，防止特殊目录/文件攻击
fn final_pre_replace_check(target: &Path) -> Result<()> {
    // Unix 平台：如果目标文件是符号链接，拒绝覆盖，防止竞态攻击
    #[cfg(unix)]
    if unix_is_symlink(target) {
        return Err(anyhow!("refuse to overwrite symlinked wallet file (race)"));
    }
    // Windows 平台：如果目标文件是重解析点，拒绝覆盖，防止竞态攻击
    #[cfg(windows)]
    if windows_has_reparse_point(target) {
        return Err(anyhow!("refuse to overwrite reparse point (race)"));
    }
    // 校验通过
    Ok(())
}

#[cfg(windows)]
/// 在 Windows 平台下，原子性地用 src 替换 dst 文件（带重试机制）。
/// 优先使用 ReplaceFileW（原子替换），失败则降级为 MoveFileExW。
fn atomic_replace_with_retry(src: &Path, dst: &Path) -> Result<()> {
    // 将源文件和目标文件路径转换为以 0 结尾的 UTF-16 编码（Windows API 需要）
    let src_w: Vec<u16> = src
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dst_w: Vec<u16> = dst
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // 优先尝试使用 ReplaceFileW 进行原子替换（Windows 原生 API，推荐方式）
    let rep_res = unsafe {
        ReplaceFileW(
            PCWSTR(dst_w.as_ptr()),    // 目标文件路径
            PCWSTR(src_w.as_ptr()),    // 源（临时）文件路径
            PCWSTR::null(),            // 备份文件路径（不需要）
            REPLACEFILE_WRITE_THROUGH, // 写入后立即落盘
            None,
            None,
        )
    };
    // 如果 ReplaceFileW 成功，直接返回 Ok
    if rep_res.is_ok() {
        return Ok(());
    }

    // 如果 ReplaceFileW 失败，降级为 MoveFileExW（带覆盖和写穿透标志）
    let mv_res = unsafe {
        MoveFileExW(
            PCWSTR(src_w.as_ptr()),                             // 源（临时）文件路径
            PCWSTR(dst_w.as_ptr()),                             // 目标文件路径
            MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING, // 覆盖并写穿透
        )
    };
    // 如果 MoveFileExW 成功，直接返回 Ok
    if mv_res.is_ok() {
        return Ok(());
    }

    // 合并错误而不使用 unwrap
    let err = mv_res
        .err()
        .or_else(|| rep_res.err())
        .ok_or_else(|| anyhow!("atomic replace failed without Windows error"))?;
    Err(anyhow!("atomic replace failed: {err}"))
}

#[cfg(not(windows))]
/// 非 Windows 平台下的原子替换实现：直接用 std::fs::rename（通常是原子操作）
fn atomic_replace_with_retry(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::rename(src, dst)
}

#[cfg(unix)]
/// Unix 平台下同步目录元数据，确保文件操作落盘
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    let f = File::open(dir)?; // 打开目录
    f.sync_all() // 强制同步目录元数据到磁盘
}

/// 在指定目录下创建唯一的临时文件（带随机后缀，防止重名冲突）
/// - dir: 目标目录
/// - base: 基础文件名（如 "wallet.json"）
fn create_temp_exclusive(dir: &Path, base: &str) -> Result<(File, PathBuf)> {
    for _ in 0..8 {
        let mut rnd = [0u8; 8];
        OsRng.fill_bytes(&mut rnd); // 生成 8 字节随机数
        let tmp_name = format!("{base}.{}.tmp", hex::encode(rnd)); // 拼接临时文件名
        let candidate = dir.join(tmp_name); // 组合完整路径
        let mut opts = OpenOptions::new();
        opts.create_new(true).write(true); // 只在文件不存在时创建，防止覆盖
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600); // Unix 下设置权限为 600（仅当前用户可读写）
        }
        match opts.open(&candidate) {
            Ok(f) => {
                // 创建成功，返回文件句柄和路径
                return Ok((f, candidate));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // 如果文件已存在，尝试下一个随机名
                continue;
            }
            Err(e) => {
                // 其它错误，返回错误信息
                return Err(e).context("create temp file");
            }
        }
    }
    // 连续 8 次都冲突，返回错误
    Err(anyhow!("create temp file: too many collisions"))
}
#[cfg(unix)]
/// 安全读取加密钱包文件内容（仅 Unix 平台）
/// - 防止符号链接攻击（O_NOFOLLOW）
/// - 防止大文件 DoS 攻击
/// - 只允许读取普通文件
fn read_wallet_file_secure(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;

    // 以只读方式打开文件，并加上 O_NOFOLLOW（拒绝符号链接）、O_CLOEXEC（防止句柄泄露）
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("open encrypted wallet file (O_NOFOLLOW)")?;

    // 获取文件元数据，检查类型和大小
    let meta = file.metadata().context("fstat encrypted wallet file")?;
    if !meta.is_file() {
        // 不是普通文件则报错
        return Err(WalletError::NotRegularFile.into());
    }
    if meta.len() > MAX_WALLET_FILE_SIZE {
        // 文件太大则报错，防止 DoS 攻击
        return Err(WalletError::FileTooLarge(meta.len()).into());
    }

    // 读取文件内容到缓冲区
    let mut reader = BufReader::new(file);
    let mut buf = Vec::with_capacity((meta.len() as usize).min(MAX_WALLET_FILE_SIZE as usize));
    reader
        .read_to_end(&mut buf)
        .context("read encrypted wallet file")?;
    Ok(buf)
}

#[cfg(not(unix))]
/// 安全读取加密钱包文件内容（非 Unix 平台，如 Windows）
/// - 防止大文件 DoS 攻击
/// - 只允许读取普通文件
fn read_wallet_file_secure(path: &Path) -> Result<Vec<u8>> {
    // 打开钱包文件（只读模式）
    let file = File::open(path).context("open encrypted wallet file")?;
    // 获取文件元数据（类型、大小等）
    let meta = file.metadata().context("fstat encrypted wallet file")?;
    // 检查是否为普通文件（不是目录、设备等）
    if !meta.is_file() {
        return Err(WalletError::NotRegularFile.into());
    }
    // 检查文件大小，防止恶意超大文件攻击
    if meta.len() > MAX_WALLET_FILE_SIZE {
        return Err(WalletError::FileTooLarge(meta.len()).into());
    }
    // 用缓冲区读取文件内容到内存
    let mut reader = std::io::BufReader::new(file);
    let mut buf = Vec::with_capacity((meta.len() as usize).min(MAX_WALLET_FILE_SIZE as usize));
    use std::io::Read;
    reader
        .read_to_end(&mut buf)
        .context("read encrypted wallet file")?;
    // 返回文件内容（字节数组）
    Ok(buf)
}
/// 判断指定路径是否为重解析点（reparse point，Windows 下的特殊目录/文件）
/// 返回 true 表示是重解析点，false 表示不是或获取属性失败
#[cfg(windows)]
fn windows_has_reparse_point(path: &Path) -> bool {
    // 将路径转换为以 0 结尾的 UTF-16 编码（Windows API 需要）
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        // 调用 Windows API 获取文件属性
        let attrs = GetFileAttributesW(PCWSTR(wide.as_ptr()));
        if attrs == INVALID_FILE_ATTRIBUTES {
            // 获取属性失败，返回 false
            false
        } else {
            // 检查属性中是否包含重解析点标志
            (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0
        }
    }
}

#[cfg(windows)]
/// 判断路径是否包含 ADS（Alternate Data Streams，Windows 下的冒号攻击）
/// 返回 true 表示路径中有冒号（:），可能是 ADS，false 表示没有
fn windows_path_has_ads(path: &Path) -> bool {
    use std::path::Component;
    // 遍历路径的每一部分
    for comp in path.components() {
        // 只检查普通路径部分（不检查根、前缀等）
        if let Component::Normal(os) = comp {
            // 如果这一部分包含冒号（:），说明可能是 ADS
            if os.to_string_lossy().contains(':') {
                return true;
            }
        }
    }
    // 没有发现冒号，返回 false
    false
}

// 统一校验：盐与随机数（长度 + 非全零）
fn validate_salt_nonce(salt: &[u8], nonce: &[u8]) -> Result<()> {
    // 检查 salt 和 nonce 的长度是否符合要求
    if salt.len() != SALT_LEN || nonce.len() != NONCE_LEN {
        return Err(anyhow!("invalid salt/nonce length"));
    }
    // 检查 salt 或 nonce 是否全为 0（全 0 不安全）
    if salt.iter().all(|&b| b == 0) || nonce.iter().all(|&b| b == 0) {
        return Err(anyhow!("invalid salt/nonce"));
    }
    // 校验通过
    Ok(())
}

// 统一派生：根据 KDF 生成 32 字节密钥
/// 根据指定的 KDF 算法（PBKDF2 或 Argon2id）
/// 用密码和盐派生出 32 字节的加密密钥，写入 out_key。
/// - kdf: 密钥派生算法及参数
/// - password: 用户输入的密码
/// - salt: 随机盐
/// - out_key: 输出的 32 字节密钥缓冲区
fn derive_key_into(
    kdf: KdfKind,
    password: &[u8],
    salt: &[u8],
    out_key: &mut [u8; 32],
) -> Result<()> {
    match kdf {
        // 如果是 PBKDF2 算法
        KdfKind::Pbkdf2 { iterations } => {
            let min_iters = TEST_MIN_PBKDF2;
            // 检查迭代次数是否在允许范围内
            if !(min_iters..=MAX_PBKDF2_ITERATIONS).contains(&iterations) {
                return Err(anyhow!(
                    "pbkdf2 iterations out of range: {}, allowed {}..={}",
                    iterations,
                    min_iters,
                    MAX_PBKDF2_ITERATIONS
                ));
            }
            // 用 PBKDF2 算法派生密钥，写入 out_key
            pbkdf2_hmac::<Sha256>(password, salt, iterations, out_key);
            Ok(())
        }
        // 如果是 Argon2id 算法（需启用 argon2 特性）
        #[cfg(feature = "argon2")]
        KdfKind::Argon2id {
            t_cost,
            m_cost_kib,
            parallelism,
        } => {
            // 调用 Argon2id 派生密钥函数
            derive_key_argon2id(password, salt, t_cost, m_cost_kib, parallelism, out_key)
        }
    }
}

// Windows：统一设置文件属性（不参与内容索引 + 可选隐藏）
#[cfg(windows)]
fn set_windows_attrs(target: &Path) -> Result<()> {
    // 将目标路径转换为以 0 结尾的 UTF-16 编码（Windows API 需要）
    let dst_w: Vec<u16> = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // 获取当前文件属性
        let mut attrs = GetFileAttributesW(PCWSTR(dst_w.as_ptr()));
        if attrs == INVALID_FILE_ATTRIBUTES {
            // 如果获取属性失败（如文件不存在），静默跳过
            return Ok(());
        }
        // 设置“不参与内容索引”属性，防止被 Windows 索引服务扫描
        attrs |= FILE_ATTRIBUTE_NOT_CONTENT_INDEXED.0;
        // 如果启用了 win_harden 特性，额外设置为“隐藏文件”
        #[cfg(feature = "win_harden")]
        {
            use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_HIDDEN;
            attrs |= FILE_ATTRIBUTE_HIDDEN.0;
        }
        // 应用新的文件属性
        SetFileAttributesW(PCWSTR(dst_w.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(attrs))?;
    }
    // 设置成功或跳过，返回 Ok
    Ok(())
}

#[cfg(feature = "argon2")]
/// 用 Argon2id 算法从密码和盐派生 32 字节密钥
/// - password: 用户输入的密码
/// - salt: 随机盐
/// - t_cost: 迭代次数（time cost）
/// - m_cost_kib: 内存消耗（单位 KiB）
/// - parallelism: 并行度（线程数）
/// - out32: 输出的 32 字节密钥缓冲区
fn derive_key_argon2id(
    password: &[u8],
    salt: &[u8],

    t_cost: u32,
    m_cost_kib: u32,
    parallelism: u32,
    out32: &mut [u8; 32],
) -> Result<()> {
    // 检查迭代次数是否在允许范围内（1~10）
    if !(1..=10).contains(&t_cost) {
        return Err(anyhow!("argon2 t_cost out of range"));
    }
    // 检查内存消耗是否在允许范围内（8 MiB ~  1 GiB）
    if !(8 * 1024..=1024 * 1024).contains(&m_cost_kib) {
        return Err(anyhow!("argon2 memory cost out of range"));
    }
    // 检查并行度是否在允许范围内（1~8）
    if !(1..=8).contains(&parallelism) {
        return Err(anyhow!("argon2 parallelism out of range"));
    }
    // 构造 Argon2 参数对象
    let params = Params::new(m_cost_kib, t_cost, parallelism, Some(32))
        .map_err(|_| anyhow!("argon2 params invalid"))?;
    // 创建 Argon2id 算法实例
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // 用 Argon2id 算法派生密钥，写入 out32
    argon2
        .hash_password_into(password, salt, out32)
        .map_err(|_| anyhow!("argon2 derive failed"))
}

#[cfg(feature = "argon2")]
/// 从 KDF 标签字符串中解析 Argon2 参数（内存消耗和并行度）
/// 例如：kdf = "Argon2id-v1:m=65536,p=1"
/// 返回 (m_cost_kib, parallelism)
fn parse_argon2_params_from_kdf(kdf: &str) -> Result<(u32, u32)> {
    // 查找参数部分（冒号后面）
    if let Some(pos) = kdf.find(':') {
        let params = &kdf[pos + 1..];
        // 默认参数
        let mut m_cost_kib = ARGON2_DEFAULT_M_COST_KIB;
        let mut parallelism = ARGON2_DEFAULT_PARALLELISM;
        // 解析每个参数（用逗号分隔）
        for part in params.split(',') {
            let mut it = part.splitn(2, '=');
            let k = it.next().unwrap_or("").trim();
            let v = it.next().unwrap_or("").trim();
            // 解析内存消耗参数 m
            if k.eq_ignore_ascii_case("m") {
                m_cost_kib = v.parse::<u32>().map_err(|_| anyhow!("invalid argon2 m"))?;
                // 解析并行度参数 p
            } else if k.eq_ignore_ascii_case("p") {
                parallelism = v.parse::<u32>().map_err(|_| anyhow!("invalid argon2 p"))?;
            }
        }
        Ok((m_cost_kib, parallelism))
    } else {
        // 如果没有参数部分，返回默认值
        Ok((ARGON2_DEFAULT_M_COST_KIB, ARGON2_DEFAULT_PARALLELISM))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::{env, str::FromStr};

    /// 生成一个唯一的临时文件路径，用于测试时避免文件名冲突
    fn test_temp_path(prefix: &str) -> PathBuf {
        // 1. 获取系统的临时目录（如 Windows 下是 C:\Users\用户名\AppData\Local\Temp）
        let mut p = env::temp_dir();
        // 2. 获取当前时间戳（单位：纳秒），这样每次生成的文件名都不会重复
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // 3. 拼接文件名：前缀_时间戳.json，例如 ark_wallet_test_1234567890.json
        p.push(format!("{prefix}_{ts}.json"));
        // 4. 返回完整的临时文件路径
        p
    }

    /// 测试新钱包的生成和地址格式是否合法
    #[test]
    fn test_new_wallet_and_address() -> anyhow::Result<()> {
        // 创建一个新钱包
        let w = Wallet::new()?;
        // 检查钱包地址是否以 '1' 开头（比特币风格）
        assert!(w.address.starts_with('1'));
        // 检查钱包地址长度是否在合理范围（26~35位）
        assert!((26..=35).contains(&w.address.len()));
        Ok(())
    }

    #[test]
    fn test_from_secret_key_and_sign() -> anyhow::Result<()> {
        // 用指定的私钥字符串创建 SecretKey 对象
        let sk = SecretKey::from_str(
            "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262",
        )?;
        // 用 SecretKey 创建钱包实例
        let w = Wallet::from_secret_key(sk)?;
        // 检查钱包地址是否等于预期的比特币风格地址
        assert_eq!(w.address, "1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj");

        // 要签名的消息内容
        let msg = b"ark-wallet";
        let sig = w.sign_sha256(msg)?; // <-- 适配 Result
        assert!(w.verify_sha256(msg, &sig)?); // <-- 适配 Result
        assert!(!w.verify_sha256(b"ark-wallet!", &sig)?);
        Ok(())
    }

    #[test]
    fn test_save_and_load_encrypted_wallet() -> anyhow::Result<()> {
        // 创建一个新的钱包对象
        let original_wallet = Wallet::new()?;
        // 设置一个测试用的强密码
        let password = b"a_very_strong_password";
        // 生成一个唯一的临时文件路径，用于保存加密钱包
        let path = test_temp_path("ark_wallet_test");
        // 用密码将钱包加密并保存到临时文件
        original_wallet.save_encrypted(&path, password)?;
        // 用同样的密码从文件中加载并解密钱包
        let loaded_wallet = Wallet::load_encrypted(&path, password)?;
        // 检查解密出来的钱包私钥是否和原钱包一致
        assert_eq!(
            original_wallet.secret_key.secret_bytes(),
            loaded_wallet.secret_key.secret_bytes()
        );
        // 检查公钥是否一致
        assert_eq!(original_wallet.public_key, loaded_wallet.public_key);
        // 检查钱包地址是否一致
        assert_eq!(original_wallet.address, loaded_wallet.address);
        // 用错误密码尝试解密，应该失败
        assert!(Wallet::load_encrypted(&path, b"wrong_password").is_err());
        // 删除临时文件，清理测试环境
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn test_overwrite_existing_wallet_file() -> anyhow::Result<()> {
        // 创建第一个钱包对象
        let w1 = Wallet::new()?;
        // 创建第二个钱包对象
        let w2 = Wallet::new()?;
        // 设置测试用的强密码
        let pwd = b"a_very_strong_password";
        // 生成一个唯一的临时文件路径
        let path = test_temp_path("ark_wallet_overwrite");
        // 用第一个钱包加密并保存到文件
        w1.save_encrypted(&path, pwd)?;
        // 用第二个钱包加密并保存到同一个文件（覆盖原内容）
        w2.save_encrypted(&path, pwd)?;
        // 用密码加载文件，得到最后保存的钱包
        let loaded = Wallet::load_encrypted(&path, pwd)?;
        // 检查加载出来的钱包私钥是否等于第二个钱包（说明覆盖成功）
        assert_eq!(
            loaded.secret_key.secret_bytes(),
            w2.secret_key.secret_bytes()
        );
        // 删除临时文件，清理测试环境
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn test_load_legacy_v1_wallet() -> anyhow::Result<()> {
        // 创建一个新的钱包对象
        let original_wallet = Wallet::new()?;
        // 设置一个测试用的强密码
        let password = b"a_very_strong_password";
        // 随机生成 salt（盐）
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        // 随机生成 nonce（随机数）
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        // 用 PBKDF2 算法从密码和盐派生出 32 字节密钥
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password, &salt, PBKDF2_ITERATIONS, &mut key);
        // 用派生密钥初始化 AES-256-GCM 加密器
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
        // 获取原钱包的私钥字节
        let plaintext = original_wallet.secret_key.secret_bytes();
        // 用 AES-GCM 加密私钥，得到密文
        let ciphertext = cipher
            .encrypt(GenericArray::from_slice(&nonce), plaintext.as_ref())
            .map_err(|_| anyhow!("manual v1 encrypt failed"))?;
        // 构造 v1 版本的加密钱包结构体
        let enc = EncryptedWallet {
            magic: Some(WALLET_MAGIC.into()),        // 魔法字串
            version: 1,                              // v1 版本
            kdf: "PBKDF2-SHA256".into(),             // KDF 算法
            iterations: PBKDF2_ITERATIONS,           // 迭代次数
            salt_hex: hex::encode(salt),             // 盐（16进制字符串）
            nonce_hex: hex::encode(nonce),           // 随机数（16进制字符串）
            ciphertext_hex: hex::encode(ciphertext), // 密文（16进制字符串）
        };
        // 序列化为 JSON 数据
        let data = serde_json::to_vec_pretty(&enc).context("serialize legacy v1 wallet")?;
        // 生成一个唯一的临时文件路径
        let path = test_temp_path("ark_wallet_legacy_v1");
        // 在临时目录下创建唯一的临时文件
        let (mut f, tmp) =
            create_temp_exclusive(path.parent().unwrap_or(Path::new(".")), "wallet.json")?;
        // 写入加密钱包数据到临时文件
        f.write_all(&data).context("write legacy v1 wallet file")?;
        // 强制同步到磁盘
        f.sync_all().context("fsync legacy v1 wallet file")?;
        drop(f); // 关闭文件
                 // 用密码加载并解密钱包
        let loaded_wallet = Wallet::load_encrypted(&tmp, password)?;
        // 检查解密出来的钱包私钥是否和原钱包一致
        assert_eq!(
            original_wallet.secret_key.secret_bytes(),
            loaded_wallet.secret_key.secret_bytes()
        );
        // 删除临时文件，清理测试环境
        let _ = fs::remove_file(&tmp);
        Ok(())
    }

    #[test]
    fn test_corrupted_ciphertext_fails_auth() -> anyhow::Result<()> {
        // 创建一个新的钱包对象
        let w = Wallet::new()?;
        // 设置测试用的强密码

        let pwd = b"a_very_strong_password";
        // 生成一个唯一的临时文件路径
        let path = test_temp_path("ark_wallet_corrupt");
        w.save_encrypted(&path, pwd)?;
        // 用密码加密并保存钱包到临时文件
        let mut enc: EncryptedWallet = serde_json::from_slice(&read_wallet_file_secure(&path)?)?;
        // 读取加密钱包文件内容并反序列化为 EncryptedWallet 结构体
        enc.ciphertext_hex.push_str("00");
        // 把被破坏的加密钱包重新写回文件
        fs::write(&path, serde_json::to_vec_pretty(&enc)?)?;
        // 尝试用密码解密被破坏的钱包，应该返回错误
        let err = Wallet::load_encrypted(&path, pwd).unwrap_err();
        // 获取错误信息并转为小写字符串
        let msg = format!("{err}").to_lowercase();
        // 检查错误信息中包含 "auth"，说明是认证失败（解密失败）
        assert!(msg.contains("auth"));
        // 删除临时文件，清理测试环境
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn test_short_password_is_rejected_on_load_v2() -> anyhow::Result<()> {
        // 创建一个新的钱包对象
        let w = Wallet::new()?;
        // 设置一个合格的强密码
        let good = b"a_very_strong_password";
        // 设置一个不合格的短密码
        let bad = b"1";
        // 生成一个唯一的临时文件路径
        let path = test_temp_path("ark_wallet_short_pwd");
        // 用强密码加密并保存钱包到临时文件
        w.save_encrypted(&path, good)?;
        // 尝试用短密码解密钱包，应该返回错误
        let err = Wallet::load_encrypted(&path, bad).unwrap_err();
        // 检查错误信息中包含 "password too short"
        assert!(format!("{err}").contains("password too short"));
        // 删除临时文件，清理测试环境
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn test_large_file_rejected() -> anyhow::Result<()> {
        // 生成一个唯一的临时文件路径
        let path = test_temp_path("ark_wallet_large");
        // 创建一个空文件
        let f = std::fs::File::create(&path)?;
        // 设置文件大小为钱包允许的最大值 + 1 字节（超出限制）
        f.set_len(super::MAX_WALLET_FILE_SIZE + 1)?;
        drop(f); // 关闭文件句柄
                 // 尝试加载这个超大文件，应该返回错误
        let err = Wallet::load_encrypted(&path, b"aaaaaaaa").unwrap_err();
        // 检查错误信息中包含 "too large"
        assert!(format!("{err}").contains("too large"));
        // 删除临时文件，清理测试环境
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_read_is_rejected() -> anyhow::Result<()> {
        // 创建一个新的钱包对象
        let w = Wallet::new()?;
        // 设置测试用的强密码
        let pwd = b"a_very_strong_password";
        // 生成真实钱包文件的临时路径
        let real = test_temp_path("ark_wallet_symlink_real");
        // 生成符号链接文件的临时路径
        let link = test_temp_path("ark_wallet_symlink_link");
        // 用密码加密并保存钱包到真实文件
        w.save_encrypted(&real, pwd)?;
        // 创建一个指向真实钱包文件的符号链接
        std::os::unix::fs::symlink(&real, &link)?;
        // 尝试通过符号链接加载钱包，应该被拒绝（返回错误）
        assert!(Wallet::load_encrypted(&link, pwd).is_err());
        // 删除真实钱包文件，清理测试环境
        let _ = fs::remove_file(&real);
        // 删除符号链接文件，清理测试环境
        let _ = fs::remove_file(&link);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_parent_dir_is_rejected_on_save() -> anyhow::Result<()> {
        // 创建一个新的钱包对象
        let w = Wallet::new()?;
        // 设置测试用的强密码
        let pwd = b"a_very_strong_password";
        // 生成真实钱包目录的临时路径
        let mut real_dir = env::temp_dir();
        real_dir.push(format!(
            "ark_wallet_real_{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        // 生成符号链接目录的临时路径
        let mut link_dir = env::temp_dir();
        link_dir.push(format!(
            "ark_wallet_link_{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        // 创建真实钱包目录
        fs::create_dir_all(&real_dir)?;
        // 创建一个指向真实钱包目录的符号链接目录
        std::os::unix::fs::symlink(&real_dir, &link_dir)?;
        // 构造符号链接目录下的钱包文件路径
        let target = link_dir.join("wallet.json");
        // 尝试在符号链接目录下保存钱包，应该被拒绝（返回错误）
        assert!(w.save_encrypted(&target, pwd).is_err());
        // 删除真实钱包目录，清理测试环境
        let _ = fs::remove_dir_all(&real_dir);
        // 删除符号链接目录，清理测试环境
        let _ = fs::remove_dir_all(&link_dir);
        Ok(())
    }

    #[test]
    fn test_magic_mismatch_rejected() -> anyhow::Result<()> {
        // 创建一个新的钱包对象
        let w = Wallet::new()?;
        // 设置测试用的强密码
        let pwd = b"a_very_strong_password";
        let path = test_temp_path("ark_wallet_magic_mismatch");
        // 用强密码加密并保存钱包到临时文件
        w.save_encrypted(&path, pwd)?;
        // 读取加密钱包文件内容并反序列化为 EncryptedWallet 结构体
        let mut enc: EncryptedWallet = serde_json::from_slice(&read_wallet_file_secure(&path)?)?;
        // 人为篡改 magic 字段，模拟魔术字串不匹配的情况
        enc.version = 2;
        enc.magic = Some("NotArkWallet".into());
        // 把被篡改的加密钱包重新写回文件
        fs::write(&path, serde_json::to_vec_pretty(&enc)?)?;
        // 尝试用密码解密被篡改的钱包，应该返回 magic 校验失败的错误
        let err = Wallet::load_encrypted(&path, pwd).unwrap_err();
        // 检查错误信息中包含 "magic"
        assert!(format!("{err}").to_lowercase().contains("magic"));
        // 删除临时文件，清理测试环境
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn test_unknown_kdf_rejected() -> anyhow::Result<()> {
        // 创建一个新的钱包对象
        let w = Wallet::new()?;
        // 设置测试用的强密码
        let pwd = b"a_very_strong_password";
        // 生成一个唯一的临时文件路径
        let path = test_temp_path("ark_wallet_unknown_kdf");
        // 用强密码加密并保存钱包到临时文件
        w.save_encrypted(&path, pwd)?;
        // 读取加密钱包文件内容并反序列化为 EncryptedWallet 结构体
        let mut enc: EncryptedWallet = serde_json::from_slice(&read_wallet_file_secure(&path)?)?;
        // 人为篡改 kdf 字段，模拟未知的 KDF 算法
        enc.kdf = "UNKNOWN-KDF".into();
        // 把被篡改的加密钱包重新写回文件
        fs::write(&path, serde_json::to_vec_pretty(&enc)?)?;
        // 尝试用密码解密被篡改的钱包，应该返回 "unsupported kdf" 错误
        let err = Wallet::load_encrypted(&path, pwd).unwrap_err();
        // 检查错误信息中包含 "unsupported kdf"
        assert!(format!("{err}").to_lowercase().contains("unsupported kdf"));
        // 删除临时文件，清理测试环境
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn test_truncated_nonce_or_salt_rejected() -> anyhow::Result<()> {
        // 创建一个新的钱包对象
        let w = Wallet::new()?;
        // 设置测试用的强密码
        let pwd = b"a_very_strong_password";
        // 生成一个唯一的临时文件路径
        let path = test_temp_path("ark_wallet_truncated");
        // 用强密码加密并保存钱包到临时文件
        w.save_encrypted(&path, pwd)?;
        // 读取加密钱包文件内容并反序列化为 EncryptedWallet 结构体
        let mut enc: EncryptedWallet = serde_json::from_slice(&read_wallet_file_secure(&path)?)?;
        // 人为截断 nonce 字段，模拟 nonce 长度不合法的情况
        enc.nonce_hex
            .truncate(enc.nonce_hex.len().saturating_sub(2));
        // 把被截断的加密钱包重新写回文件
        fs::write(&path, serde_json::to_vec_pretty(&enc)?)?;
        // 尝试用密码解密被截断 nonce 的钱包，应该返回 nonce 或长度相关的错误
        let err = Wallet::load_encrypted(&path, pwd).unwrap_err();
        let msg = format!("{err}").to_lowercase();
        // 检查错误信息中包含 "nonce" 或 "length"
        assert!(msg.contains("nonce") || msg.contains("length"));
        // 删除临时文件，清理测试环境
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn test_calibrate_pbkdf2_iterations() -> anyhow::Result<()> {
        // 目标耗时（毫秒），用于校准 PBKDF2 迭代次数
        let target_ms = 200u64;
        // 统计所有轮次的迭代次数总和
        let mut total_iters = 0u64;
        // 测试轮数
        const ROUNDS: usize = 4;
        // 循环多次，测试 PBKDF2 校准函数的稳定性和范围
        for _ in 0..ROUNDS {
            // 根据目标耗时自动校准 PBKDF2 迭代次数
            let iters = Wallet::calibrate_pbkdf2_iterations(target_ms);
            // 检查迭代次数是否在允许的最小/最大范围内
            assert!(
                (MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&iters),
                "iter count out of range: {iters}"
            );
            // 累加本轮的迭代次数
            total_iters += iters as u64;
        }
        // 计算平均迭代次数（可选，未使用）
        let _avg = total_iters / (ROUNDS as u64);
        Ok(())
    }

    #[cfg(feature = "hd")]
    #[test]
    fn test_mnemonic_generation_and_key_recovery() -> anyhow::Result<()> {
        // 导入生成助记词和通过助记词恢复私钥的函数
        use super::{generate_mnemonic, secret_key_from_mnemonic};

        // 生成一个新的助记词（12个英文单词）
        let phrase = generate_mnemonic()?;
        // 用户保存 phrase（实际应用中用户应妥善保存助记词）

        // 通过助记词恢复 secp256k1 私钥
        let sk = secret_key_from_mnemonic(&phrase)?;
        // 检查恢复出的私钥长度是否为32字节
        assert_eq!(sk.secret_bytes().len(), 32);

        Ok(())
    }
}

#[cfg(feature = "hd")]
// 导入 bip39 助记词库的 Mnemonic 和 Language 类型
use bip39::{Language, Mnemonic};

/// 生成新的助记词（12个英文单词）
#[cfg(feature = "hd")]
pub fn generate_mnemonic() -> anyhow::Result<String> {
    // 生成 128 位（16 字节）随机熵，对应 12 个助记词单词
    let mut entropy = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut entropy);
    // 用随机熵生成英文助记词
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
    // 返回助记词字符串
    Ok(mnemonic.to_string())
}

/// 通过助记词恢复 secp256k1 私钥（取种子前32字节）
#[cfg(feature = "hd")]
pub fn secret_key_from_mnemonic(mnemonic_phrase: &str) -> anyhow::Result<secp256k1::SecretKey> {
    // 解析英文助记词字符串，得到 Mnemonic 对象
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)?;
    // 通过助记词生成种子（BIP39 标准，默认无密码）
    let seed = mnemonic.to_seed_normalized("");
    let seed_bytes = &seed[..]; // 获取种子字节切片
                                // 用种子前 32 字节生成 secp256k1 私钥
    let secret_key = secp256k1::SecretKey::from_slice(&seed_bytes[0..32])?;
    // 返回私钥对象
    Ok(secret_key)
}

#[cfg(feature = "hd")]
impl Wallet {
    /// 通过助记词生成钱包
    pub fn from_mnemonic(phrase: &str) -> anyhow::Result<Self> {
        let sk = secret_key_from_mnemonic(phrase)?;
        Wallet::from_secret_key(sk)
    }
    /// 通过助记词和语言生成钱包，自动校验助记词合法性
    pub fn from_mnemonic_with_lang(phrase: &str, lang: Language) -> anyhow::Result<Self> {
        // 校验助记词合法性
        let mnemonic = Mnemonic::parse_in_normalized(lang, phrase)
            .map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
        let seed = mnemonic.to_seed_normalized("");
        let seed_bytes = &seed[..];
        let sk = secp256k1::SecretKey::from_slice(&seed_bytes[0..32])
            .map_err(|e| anyhow!("invalid secret key from mnemonic: {e}"))?;
        Wallet::from_secret_key(sk)
    }

    /// 生成新的助记词（可指定语言）
    pub fn generate_mnemonic_with_lang(lang: Language) -> anyhow::Result<String> {
        let mut entropy = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy_in(lang, &entropy)
            .map_err(|e| anyhow!("mnemonic generation failed: {e}"))?;
        Ok(mnemonic.to_string())
    }

    /// 通过助记词、语言和可选 passphrase 以及 BIP32/BIP44 路径生成钱包
    pub fn from_mnemonic_with_path(
        phrase: &str,
        lang: Language,
        passphrase: &str,
        derivation_path: &str,
    ) -> anyhow::Result<Self> {
        use bip32::{DerivationPath, XPrv}; // 精简导入，去掉 Mnemonic/Prefix

        // 校验助记词合法性（bip39）
        let mnemonic = Mnemonic::parse_in_normalized(lang, phrase)
            .map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
        // 生成 BIP39 种子（支持 passphrase）
        let seed = mnemonic.to_seed_normalized(passphrase);

        // 用种子创建主扩展私钥（bip32）
        let xprv = XPrv::new(seed).map_err(|e| anyhow!("bip32 xprv error: {e}"))?;
        // 解析派生路径
        let path = DerivationPath::from_str(derivation_path)
            .map_err(|e| anyhow!("invalid derivation path: {e}"))?;
        // 按路径逐级派生子扩展私钥（bip32 0.5）
        let mut cur = xprv;
        for c in path.into_iter() {
            cur = cur
                .derive_child(c)
                .map_err(|e| anyhow!("bip32 derive error: {e}"))?;
        }
        let child_xprv = cur;
        // 取子私钥 32 字节
        let sk_bytes = child_xprv.private_key().to_bytes();
        let sk = secp256k1::SecretKey::from_slice(&sk_bytes)
            .map_err(|e| anyhow!("invalid secret key from bip32: {e}"))?;
        Wallet::from_secret_key(sk)
    }
}
