use bs58::decode;
use sha2::{Digest, Sha256};

fn base58check_decode(addr: &str) -> Result<Vec<u8>, String> {
    let data = decode(addr).into_vec().map_err(|e| e.to_string())?;
    if data.len() < 5 {
        return Err("too short".into());
    }
    let (payload, checksum) = data.split_at(data.len() - 4);
    let h1 = Sha256::digest(payload);
    let h2 = Sha256::digest(h1);
    if &h2[..4] != checksum {
        return Err("checksum mismatch".into());
    }
    Ok(payload.to_vec())
}

#[test]
fn base58check_detects_checksum_error() {
    let addr_ok = "1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj";
    // 有效地址应通过
    base58check_decode(addr_ok).expect("valid Base58Check");

    // 篡改一位，保持仍是 Base58 字符
    let mut bytes = addr_ok.as_bytes().to_vec();
    for b in &mut bytes {
        if *b != b'1' {
            *b = b'1';
            break;
        }
    }
    let tampered = String::from_utf8(bytes).unwrap();

    // 篡改后应因校验和不一致而失败
    let res = base58check_decode(&tampered);
    res.expect_err("should fail checksum");
}
