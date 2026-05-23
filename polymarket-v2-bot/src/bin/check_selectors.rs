use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::sol_types::{SolStruct, SolValue};
use alloy_sol_types::sol;
use std::str::FromStr;

sol! {
    struct SafeTx {
        address to; uint256 value; bytes data; uint8 operation;
        uint256 safeTxGas; uint256 baseGas; uint256 gasPrice;
        address gasToken; address refundReceiver; uint256 nonce;
    }
}

fn main() -> anyhow::Result<()> {
    let safe_addr = Address::from_str("0x179e37a8e42b012c99587e78b15ba9c44e1e2182")?;
    let onchain_sep = "e4d523881c1fb0c6a4d4bd0d7418008852b60045c552face2bd8c36b26c887bd";

    let domain_typehash = keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    println!("Domain typehash: 0x{}", hex::encode(domain_typehash));

    // --- Try all methods ---
    // Method 1: hashed strings (keccak256 of "Gnosis Safe", "1.3.0")
    let name_hash = keccak256(b"Gnosis Safe");
    let version_hash = keccak256(b"1.3.0");
    let m1 = keccak256(&(
        B256::from(domain_typehash), B256::from(name_hash), B256::from(version_hash),
        U256::from(137), safe_addr,
    ).abi_encode_params());
    println!("M1 hashed strings:    0x{}", hex::encode(m1));

    // Method 2: raw strings in abi.encode
    let m2 = keccak256(&(
        B256::from(domain_typehash),
        "Gnosis Safe",
        "1.3.0",
        U256::from(137),
        safe_addr,
    ).abi_encode_params());
    println!("M2 raw strings:       0x{}", hex::encode(m2));

    // Method 3: 5-field with salt=0, raw strings
    let m3 = keccak256(&(
        B256::from(domain_typehash),
        "Gnosis Safe",
        "1.3.0",
        U256::from(137),
        safe_addr,
        B256::ZERO,
    ).abi_encode_params());
    println!("M3 raw+salt:          0x{}", hex::encode(m3));

    // Method 4: 5-field typehash with hashed values and salt=0
    let type5 = keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    let m4 = keccak256(&(
        B256::from(type5), B256::from(name_hash), B256::from(version_hash),
        U256::from(137), safe_addr, B256::ZERO,
    ).abi_encode_params());
    println!("M4 5-field hashed:    0x{}", hex::encode(m4));

    // Method 5: with space after commas
    let type_sp = keccak256(b"EIP712Domain(string name, string version, uint256 chainId, address verifyingContract)");
    let m5 = keccak256(&(
        B256::from(type_sp), B256::from(name_hash), B256::from(version_hash),
        U256::from(137), safe_addr,
    ).abi_encode_params());
    println!("M5 spaced commas:     0x{}", hex::encode(m5));

    // Method 6: Try "Safe" instead of "Gnosis Safe"
    let name2 = keccak256(b"Safe");
    let m6 = keccak256(&(
        B256::from(domain_typehash), B256::from(name2), B256::from(version_hash),
        U256::from(137), safe_addr,
    ).abi_encode_params());
    println!("M6 name=Safe:         0x{}", hex::encode(m6));

    // Method 7: empty name
    let name0 = keccak256(b"");
    let m7 = keccak256(&(
        B256::from(domain_typehash), B256::from(name0), B256::from(version_hash),
        U256::from(137), safe_addr,
    ).abi_encode_params());
    println!("M7 empty name:        0x{}", hex::encode(m7));

    // Method 8: version = "1.0.0"
    let v100 = keccak256(b"1.0.0");
    let m8 = keccak256(&(
        B256::from(domain_typehash), B256::from(name_hash), B256::from(v100),
        U256::from(137), safe_addr,
    ).abi_encode_params());
    println!("M8 version=1.0.0:     0x{}", hex::encode(m8));

    // Method 9: version = ""
    let v0 = keccak256(b"");
    let m9 = keccak256(&(
        B256::from(domain_typehash), B256::from(name_hash), B256::from(v0),
        U256::from(137), safe_addr,
    ).abi_encode_params());
    println!("M9 empty version:     0x{}", hex::encode(m9));

    // Method 10: What if they use the 4-field typehash with raw VERSION string
    // i.e. keccak256(abi.encode(typehash, keccak256(name), VERSION, chainId, addr))
    for desc in ["1.3.0", "1.0.0", ""] {
        let vv = keccak256(desc.as_bytes());
        let s = keccak256(&(
            B256::from(domain_typehash), B256::from(name_hash), B256::from(vv),
            U256::from(137), safe_addr,
        ).abi_encode_params());
        if hex::encode(s) == onchain_sep {
            println!("MATCH with version '{}' (hashed)", desc);
        }
    }

    // Method 11: Try without hashing version at all (just raw string)
    for ver in &["1.3.0", "1.0.0", ""] {
        let s = keccak256(&(
            B256::from(domain_typehash), B256::from(name_hash),
            *ver, U256::from(137), safe_addr,
        ).abi_encode_params());
        if hex::encode(s) == onchain_sep {
            println!("MATCH with version '{}' (raw string)", ver);
        }
    }

    // Method 12: try different RPC provider
    println!("\nOn-chain separator:  0x{onchain_sep}");
    println!("Match if any printed above");

    Ok(())
}
