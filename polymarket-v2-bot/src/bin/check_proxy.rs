use alloy::primitives::{keccak256, Address};
fn main() {
    let eoa: Address = "0x2200709f4eeee905a9f463afc92e215630bc6b62".parse().unwrap();
    let factory: Address = "0xaB45c5A4B0c941a2F231C04C3f49182e1A254052".parse().unwrap();
    let init_code_hash = hex::decode("d21df8dc65880a8606f09fe0ce3df9b8869287ab0b058be05aa9e8af6330a00b").unwrap();
    let salt = keccak256(eoa.as_slice());
    let mut input = Vec::new();
    input.push(0xff);
    input.extend_from_slice(factory.as_slice());
    input.extend_from_slice(salt.as_slice());
    input.extend_from_slice(&init_code_hash);
    let hash = keccak256(input);
    let proxy_addr = Address::from_slice(&hash[12..]);
    println!("Derived proxy:   {proxy_addr:#x}");
    println!("Config proxy:    0x30f6fbe55c1a45bd9fa7cc9823649bf6cc3a2e48");
    println!("Match: {}", proxy_addr == "0x30f6fbe55c1a45bd9fa7cc9823649bf6cc3a2e48".parse::<Address>().unwrap());
}
