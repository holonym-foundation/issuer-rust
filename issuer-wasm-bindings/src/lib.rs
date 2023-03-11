use num_bigint::BigInt;
use wasm_bindgen::prelude::*;
use std::str::FromStr;
use issuer::Issuer;
extern crate console_error_panic_hook;
use std::panic;
use babyjubjub_rs::{PrivateKey, Point};

#[wasm_bindgen]
pub fn issue(private_key: String, field1: String, field2: String) -> String {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
    let iss = Issuer::from_privkey(&private_key);
    let sig = iss.issue([field1, field2]).unwrap();
    serde_json::to_string(&sig).unwrap()
}

#[wasm_bindgen]
pub fn sign(private_key: String, msg: String) -> String {
    let privkey = PrivateKey::import(
        hex::decode(private_key)
        .unwrap(),
    ).unwrap();
    let sig = privkey.sign(
        BigInt::from_str(&msg).unwrap()
    ).unwrap();
    serde_json::to_string(&sig).unwrap()
}

#[wasm_bindgen]
pub fn get_pubkey(private_key: String) -> String {
    let privkey = PrivateKey::import(
        hex::decode(private_key)
        .unwrap(),
    ).unwrap();
    let pubkey: Point = privkey.public();
    serde_json::to_string(&pubkey).unwrap()
}

#[wasm_bindgen]
pub fn get_pubkey_times_8(private_key: String) -> String {
    let privkey = PrivateKey::import(
        hex::decode(private_key)
        .unwrap(),
    ).unwrap();
    let pubkey: Point = privkey.public();
    serde_json::to_string(&pubkey.mul_scalar(&BigInt::from(8))).unwrap()
}
