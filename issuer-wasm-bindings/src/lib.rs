use wasm_bindgen::prelude::*;
use issuer::Issuer;
extern crate console_error_panic_hook;
use std::panic;

#[wasm_bindgen]
pub fn issue(private_key: String, field1: String, field2: String) -> String {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
    let iss = Issuer::from_privkey(&private_key);
    let sig = iss.issue(["12345678".to_string(), "23456789".to_string()]).unwrap();
    serde_json::to_string(&sig).unwrap()
}
