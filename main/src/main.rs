
use std::env;
mod issuer;
fn main() {
    // private key is 32-byte hex
    // let iss = issuer::Issuer::from_privkey("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let p = match env::var("HOLONYM_ISSUER_PRIVKEY") {
        Ok(privkey) => privkey,
        Err(error) => {
            panic!("HOLONYM_ISSUER_PRIVKEY does not exist. It should be a 32-byte hex string such as 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef but random")
        }
    };
    let iss = issuer::Issuer::from_privkey(&p);
    print!("issuer: {:?} ", iss.address);
}
