use babyjubjub_rs::PrivateKey;
fn main() {
    let sk = PrivateKey::import(
        hex::decode("0001020304050607080900010203040506070809000102030405060708090001")
            .unwrap(),
    )
    .unwrap();
    let a= sk.public();
    // println!("secret key is {:?}", s);
}
