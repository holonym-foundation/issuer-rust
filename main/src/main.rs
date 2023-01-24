use babyjubjub_rs::PrivateKey;
use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
fn main() {
    let sk = PrivateKey::import(
        hex::decode("0001020304050607080900010203040506070809000102030405060708090001")
            .unwrap(),
    )
    .unwrap();
    let a= sk.public();
    let sig = sk.sign(69.to_bigint().unwrap()).unwrap();
    println!("secret key is {:?} and public key is {:?}", sk.scalar_key(), a);
    println!("Signature is R8 : {:?} , S : {:?}", sig.r_b8, sig.s);

}
