use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use babyjubjub_rs::{POSEIDON, Fr, Point, PrivateKey};

pub struct Issuer {
    pub privkey: PrivateKey,
    // pub pubkey_point: Point,
    // pub address: Fr //Address is poseidon([pubkey_point.x, pubkey_point.y])
}
impl Issuer {
    pub fn from_privkey(privkey: &str) -> Issuer{
        let prv = PrivateKey::import(
            hex::decode(privkey)
            .unwrap(),
        ).unwrap();

        let pk = prv.public();

        return Issuer {
            privkey: prv,
            // pubkey_point: pk,
            // address: POSEIDON.hash(vec![pk.x, pk.y]).unwrap()
        };
        // let sig = sk.sign(69.to_bigint().unwrap()).unwrap();
        // println!("secret key is {:?} and public key is {:?}", sk.scalar_key(), a);
        // println!("Signature is R8 : {:?} , S : {:?}", sig.r_b8, sig.s);
    }
}

