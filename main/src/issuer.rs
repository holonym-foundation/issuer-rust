use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use babyjubjub_rs::{POSEIDON, Fr, Point, PrivateKey};

pub struct Issuer {
    pub privkey: PrivateKey,
    pub pubkey_point: Point,
    pub address: Fr //Address is poseidon([pubkey_point.x, pubkey_point.y])
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
            pubkey_point: Point { x: pk.x, y: pk.y},
            address: POSEIDON.hash(vec![pk.x, pk.y]).unwrap()
        };
        // let sig = sk.sign(69.to_bigint().unwrap()).unwrap();
        // println!("secret key is {:?} and public key is {:?}", sk.scalar_key(), a);
        // println!("Signature is R8 : {:?} , S : {:?}", sig.r_b8, sig.s);
    }

    // Returns poseidon([issuer address, random secret, custom_fields[0], custom_fields[1], current timestamp as days since 1900, scope (never/seldom used; set to 0 by default)])
    pub fn create_leaf(custom_fields: &[Fr; 2]) {
        // POSEIDON.hash(vec![pk.x, pk.y]).unwrap()
    }
}

