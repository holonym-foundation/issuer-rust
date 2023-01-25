use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use babyjubjub_rs::{POSEIDON, Fr, Point, PrivateKey};
use ff::PrimeField;
use time::Timespec;
extern crate time;
pub struct Issuer {
    pub privkey: PrivateKey,
    pub pubkey_point: Point,
    pub address: Fr //Address is poseidon([pubkey_point.x, pubkey_point.y])
}

pub struct HoloTimestamp {
    timestamp: Fr
}

impl HoloTimestamp {
    pub fn from_timespec(t: Timespec) -> HoloTimestamp {
        let sec1900 = t.sec - 2208988800; // 2208988800000 is 70 year offset; Unix timestamps below 1970 are negative and we want to allow from 1900
        // return Err(String::from("Error parsing time::Timespec object"));
        // Ok(HoloTimestamp { timestamp : Fr::from(sec1900) });
        return HoloTimestamp { timestamp : Fr::from_str(&sec1900.to_string()).unwrap() }
    }
}

pub struct Leaf {
    pub address: Fr,
    pub secret: Fr,
    pub custom_fields: [Fr; 2],
    pub iat: Fr, // Timestamp issued at, offset to 1900 instead of standard unix 1970

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
    pub fn create_leaf(&self, custom_fields: &[Fr; 2]) -> Fr {
        POSEIDON.hash(vec![self.address]).unwrap()
    }
}

