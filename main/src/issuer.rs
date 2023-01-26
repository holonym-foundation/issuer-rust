use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use babyjubjub_rs::{POSEIDON, Fr, Point, PrivateKey, blh, Signature};
use rand::{Rng, random}; // 0.6.5
use serde::{Serialize, ser::SerializeSeq};
use ff::{Field, PrimeField};
use time::Timespec;
extern crate time;
pub struct Issuer {
    pub privkey: PrivateKey,
    pub pubkey_point: Point,
    pub address: Fr //Address is poseidon([pubkey_point.x, pubkey_point.y])
}
pub struct Credentials {
    pub address: Fr,
    pub secret: Fr,
    pub custom_fields: [Fr; 2],
    pub iat: Fr, // Timestamp issued at, offset to 1900 instead of standard unix 1970
    pub scope: Fr // Usually zero
}
#[derive(Serialize)]
pub struct SerializableCredentials {
    pub address: String,
    pub secret: String,
    pub custom_fields: [String; 2],
    pub iat: String,
    pub scope: String
}

#[derive(Serialize)]
pub struct SignedCredentials {
    credentials: SerializableCredentials,
    leaf: String,
    signature: Signature
}

pub struct HoloTimestamp {
    pub timestamp: Fr
}

impl Credentials {
    pub fn from_fields(&self, custom_fields: [Fr; 2]) -> Result<Credentials, String> {
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        let secret_bytes = blh(&random_bytes);
        let secret_fr = Fr::from_str(
            &hex::encode(secret_bytes)
        ).unwrap();
        let creds = Credentials {
            address: self.address,
            secret: secret_fr,
            custom_fields: custom_fields,
            iat : HoloTimestamp::cur_time().timestamp,
            scope: Fr::zero()
        };
        Ok(creds)
    }

    pub fn serializable(&self) -> SerializableCredentials {
        return SerializableCredentials {
            address : self.address.to_string(),
            secret : self.secret.to_string(),
            custom_fields : [self.custom_fields[0].to_string(), self.custom_fields[1].to_string()],
            iat : self.iat.to_string(),
            scope : self.scope.to_string(),
        }
       
    }

    // Returns poseidon([issuer address, random secret, custom_fields[0], custom_fields[1], current timestamp as days since 1900, scope (never/seldom used; set to 0 by default)])
    pub fn to_leaf(&self) -> Result<Fr, String> {
        POSEIDON.hash(vec![
            self.address,
            self.secret, 
            self.custom_fields[0], 
            self.custom_fields[1], 
            self.iat,
            self.scope
        ])
    }
}

impl HoloTimestamp {
    pub fn from_timespec(t: Timespec) -> HoloTimestamp {
        let sec1900 = t.sec + 2208988800; // 2208988800000 is 70 year offset; Unix timestamps below 1970 are negative and we want to allow from 1900
        // return Err(String::from("Error parsing time::Timespec object"));
        // Ok(HoloTimestamp { timestamp : Fr::from(sec1900) });
        // println!("sec1900 {} {}", sec1900, t.sec);
        return HoloTimestamp { timestamp : Fr::from_str(&sec1900.to_string()).unwrap() }
    }
    pub fn cur_time() -> HoloTimestamp {
        return Self::from_timespec(time::get_time());
    }
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

    pub fn sign_credentials(&self, creds: Credentials) -> Result<SignedCredentials, String> {
        let leaf = creds.to_leaf().unwrap();
        let as_bigint = leaf.to_string().parse::<BigInt>().unwrap();
        println!("as_bigint {}", as_bigint);
        let signature = self.privkey.sign(as_bigint).unwrap();
        Ok(
            SignedCredentials {
                credentials: creds.serializable(),
                leaf: leaf.to_string(),
                signature: signature
            }
        )
    }
}

