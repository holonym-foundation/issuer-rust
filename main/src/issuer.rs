use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use num_traits::Num;
use babyjubjub_rs::{POSEIDON, Fr, Point, PrivateKey, blh, Signature};
use rand::{Rng, random}; // 0.6.5
use serde::{Serialize, ser::SerializeSeq};
use ff::{Field, PrimeField, PrimeFieldRepr};
use time::Timespec;
use std::io::{self, Read, Write};
use bytes::BufMut;

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
    pubkey: Point,
    signature: Signature
}

pub struct HoloTimestamp {
    pub timestamp: Fr
}

impl Credentials {
    pub fn from_fields(address: Fr, custom_fields: [Fr; 2]) -> Result<Credentials, String> {
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        let secret_bytes = blh(&random_bytes);
        println!("secret bytes {:?} |||||||| qwerwqre ||||| {}", secret_bytes,  BigInt::from_bytes_le(Sign::Plus, &secret_bytes).to_string().as_str());

        let secret_fr = Fr::from_str(
            BigInt::from_bytes_le(Sign::Plus, &secret_bytes).to_string().as_str()
        ).unwrap();
        let creds = Credentials {
            address: address,
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
    }

    pub fn sign_credentials(&self, creds: Credentials) -> Result<SignedCredentials, String> {
        let leaf = creds.to_leaf().unwrap();
        // Convert Fr to BigInt. TODO: find more efficient way of converting the Fr to a BigInt
        // Convert to chars and remove 0x prefix
        let leaf_str = leaf.into_repr().to_string();
        let mut as_chars = leaf_str.chars();
        as_chars.next();
        as_chars.next();
        // Now, convert as_chars to BigInt
        let as_bigint = BigInt::from_str_radix(as_chars.as_str(), 16).unwrap();
        let signature = self.privkey.sign(as_bigint).unwrap();
        Ok(
            SignedCredentials {
                credentials: creds.serializable(),
                leaf: leaf.to_string(),
                pubkey: Point { x: self.pubkey_point.x, y: self.pubkey_point.y },
                signature: signature
            }
        )
    }

    // creates credentials from custom fields, and returns credentials + leaf + signature
    pub fn issue(&self, custom_fields: [String; 2]) -> Result<SignedCredentials, String> {
        let cf = [Fr::from_str(&custom_fields[0]).unwrap(), Fr::from_str(&custom_fields[1]).unwrap()];
        let c = Credentials::from_fields(self.address, cf).unwrap();
        self.sign_credentials(c)
    }
}

