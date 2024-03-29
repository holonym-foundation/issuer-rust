use num_bigint::{BigInt,Sign};
use num_traits::Num;
use babyjubjub_rs::{POSEIDON, Fr, Point, PrivateKey, blh, Signature, ToDecimalString};
use rand::{Rng}; 
use serde::{Serialize};
use ff::{Field, PrimeField};
use time::Timespec;
#[cfg(target_arch = "wasm32")]
use js_sys::Date;
#[cfg(not(target_arch = "wasm32"))]
extern crate time;

pub struct Issuer {
    pub privkey: PrivateKey,
    pub pubkey_point: Point,
    pub address: Fr //Address is poseidon([pubkey_point.x, pubkey_point.y])
}
pub struct Credentials {
    pub address: Fr,
    pub isusance_nullifier: Fr,
    pub custom_fields: [Fr; 2],
    pub iat: Fr, // Timestamp issued at, offset to 1900 instead of standard unix 1970
    pub scope: Fr // Usually zero
}
#[derive(Serialize)]
pub struct SerializableCredentials {
    pub address: String,
    pub isusance_nullifier: String,
    pub custom_fields: [String; 2],
    pub iat: String,
    pub scope: String,
    // /// The fields of credentials in the order that they have ben signed
    // pub order_of_preimage: [String; 6]

}

#[derive(Serialize)]
pub struct SerializablePoint {
    x: String,
    y: String
}
impl From<Point> for SerializablePoint {
    fn from(value: Point) -> Self { Self { x: value.x.to_dec_string(), y: value.y.to_dec_string() } }
}
#[derive(Serialize)]
pub struct SignedCredentials {
    credentials: SerializableCredentials,
    leaf: String,
    pubkey: SerializablePoint,
    signature_r8: SerializablePoint,
    signature_s: String
}

pub struct HoloTimestamp {
    pub timestamp: Fr
}

impl Credentials {
    pub fn from_fields(address: Fr, issuance_nullifier: String, custom_fields: [Fr; 2]) -> Result<Credentials, String> {
        let creds = Credentials {
            address: address,
            isusance_nullifier: Fr::from_str(&issuance_nullifier).unwrap(),
            custom_fields: custom_fields,
            iat : HoloTimestamp::cur_time().timestamp,
            scope: Fr::zero()
        };
        Ok(creds)
    }

    pub fn serializable(&self) -> SerializableCredentials {
        let address = self.address.to_dec_string();
        let isusance_nullifier = self.isusance_nullifier.to_dec_string();
        let custom_fields = [self.custom_fields[0].to_dec_string(), self.custom_fields[1].to_dec_string()];
        let iat = self.iat.to_dec_string();
        let scope = self.scope.to_dec_string();
        // let order_of_preimage = [address, isusance_nullifier, custom_fields[0], custom_fields[1], iat, scope].iter().map(|x|x.clone()).collect();

        return SerializableCredentials {
            address,
            isusance_nullifier,
            custom_fields,
            iat,
            scope,
            // order_of_preimage,
        }
       
    }

    // Returns poseidon([issuer address, random secret, custom_fields[0], custom_fields[1], current timestamp as days since 1900, scope (never/seldom used; set to 0 by default)])
    pub fn to_leaf(&self) -> Result<Fr, String> {
        POSEIDON.hash(vec![
            self.address,
            self.isusance_nullifier, 
            self.custom_fields[0], 
            self.custom_fields[1], 
            self.iat,
            self.scope
        ])
    }
}

impl HoloTimestamp {
    // pub fn from_timespec(t: Timespec) -> HoloTimestamp {
    //     let sec1900 = t.sec + 2208988800; // 2208988800000 is 70 year offset; Unix timestamps below 1970 are negative and we want to allow from 1900
    //     return HoloTimestamp { timestamp : Fr::from_str(&sec1900.to_string()).unwrap() }
    // }

    pub fn from_timestamp_sec(timestamp_in_seconds: i64) -> HoloTimestamp {
        let adjusted = timestamp_in_seconds + 2208988800; // 2208988800000 is 70 year offset; Unix timestamps below 1970 are negative and we want to allow from 1900
        HoloTimestamp { timestamp: Fr::from_str(&adjusted.to_string()).unwrap() }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn cur_time() -> HoloTimestamp {
        return Self::from_timestamp_sec(time::get_time().sec);
    }
    #[cfg(target_arch = "wasm32")]
    pub fn cur_time() -> HoloTimestamp {
        return Self::from_timestamp_sec((Date::now() as i64) / 1000);
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
                pubkey: self.pubkey_point.clone().into(),
                signature_r8: signature.r_b8.into(),
                signature_s: signature.s.to_string()
            } 
        )
    }
    
    // creates credentials from custom fields, and returns credentials + leaf + signature
    pub fn issue(&self, issuance_nullifier: String, custom_fields: [String; 2]) -> Result<SignedCredentials, String> {
        let cf = [Fr::from_str(&custom_fields[0]).unwrap(), Fr::from_str(&custom_fields[1]).unwrap()];
        let c = Credentials::from_fields(self.address, issuance_nullifier, cf).unwrap();
        self.sign_credentials(c)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn from_privkey() {
        let prv = "a2aa2ffcbf908eba5f613a481906c5d4ec29d31ee2df20ef176e6de3d5bbca4c";//.to_string();
        Issuer::from_privkey(prv);
        // , "123", "456", "789");
    }
}