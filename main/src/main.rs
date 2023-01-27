
use clap::{Arg, App};
use std::env;
mod issuer;
pub type Issuer = issuer::Issuer;
pub type HoloTimestamp = issuer::HoloTimestamp;

fn main() {
    // private key is 32-byte hex
    // let iss = issuer::Issuer::from_privkey("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let p = match env::var("HOLONYM_ISSUER_PRIVKEY") {
        Ok(privkey) => privkey,
        Err(error) => {
            panic!("HOLONYM_ISSUER_PRIVKEY does not exist. It should be a 32-byte hex string such as 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef but random")
        }
    };
    
    // Set up command line arguments using clap:
    let matches = App::new("Holonym Issuer")
        .version("0.0.0")
        .author("Nanak Nihal Khalsa <nanak@holonym.id>")
        .about("Issues a Holonym credential")
        .arg(Arg::with_name("Field 1")
            .short("1")
            .long("field1")
            .takes_value(true)
            .help("A custom field you can put in the credentials as an issuer. Can be a field element representing the user's phone number, name, or any other attribute. Can also be a hash of many other values if you'd like to fit more than one")
        )
        .arg(Arg::with_name("Field 2")
            .short("2")
            .long("field2")
            .takes_value(true)
            .help("A custom field you can put in the credentials as an issuer. Can be a field element representing the user's phone number, name, or any other attribute. Can also be a hash of many other values if you'd like to fit more than one")
        )
        .get_matches();

    let field1 = matches.value_of("Field 1").unwrap();
    let field2 = matches.value_of("Field 2").unwrap();
    // let matches = App::new("My Test Program")
    //     .version("0.1.0")
    //     .author("Hackerman Jones <hckrmnjones@hack.gov>")
    //     .about("Teaches argument parsing")
    //     .arg(Arg::with_name("file")
    //              .short("f")
    //              .long("file")
    //              .takes_value(true)
    //              .help("A cool file"))
    //     .arg(Arg::with_name("num")
    //              .short("n")
    //              .long("number")
    //              .takes_value(true)
    //              .help("Five less than your favorite number"))
    //     .get_matches();

    let iss = Issuer::from_privkey(&p);
    let sig = iss.issue([field1.to_string(), field2.to_string()])
    .unwrap();
    println!("JSON {:?}", serde_json::to_string(&sig).unwrap());
    
}
