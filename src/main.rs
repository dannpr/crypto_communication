use hex::ToHex;
use ring::{
    rand,
    signature::{self, KeyPair},
};
use std::env;

fn main() {
    let mut message = String::from("Hello world!");

    println!("Hello, world!");
    // List type string
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        message = args[1].clone();
    }

    println!("Message: {}", message);

    let msg = message.as_bytes();

    let randgen = rand::SystemRandom::new();
    // formating the the random number generator in bytes
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&randgen).unwrap();
    // create a Ed25519 key pair (pub/private) from the pkcs8 bytes
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    // retreiving the public key from the key pair
    let peer_public_key_bytes = key_pair.public_key().as_ref();

    println!("\nPkcs8: {:?}", pkcs8_bytes.as_ref().encode_hex::<String>());
    println!(
        "\nPublic key: {:?}",
        peer_public_key_bytes.encode_hex::<String>()
    );

    let sig = key_pair.sign(msg);

    let sig_bytes = sig.as_ref();

    println!("\nSignature: {:?}", sig_bytes.encode_hex::<String>());

    let peer_public_key =
        signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);

    let rtn = peer_public_key.verify(msg, sig.as_ref()).is_ok();

    if rtn == true {
        println!("\nMessage signature correct");
    } else {
        println!("\nMessage signature incorrect");
    }
}
