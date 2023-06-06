pub mod client_hello;
pub mod server_hello;

extern crate rand;

use crate::crypto;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::process::exit;

// https://techcommunity.microsoft.com/t5/iis-support-blog/ssl-tls-alert-protocol-and-the-alert-codes/ba-p/377132
fn alert(alert: u8) {
    match alert {
        0 => println!("Close notify"),
        10 => println!("Unexpected message"),
        20 => println!("Bad record MAC"),
        21 => println!("Decryption failed"),
        22 => println!("Record overflow"),
        30 => println!("Decompression failure"),
        40 => println!("Handshake failure"),
        41 => println!("No certificate"),
        42 => println!("Bad certificate"),
        43 => println!("Unsupported certificate"),
        44 => println!("Certificate revoked"),
        45 => println!("Certificate expired"),
        46 => println!("Certificate unknown"),
        47 => println!("Illegal parameter"),
        48 => println!("Unknown CA"),
        49 => println!("Access denied"),
        50 => println!("Decode error"),
        51 => println!("Decrypt error"),
        60 => println!("Export restriction"),
        70 => println!("Protocol version"),
        71 => println!("Insufficient security"),
        80 => println!("Internal error"),
        90 => println!("User canceled"),
        100 => println!("No renegotiation"),
        _ => println!("Unknown error code")
    }
}

pub fn connect(host: &str) {
    
    let client_key = crypto::client_key_exchange_generation();
    let client_hello = client_hello::client_hello(host, client_key.pubkey);

    if let Ok(mut stream) = TcpStream::connect(format!("{}:443", host)) {
        println!("Connected to the server!");
        stream.write(&client_hello).unwrap();
        let mut server_hello = [0; 16384];
        
        stream.read(&mut server_hello);

        match server_hello[0] {
            0x16 => {
                //println!("{:x?}", server_hello);
                let server_pubkey = server_hello::parse_pubkey(&server_hello);
                //println!("{:x?}", server_pubkey);
                let shared_secret = crypto::shared_secret(server_pubkey, client_key.privkey);
                //println!("{:x?}", shared_secret.as_bytes());
            },
            0x15 => {
                println!("Server alert");
                alert(server_hello[6]);
                exit(1);

            },
            _ => {
                println!("Unknown message");
                exit(1);
            }
        }

    } else {
        println!("Couldn't connect to server...");
    }
    
}