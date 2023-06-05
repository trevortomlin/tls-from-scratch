extern crate rand;
extern crate ed25519_dalek;

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;

use ed25519_dalek::PublicKey;
use rand::Rng;
use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use ed25519_dalek::Signature;

fn client_hello(hostname: &str, pubkey: PublicKey) -> Vec<u8> {

    let mut result = vec![];

    /*  
        Client Version
        03 03 - protocol version is "3,3" (also known as TLS 1.2)
    */
    let client_version = vec![0x03, 0x03];

    /*  
        Client Random
        32 bytes of random data
    */
    let client_random = &rand::thread_rng().gen::<[u8; 32]>();

    /*  
        Session ID
        0x20 - length of session ID
        32 bytes of fake session ID 
    */
   let session_id = vec![
                                0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 
                                0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 
                                0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 
                                0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 
                                0xfb, 0xfc, 0xfd, 0xfe, 0xff
                            ];

    /*
        Cipher Suites
        00 02 - length of cipher suites list
        00 13 - cipher suite TLS_AES_256_GCM_SHA384
    */
    let cipher_suites = vec![0x00, 0x02, 0x00, 0x13];

    /*
        Compression Methods
        01 - length of compression methods list
        00 - compression method "null"
    */
    let compression_methods = vec![0x01, 0x00];

    /*
        Extension: server_name
        00 00 - extension type "server_name"
        00 0b - length of extension data
        00 09 - length of server name list
        00 - name type "host_name"
        00 06 - length of host name
        00 04 - length of host name
        68 6f 73 74 - "host"
    */
    let host_name_bytes = hostname.as_bytes();
    let host_name_length = (host_name_bytes.len() as u16).to_be_bytes();
    
    let list_entry_type = 0x00_u8.to_be_bytes();
    
    let entry_length = (list_entry_type.len() as u16 + host_name_length.len() as u16 + host_name_bytes.len() as u16).to_be_bytes();
    
    let extension_length = (list_entry_type.len() as u16 + entry_length.len() as u16 + host_name_length.len() as u16 + host_name_bytes.len() as u16).to_be_bytes();
    
    let mut server_name = vec![];
    server_name.extend_from_slice(&[0, 0]);
    server_name.extend_from_slice(&extension_length);
    server_name.extend_from_slice(&entry_length);
    server_name.extend_from_slice(&[0]);
    server_name.extend_from_slice(&host_name_length);
    server_name.extend_from_slice(&host_name_bytes);

    /*
        Extension - EC Point Formats
        00 0b - assigned value for extension "ec point formats"
        00 04 - 4 bytes of format types follow
        03 - 3 bytes of format types follow
        00 - assigned value for format "uncompressed"
        01 - assigned value for format "ansiX962_compressed_prime"
        02 - assigned value for format "ansiX962_compressed_char2" 
    */
    let ec_point_formats = vec![0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02];

    /*
        Extension - Supported Groups
        00 0a - assigned value for extension "supported groups"
        00 16 - 0x16 (22) bytes of "supported group" extension data follows
        00 14 - 0x14 (20) bytes of data are in the curves list
        00 1d - assigned value for the curve "x25519"
        00 17 - assigned value for the curve "secp256r1"
        00 1e - assigned value for the curve "x448"
        00 19 - assigned value for the curve "secp521r1"
        00 18 - assigned value for the curve "secp384r1"
        01 00 - assigned value for the curve "ffdhe2048"
        01 01 - assigned value for the curve "ffdhe3072"
        01 02 - assigned value for the curve "ffdhe4096"
        01 03 - assigned value for the curve "ffdhe6144"
        01 04 - assigned value for the curve "ffdhe8192" 
    */
    let mut supported_groups = vec![];
    supported_groups.extend_from_slice(&[0x00, 0x0a]);

    let groups = vec![0x00, 0x1d];

    let curves_list_length = (groups.len() as u16).to_be_bytes();
    let extension_length = (curves_list_length.len() as u16 + groups.len() as u16).to_be_bytes();

    supported_groups.extend_from_slice(&extension_length);
    supported_groups.extend_from_slice(&curves_list_length);
    supported_groups.extend_from_slice(&groups);

    /*
        Extension - Session Ticket
        00 23 - assigned value for extension "Session Ticket"
        00 00 - 0 bytes of "Session Ticket" extension data follows 
    */
    let session_ticket = vec![0x00, 0x23, 0x00, 0x00];

    /*
        Extension - Encrypt-Then-MAC
        00 16 - assigned value for extension "Encrypt Then MAC"
        00 00 - 0 bytes of "Encrypt Then MAC" extension data follows 
    */
    let encrypt_then_mac = vec![0x00, 0x16, 0x00, 0x00];

    /*
        Extension - Extended Master Secret
        00 17 - assigned value for extension "Extended Master Secret"
        00 00 - 0 bytes of "Extended Master Secret" extension data follows 
    */
    let extended_master_secret = vec![0x00, 0x17, 0x00, 0x00];

    /*
        Extension - Signature Algorithms
        00 0d - assigned value for extension "Signature Algorithms"
        00 1e - 0x1E (30) bytes of "Signature Algorithms" extension data follows
        00 1c - 0x1C (28) bytes of data are in the following list of algorithms
        04 03 - assigned value for ECDSA-SECP256r1-SHA256
        05 03 - assigned value for ECDSA-SECP384r1-SHA384
        06 03 - assigned value for ECDSA-SECP521r1-SHA512
        08 07 - assigned value for ED25519
        08 08 - assigned value for ED448
        08 09 - assigned value for RSA-PSS-PSS-SHA256
        08 0a - assigned value for RSA-PSS-PSS-SHA384
        08 0b - assigned value for RSA-PSS-PSS-SHA512
        08 04 - assigned value for RSA-PSS-RSAE-SHA256
        08 05 - assigned value for RSA-PSS-RSAE-SHA384
        08 06 - assigned value for RSA-PSS-RSAE-SHA512
        04 01 - assigned value for RSA-PKCS1-SHA256
        05 01 - assigned value for RSA-PKCS1-SHA384
        06 01 - assigned value for RSA-PKCS1-SHA512 
    */
    let mut signature_algorithms = vec![];
    signature_algorithms.extend_from_slice(&[0x00, 0x0d]);

    let algorithms = vec![0x04, 0x03];

    let algorithms_lengths = (algorithms.len() as u16).to_be_bytes();
    let algorithm_extension_length = (algorithms_lengths.len() as u16 + algorithms.len() as u16).to_be_bytes();

    signature_algorithms.extend_from_slice(&algorithm_extension_length);
    signature_algorithms.extend_from_slice(&algorithms_lengths);
    signature_algorithms.extend_from_slice(&algorithms);

    /*
        Extension - Supported Versions
        00 2b - assigned value for extension "Supported Versions"
        00 03 - 3 bytes of "Supported Versions" extension data follows
        02 - 2 bytes of TLS versions follow
        03 04 - assigned value for TLS 1.3 
    */
    let supported_versions = vec![0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];

    /*
        Extension - PSK Key Exchange Modes
        00 2d - assigned value for extension "PSK Key Exchange Modes"
        00 02 - 2 bytes of "PSK Key Exchange Modes" extension data follows
        01 - 1 bytes of exchange modes follow
        01 - assigned value for "PSK with (EC)DHE key establishment" 
    */
    let psk_key_exchange_modes = vec![0x00, 0x2d, 0x00, 0x02, 0x01, 0x01];

    /*
        Extension - Key Share
        00 33 - assigned value for extension "Key Share"
        00 26 - 0x26 (38) bytes of "Key Share" extension data follows
        00 24 - 0x24 (36) bytes of key share data follows
        00 1d - assigned value for x25519 (key exchange via curve25519)
        00 20 - 0x20 (32) bytes of public key follows
        35 80 ... 62 54 - public key from the step "Client Key Exchange Generation" 
    */
    let mut key_share = vec![];
    key_share.extend_from_slice(&[0x00, 0x33]);
    key_share.extend_from_slice(&[0x00, 0x26]);
    key_share.extend_from_slice(&[0x00, 0x24]);
    key_share.extend_from_slice(&[0x00, 0x1d]);
    key_share.extend_from_slice(&[0x00, 0x20]);
    key_share.extend_from_slice(&pubkey.to_bytes());

    /*  
        Record Header
        16 - type is 0x16 (handshake record)
        03 01 - protocol version is "3,1" (also known as TLS 1.0)
        00 f8 - 0xF8 (248) bytes of handshake message follows 
    */
    result.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0xf8]);

    /*  
        Handshake Header
        01 - handshake message type 0x01 (client hello)
        00 00 f4 - 0xF4 (244) bytes of client hello data follows
    */
    result.extend_from_slice(&[0x01, 0x00, 0x00, 0xf4]);

    /*
        Extensions Length
        00 a3 - length of extensions list
    */
    let mut extensions_length = 0u16;
    extensions_length += session_ticket.len() as u16;
    extensions_length += encrypt_then_mac.len() as u16;
    extensions_length += extended_master_secret.len() as u16;
    extensions_length += signature_algorithms.len() as u16;
    extensions_length += supported_versions.len() as u16;
    extensions_length += psk_key_exchange_modes.len() as u16;
    extensions_length += key_share.len() as u16;

    // print extensions length
    println!("Extensions length: {}", extensions_length);

    let extensions_length = extensions_length.to_be_bytes();

    result.extend_from_slice(&extensions_length);
    result.extend_from_slice(&session_ticket);
    result.extend_from_slice(&encrypt_then_mac);
    result.extend_from_slice(&extended_master_secret);
    result.extend_from_slice(&signature_algorithms);
    result.extend_from_slice(&supported_versions);
    result.extend_from_slice(&psk_key_exchange_modes);
    result.extend_from_slice(&key_share); 

    result
}

fn client_key_exchange_generation() -> Keypair {
    let mut csprng = OsRng{};
    Keypair::generate(&mut csprng)
}

pub fn connect(host: &str) {
    
    let client_key = client_key_exchange_generation();
    let client_hello = client_hello(host, client_key.public);

    // Connect to host name at port 443 using tcp
    //let mut stream = TcpStream::connect(format!("{}:443", host)).unwrap();

    // if let Ok(mut stream) =TcpStream::connect(format!("{}:443", host)) {
    //     println!("Connected to the server!");
    //     stream.write(&client_hello).unwrap();
    //     let mut server_hello = [0; 1024];
    //     stream.read(&mut server_hello);
    //     println!("{:?}", server_hello);

    // } else {
    //     println!("Couldn't connect to server...");
    // }

    // Send client hello
    // stream.write(&client_hello).unwrap();

    // // Read server hello
    // let mut server_hello = [0; 1024];
    // stream.read(&mut server_hello).unwrap();

    // // Print server hello
    // println!("{:?}", server_hello);


}