use x25519_dalek::PublicKey;
use rand::Rng;

fn record_header(total_length: u16) -> Vec<u8> {
    /*  
        Record Header
        16 - type is 0x16 (handshake record)
        03 01 - protocol version is "3,1" (also known as TLS 1.0)
        00 f8 - 0xF8 (248) bytes of handshake message follows 
    */
    let mut record_header = vec![0x16, 0x03, 0x01];
    record_header.extend(total_length.to_be_bytes().iter());

    record_header
}

fn handshake_header(handshake_length: u16) -> Vec<u8> {
    /*
        Handshake Header
        01 - handshake message type 0x01 (client hello)
        00 00 f4 - 0xF4 (244) bytes of client hello data follows 
    */
    
    let mut handshake_header = vec![0x01, 0x00];
    handshake_header.extend(handshake_length.to_be_bytes().iter());
    
    handshake_header
}

fn client_version() -> Vec<u8> {
    /*  
        Client Version
        03 03 - protocol version is "3,3" (also known as TLS 1.2)
    */
    vec![0x03, 0x03]
}

fn client_random() -> Vec<u8> {
    /*  
        Client Random
        32 bytes of random data
    */
    rand::thread_rng().gen::<[u8; 32]>().to_vec()
}

fn session_id() -> Vec<u8> {
    /*  
        Session ID
        20 - 0x20 (32) bytes of session ID follow
        e0 e1 ... fe ff - fake session ID 
    */
    vec![
            0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 
            0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 
            0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 
            0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 
            0xfb, 0xfc, 0xfd, 0xfe, 0xff
        ]
    
}

fn cipher_suites() -> Vec<u8> {
    /*
        Cipher Suites    
        00 08 - 8 bytes of cipher suite data
        13 02 - assigned value for TLS_AES_256_GCM_SHA384
        13 03 - assigned value for TLS_CHACHA20_POLY1305_SHA256
        13 01 - assigned value for TLS_AES_128_GCM_SHA256
        00 ff - assigned value for TLS_EMPTY_RENEGOTIATION_INFO_SCSV 
    */
    vec![0x00, 0x02, 0x13, 0x02]
}

fn compression_methods() -> Vec<u8> {
    /*
        Compression Methods
        01 - length of compression methods list
        00 - compression method "null"
    */
    vec![0x01, 0x00]
}

fn extension_length(extensions: &Vec<Vec<u8>>) -> u16 {
    extensions.iter().fold(0, |acc, b| acc + b.len()) as u16
}

fn extension_server_name(hostname: &str) -> Vec<u8> {
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

    server_name

}

fn extension_ec_point_formats() -> Vec<u8> {
    /*
        Extension - EC Point Formats
        00 0b - assigned value for extension "ec point formats"
        00 04 - 4 bytes of format types follow
        03 - 3 bytes of format types follow
        00 - assigned value for format "uncompressed"
        01 - assigned value for format "ansiX962_compressed_prime"
        02 - assigned value for format "ansiX962_compressed_char2" 
    */
    vec![0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02]

}

fn extension_supported_groups() -> Vec<u8> {
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

    supported_groups

}

fn extension_session_ticket() -> Vec<u8> {
    /*
        Extension - Session Ticket
        00 23 - assigned value for extension "Session Ticket"
        00 00 - 0 bytes of "Session Ticket" extension data follows 
    */
   vec![0x00, 0x23, 0x00, 0x00]
}
fn extension_encrypt_then_mac() -> Vec<u8> {
    /*
        Extension - Encrypt-Then-MAC
        00 16 - assigned value for extension "Encrypt Then MAC"
        00 00 - 0 bytes of "Encrypt Then MAC" extension data follows 
    */
    vec![0x00, 0x16, 0x00, 0x00]
}
fn extension_extended_master_secret() -> Vec<u8> {
    /*
        Extension - Extended Master Secret
        00 17 - assigned value for extension "Extended Master Secret"
        00 00 - 0 bytes of "Extended Master Secret" extension data follows 
    */
    vec![0x00, 0x17, 0x00, 0x00]
}

fn extension_signature_algorithms() -> Vec<u8> {
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

    signature_algorithms

}

fn extension_supported_versions() -> Vec<u8> {
    /*
        Extension - Supported Versions
        00 2b - assigned value for extension "Supported Versions"
        00 03 - 3 bytes of "Supported Versions" extension data follows
        02 - 2 bytes of TLS versions follow
        03 04 - assigned value for TLS 1.3 
    */
    vec![0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]

}

fn extension_psk_key_exchange_modes() -> Vec<u8> {
    /*
        Extension - PSK Key Exchange Modes
        00 2d - assigned value for extension "PSK Key Exchange Modes"
        00 02 - 2 bytes of "PSK Key Exchange Modes" extension data follows
        01 - 1 bytes of exchange modes follow
        01 - assigned value for "PSK with (EC)DHE key establishment" 
    */
    vec![0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]

}

fn extension_key_share(pubkey: PublicKey) -> Vec<u8> {
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

    key_share

}

pub fn client_hello(hostname: &str, pubkey: PublicKey) -> Vec<u8> {
    let mut result = vec![];
    
    let data = vec![
        client_version(),
        client_random(),
        session_id(),
        cipher_suites(),
        compression_methods(),
    ];

    let extensions = vec![
        extension_server_name(hostname),
        extension_ec_point_formats(),
        extension_supported_groups(),
        extension_session_ticket(),
        extension_encrypt_then_mac(),
        extension_extended_master_secret(),
        extension_signature_algorithms(),
        extension_supported_versions(),
        extension_psk_key_exchange_modes(),
        extension_key_share(pubkey),
    ];

    /*
        Extensions Length
        00 a3 - length of extensions list
    */
    let extensions_length = extension_length(&extensions);
    let extensions_length_bytes = extensions_length.to_be_bytes();

    let handshake_length = data.iter().fold(0, |acc, x| acc + x.len()) as u16 + (extensions_length_bytes.len() as u16) + extensions_length;

    let handshake_header = handshake_header(handshake_length);

    let record_header_length = handshake_length + handshake_header.len() as u16;

    let record_header = record_header(record_header_length);

    result.extend_from_slice(&record_header);
    result.extend_from_slice(&handshake_header);
    for d in data {
        result.extend_from_slice(&d);
    }
    result.extend_from_slice(&extensions_length_bytes);
    for e in extensions {
        result.extend_from_slice(&e);
    }

    result

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn test_client_version() {
        let version = client_version();
        assert_eq!(version, vec![0x03, 0x03]);
    }

    #[test]
    fn test_client_random() {
        let random = client_random();
        assert_eq!(random.len(), 32);
    }

    #[test]
    fn test_session_id() {
        let session_id = session_id();
        assert_eq!(session_id, vec![0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 
            0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 
            0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 
            0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 
            0xfb, 0xfc, 0xfd, 0xfe, 0xff]);
    }

    #[test]
    fn test_cipher_suites() {
        let cipher_suites = cipher_suites();
        assert_eq!(cipher_suites, vec![0x00, 0x02, 0x13, 0x02]);
    }

    #[test]
    fn test_compression_methods() {
        let compression_methods = compression_methods();
        assert_eq!(compression_methods, vec![0x01, 0x00]);
    }

    #[test]
    fn test_extension_server_name() {
        let hostname = "example.ulfheim.net";
        let server_name = extension_server_name(hostname);
         
        assert_eq!(server_name, vec![0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 
            0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 
            0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 
            0x6d, 0x2e, 0x6e, 0x65, 0x74]);
        
        assert_eq!(server_name.len(), 28);
    }

    #[test]
    fn test_extension_ec_point_formats() {
        let ec_point_formats = extension_ec_point_formats();
        assert_eq!(ec_point_formats, vec![0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02]);
        assert_eq!(ec_point_formats.len(), 8);
    }

    #[test]
    fn test_extension_supported_groups() {
        let supported_groups = extension_supported_groups();
        assert_eq!(supported_groups, vec![0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
        assert_eq!(supported_groups.len(), 8);
    }

    #[test]
    fn test_extension_session_ticket() {
        let session_ticket = extension_session_ticket();
        assert_eq!(session_ticket, vec![0x00, 0x23, 0x00, 0x00]);
        assert_eq!(session_ticket.len(), 4);
    }

    #[test]
    fn test_extension_encrypt_then_mac() {
        let encrypt_then_mac = extension_encrypt_then_mac();
        assert_eq!(encrypt_then_mac, vec![0x00, 0x16, 0x00, 0x00]);
        assert_eq!(encrypt_then_mac.len(), 4);
    }

    #[test]
    fn test_extension_extended_master_secret() {
        let extended_master_secret = extension_extended_master_secret();
        assert_eq!(extended_master_secret, vec![0x00, 0x17, 0x00, 0x00]);
        assert_eq!(extended_master_secret.len(), 4);
    }

    #[test]
    fn test_extension_signature_algorithms() {
        let signature_algorithms = extension_signature_algorithms();
        assert_eq!(signature_algorithms, vec![0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03]);
        assert_eq!(signature_algorithms.len(), 8);
    }

    #[test]
    fn test_extension_supported_versions() {
        let supported_versions = extension_supported_versions();
        assert_eq!(supported_versions, vec![0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        assert_eq!(supported_versions.len(), 7);
    }

    #[test]
    fn test_extension_psk_key_exchange_modes() {
        let psk_key_exchange_modes = extension_psk_key_exchange_modes();
        assert_eq!(psk_key_exchange_modes, vec![0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);
        assert_eq!(psk_key_exchange_modes.len(), 6);
    }

    #[test]
    fn test_extension_key_share() {

        let pubkey = crypto::client_key_exchange_generation().pubkey;

        let key_share = extension_key_share(pubkey);

        let mut expected = vec![0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20];
        expected.extend_from_slice(&pubkey.to_bytes());


        assert_eq!(key_share, expected);
        assert_eq!(key_share.len(), 42);

    }
}