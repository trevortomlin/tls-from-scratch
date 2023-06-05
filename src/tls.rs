use rand::Rng;

struct RecordHeader {
    record_type: [u8; 1],
    version: [u8; 2],
    length: Vec<u8>,
}

struct HandshakeHeader {
    handshake_type: Vec<u8>,
    length: Vec<u8>,
}

struct ClientVersion {
    major: Vec<u8>,
    minor: Vec<u8>,
}

struct SessionID {
    length: Vec<u8>,
    session_id: Vec<u8>,
}

struct ClientRandom {
    random_bytes: [u8; 32],
}

struct CipherSuites {
    length: Vec<u8>,
    cipher_suites: Vec<u8>,
}

fn client_hello(hostname: &str) -> Vec<u8> {

    let mut result = vec![];

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
        Client Version
        03 03 - protocol version is "3,3" (also known as TLS 1.2)
    */
    result.extend_from_slice(&[0x03, 0x03]);

    /*  
        Client Random
        32 bytes of random data
    */
    result.extend_from_slice(&rand::thread_rng().gen::<[u8; 32]>());

    /*  
        Session ID
        0x20 - length of session ID
        32 bytes of fake session ID 
    */
    result.extend_from_slice(&[
                                0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 
                                0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 
                                0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 
                                0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 
                                0xfb, 0xfc, 0xfd, 0xfe, 0xff
                            ]);

    /*
        Cipher Suites
        00 02 - length of cipher suites list
        00 13 - cipher suite TLS_AES_256_GCM_SHA384
    */
    result.extend_from_slice(&[0x00, 0x02, 0x00, 0x13]);

    /*
        Compression Methods
        01 - length of compression methods list
        00 - compression method "null"
    */
    result.extend_from_slice(&[0x01, 0x00]);

    /*
        Extensions
        00 a3 - length of extensions list
    */
    result.extend_from_slice(&[0x00, 0xa3]);

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
    let host_name_length = host_name_bytes.len().to_be_bytes();

    let list_entry_type = 0x00;

    let entry_length = (list_entry_type + host_name_length.len() + host_name_bytes.len()).to_be_bytes();

    let extension_length = (list_entry_type + entry_length.len() + entry_length.len() + host_name_length.len() + host_name_bytes.len()).to_be_bytes();

    result
}

pub fn connect() {

    

    // let record_header = RecordHeader {
    //     record_type: [0x16],
    //     version: [0x03, 0x01],
    //     length: vec![0x00, 0xf8],
    // };

    // let handshake_header = HandshakeHeader {
    //     handshake_type: vec![0x01],
    //     length: vec![0x00, 0x00, 0xf4],
    // };

    // let client_version = ClientVersion {
    //     major: vec![0x03],
    //     minor: vec![0x03],
    // };
   
    // // https://qertoip.medium.com/how-to-generate-an-array-of-random-bytes-in-rust-ccf742a1afd5
    // let client_random = ClientRandom {
    //     random_bytes: rand::thread_rng().gen::<[u8; 32]>(),
    // };

    // let session_id = SessionID {
    //     length: vec![0x20],
    //     session_id: vec![
    //         0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 
    //         0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 
    //         0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
    //         0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    //     ],
    // };

    // let cipher_suites = CipherSuites {
    //     length: vec![0x00, 0x02],
    //     cipher_suites: vec![0x00, 0x13],
    // };

}