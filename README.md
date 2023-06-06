# TLS Client Implementation in Rust

This GitHub project aims to provide a TLS (Transport Layer Security) client implementation from scratch using the Rust programming language. The code in this repository demonstrates the construction of a TLS client that adheres to the TLS protocol specifications.

## Features

- TLS Handshake: The client is designed to perform the TLS handshake process, establishing a secure connection with a TLS server.
- Certificate Validation: The implementation includes a certificate validation mechanism to verify the authenticity and integrity of server certificates.
- Cipher Suite Support: The TLS client supports a range of cipher suites for secure communication.
- Secure Communication: Once the TLS handshake is successfully completed, the client can securely communicate with the TLS server.

## Requirements

To build and run the TLS client implementation, ensure that you have the following dependencies installed:

- Rust Programming Language: Make sure you have Rust installed on your system. You can download and install Rust from the official Rust website (https://www.rust-lang.org/).

## Usage

To use the TLS client implementation, follow these steps:

1. Clone this repository to your local machine using the following command:

   ```
   git clone https://github.com/trevortomlin/tls-from-scratch.git
   ```

2. Navigate to the project directory:

   ```
   cd tls-from-scratch
   ```

3. Build the project using the Rust package manager, Cargo:

   ```
   cargo build
   ```

4. Run the TLS client:

   ```
   cargo run
   ```

   Make sure to modify the code to specify the TLS server's hostname, port number, and other necessary configurations as per your requirements.

## License

This project is licensed under the [MIT License](LICENSE). Feel free to use and modify the code as per the terms of the license.

## Acknowledgments

- [A Toy Version of TLS](https://jvns.ca/blog/2022/03/23/a-toy-version-of-tls/)
- [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org/)
