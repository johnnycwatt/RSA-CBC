# RSA-CBC Encryption/Decryption

This project implements an RSA encryption system with Cipher Block Chaining (CBC). 
It demonstrates key cryptographic concepts including RSA key generation, modular exponentiation, primality testing, and CBC mode for secure message encryption and decryption. 
The implementation uses the Boost library for handling large integers and random number generation.

## Features
- **RSA Key Generation**: Generates public and private keys using large prime numbers.
- **Miller-Rabin Primality Test**: Probabilistic primality testing for generating secure primes.
- **CBC Mode**: Implements block chaining for secure encryption of messages.
- **Client-Server Communication:** Facilitates secure message exchange over a TCP network using IPv6 or IPv4.
- **Debug Mode**: Provides detailed output of encryption and decryption steps for educational analysis when enabled.

## Project Structure
- common/: Contains RSA-CBC core implementation and header files.
- server/: Implements the server, which generates keys, accepts connections, and decrypts messages.
- client/: Implements the client, which encrypts and sends messages using the server’s public key.
- example_interaction.txt: Shows a sample client-server interactions.

## Prerequisites
- **C++20 Compiler**: GCC, MSVC, or Clang with C++20 support.
- **Boost Library**: Version 1.84.0 or compatible, for `multiprecision` and `random`.
- **CMake**: Version 3.20 or higher.

## Usage
The project includes a client-server application:

- Server: Generates RSA keys, listens for client connections, sends its public key, receives encrypted messages (with a nonce as IV), decrypts them using CBC mode, and responds with an acknowledgment.
- Client: Connects to the server, receives the public key, encrypts user-input messages with a random nonce, sends them, and displays the server’s response.
- Buffer Size: Configured to 64 KB to handle messages up to approximately 200–300 characters.
- Debug Mode: When enabled, the server outputs detailed encryption/decryption steps, including received data, nonce, ciphertext blocks, and IV.


## Notes
This project is for educational purposes only and should not be used in production environments due to potential security limitations. 



