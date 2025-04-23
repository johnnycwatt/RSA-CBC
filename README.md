# RSA-CBC Encryption/Decryption

This project implements an RSA encryption system with Cipher Block Chaining (CBC). 
It demonstrates key cryptographic concepts including RSA key generation, modular exponentiation, primality testing, and CBC mode for secure message encryption and decryption. 
The implementation uses the Boost library for handling large integers and random number generation.

## Features
- **RSA Key Generation**: Generates public and private keys using large prime numbers.
- **Miller-Rabin Primality Test**: Probabilistic primality testing for generating secure primes.
- **CBC Mode**: Implements block chaining for secure encryption of messages.
- **Simulation**: Current implementation includes a standalone simulation of encryption/decryption.

## Prerequisites
- **C++20 Compiler**: GCC, MSVC, or Clang with C++20 support.
- **Boost Library**: Version 1.84.0 or compatible, for `multiprecision` and `random`.
- **CMake**: Version 3.20 or higher.

## Usage
The current implementation (rsa_cbc.cpp) runs a simulation:
- Generates RSA keys with a 512-bit modulus.
- Encrypts a sample message ("Hello World!") using RSA-CBC with a random nonce as the IV.
- Decrypts and displays the result.

## Plan
- TCP-based client-server application
- Secure transmission of encrypted messages over a network.
- Example interaction logs to demonstrate client-server communication.

## Notes
This project is for educational purposes only and should not be used in production environments due to potential security limitations.



