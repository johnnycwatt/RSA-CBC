/*
*  File: rsa_cbc.cpp
 * Author: Johnny CW
 * Date: April 23, 2025
 * RSA-CBC encryption and decryption implementation from scratch using Boost Library for dealing with large numbers
 */

#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>

using namespace boost::multiprecision;
using namespace boost::random;

/*
 * Modular Exponentiation
 *
 * Variables:
 * base: the base number (message or ciphertext in RSA)
 * exp: Exponent (public exponent e or private exponent d)
 * mod: the modulus (eg, in RSA, n = p*q)
 *
 * Purpose:
 * In RSA, encryption is c = m^e mod n and decryption is m = c^d mod n
 * Modular exponentiation is the core operation, and doing it efficiently is critical because e, d, and n are very large numbers.
 */
cpp_int mod_exp(cpp_int base, cpp_int exp, cpp_int mod){
    return powm(base, exp,mod);
}


/*
 * Extended Euclidean Algorithm for modular inverse
 *
 * Variables
 * e: The public exponent (typically 65537)
 * phi: Euler's totient function value, phi = (p-1)*(q-1), where p and q are the prime numbers
 * t, new_t: Coefficients updated in the Extended Euclidean Algorithm
 * r, new_r: Remainders which are updated in the algorithm
 * quotient: the integer quotient  of r/new_r
 *
 * Purpose:
 * Extended Euclidean Algorithm is used to compute the gratest common divisor (GCD) of e and phi while tracking coefficients.
 * If the GCD is 1, t becomes the inverse. If it is greater than 1, no inverse exists. If t is negative, it is adjusted by adding phi to make it positive
 *
 * In RSA, e and phi must be coprime (GCD = 1), and d is computed as the inverse of e modulo phi. This ensures the encryption and decryption processes reverse each other.
 */
cpp_int mod_inverse(cpp_int e, cpp_int phi){
    cpp_int t = 0, new_t = 1;
    cpp_int r = phi, new_r = e;

    while (new_r != 0){
        cpp_int quotient = r /new_r;
        cpp_int temp_t = t;
        t = new_t;
        new_t = temp_t - quotient *new_t;
        cpp_int temp_r = r;
        r = new_r;
        new_r =temp_r - quotient* new_r;
    }

    if (r > 1) return 0; // No inverse exists
    if (t < 0) t += phi;
    return t;
}

/*
 *  Miller-Rabin primality test
 *
 *  Variables:
 *  n : the number to test
 *  k : the number of rounds (with a default of 10) controlling accuracy
 *  d,s: Express n-1 = d * 2 ^s, where d is odd
 *  a: A random base between 2 and n-2
 *  x : Result of modular exponentian, tested against conditions
 *
 *  Purpose:
 *  Tests if a number n is prime using the probabilistic Miller-Rabin algorithm.
 *
 *   It checks if n satisfies primality conditions for k random bases. If any test fails, n is composite; if all pass, n is probably prime.
 * RSA requires large prime numbers (p and q) and deterministic primality tests are too slow for large numbers.
 */

bool miller_rabin_test(cpp_int n, int k = 10){
    if (n <= 1 || (n % 2 == 0 && n != 2)) return false;
    if (n == 2 || n == 3) return true;

    cpp_int d = n -1;
    int s = 0;
    while (d % 2 == 0){
        d /= 2;
        ++s;
    }

    mt19937_64 gen(std::random_device{}());
    uniform_int_distribution<cpp_int> dis(2, n - 2);

    for (int i = 0; i < k; ++i) {
        cpp_int a = dis(gen);
        cpp_int x = mod_exp(a, d, n);
        if (x == 1 || x == n - 1) continue;

        bool is_prime = false;
        for (int r = 0;r < s - 1; ++r){
            x = mod_exp(x, 2, n);
            if (x == n - 1){
                is_prime = true;
                break;
            }
        }
        if (!is_prime) return false;
    }
    return true;
}

/*
 * Random Number Generation
 *
 * Variables:
 * bits: Desired Bit length,
 * gen:Mersenne Twister random number generator.
 * Iterations: number of 64-bit chunks needed
 *
 * Purpose:
 * Generates a random number with exactly the amount of bits, ensuring it’s odd and has the most significant bit set.
 * RSA needs large random numbers to generate candidate primes. The number must be sufficiently large and random to ensure security.
 */
cpp_int random_number(int bits){
    mt19937_64 gen(std::random_device{}());
    cpp_int result = 0;
    int iterations = (bits + 63) / 64;
    for (int i = 0; i < iterations; ++i){
        result = (result << 64) | gen();
    }
    result &= (cpp_int(1) << bits) - 1;
    result |= (cpp_int(1) << (bits - 1)) | 1;
    return result;
}


/*
 * Prime Number Generation
 *  It keeps generating random numbers and tests them with Miller-Rabin until a prime is found.
 */
cpp_int generate_prime(int bits){
    while (true){
        cpp_int candidate = random_number(bits);
        if (miller_rabin_test(candidate, 10)) return candidate;
    }
}


/*
 * RSA Key Generation
 *
 * Variables:
 * n: Modulus (p*q), part of both keys
 * e: public exponent (set to the common 65537)
 * d: Private exponent (inverse of e modulo phi)
 * p, q : Two distinct prime numbers
 * phi: (p-1)*(q-1), used to compute d
 *
 * Generates two primes of bits/2 bits, ensures they’re different, computes n and phi, sets e, and calculates d.
 */
void generate_rsa_keys(cpp_int& n, cpp_int& e, cpp_int& d, int bits){
    cpp_int p = generate_prime(bits / 2);
    cpp_int q = generate_prime(bits / 2);
    while (q == p) q = generate_prime(bits / 2); // Ensure p != q
    n = p * q;
    cpp_int phi = (p - 1) * (q - 1);
    e = 65537; // Standard public exponent
    d = mod_inverse(e, phi);
}


/*
 * Encrypts a message m using the mublic key (e, n)
 */
cpp_int rsa_encrypt(cpp_int m, cpp_int e, cpp_int n) {
    return mod_exp(m, e, n);
}


/*
 * Decrypts a ciphertext c using the private key (d, n).
 */
 cpp_int rsa_decrypt(cpp_int c, cpp_int d, cpp_int n){
    return mod_exp(c, d, n);
}

 /*
 * CBC Encryption
 *
 * Variables:
 * iv: initialization vector (starts as prev)
 * prev: previous ciphertext block (initially iv)
 * m: current plaintext byte
 * x: result of XORing m with prev % 256
 * c: encrypted block
 *
 * Purpose:
 * Encyrpts a plaintext string in CBC mode using RSA. For each character, it converts it to a byte, XORs it with the previous ciphertext (mod 256 to match byte size)
 * Encrypts with RSA, stores the result and updates prev.
 *
 * CBC mode chaines bloicks by XORing each plaintext block with the previous ciphertext, starting with an IV, ensuring identical plaintexts produce different ciphertexts if the IV differs
 */
std::vector<cpp_int> cbc_encrypt(const std::string& plaintext, cpp_int e, cpp_int n, cpp_int iv){
    std::vector<cpp_int> cipher;
    cpp_int prev = iv;
    for(char ch :plaintext){
        cpp_int m = static_cast<unsigned char>(ch);
        cpp_int x = m ^ (prev % 256); // XOR with previous ciphertext
        cpp_int c = rsa_encrypt(x, e, n);
        cipher.push_back(c);
        prev = c;
    }
    return cipher;
}


  /*
 *CBC Decryption
 *
 * cipher: vector of encrypted blocks
 * d,n: private key
 * iv: initialization vector
 * prev: previous ciphertext block
 * x: decrypted intermediate value
 * m: recovered plaintext byte
 *
 * Purpose:
 * Decrypts a CBC-encrypted message. For each ciphertext block, decrypts it, XORs with previous ciphertext, convers to a character, and updates prev
 */
 std::string cbc_decrypt(const std::vector<cpp_int>& cipher, cpp_int d, cpp_int n, cpp_int iv){
    std::string plaintext;
    cpp_int prev = iv;
    for (const auto& c : cipher) {
        cpp_int x = rsa_decrypt(c, d, n);
        cpp_int m = x ^ (prev % 256);
        plaintext += static_cast<char>(m.convert_to<int>());
        prev = c;
    }
    return plaintext;
}


/*
 * For Simulation purposes
 */
int main(){
    int bits = 512; // Bit length for RSA modulus (n = p * q)

    //Generate RSA keys
    cpp_int n, e, d;
    generate_rsa_keys(n, e, d, bits);
    std::cout << "Server Public Key: (e = " << e << ", n = " << n << ")\n";
    std::cout << "Server Private Key: (d = " << d << ", n = " << n << ")\n";

    // Client generates a nonce and encrypts it with the server's public key
    mt19937_64 gen(std::random_device{}());
    uniform_int_distribution<cpp_int> dis(1, n - 1);
    cpp_int nonce = dis(gen); // Random nonce less than n
    cpp_int encrypted_nonce = rsa_encrypt(nonce, e, n);
    std::cout << "Client: Encrypted Nonce: " << encrypted_nonce << "\n";

    //Server decrypts the nonce to use as IV
    cpp_int decrypted_nonce = rsa_decrypt(encrypted_nonce, d, n);
    std::cout << "Server: Decrypted Nonce (IV): " << decrypted_nonce << "\n";

    //Client encrypts a message using CBC with the nonce as IV
    std::string message = "Hello World!";
    std::vector<cpp_int> encrypted_message = cbc_encrypt(message, e, n, nonce);
    std::cout << "Client: Encrypted Message: ";
    for (const auto& c : encrypted_message) {
        std::cout << c << " ";
    }
    std::cout << "\n";

    //Server decrypts the message using CBC with the decrypted nonce as IV
    std::string decrypted_message = cbc_decrypt(encrypted_message, d, n, decrypted_nonce);
    std::cout << "Server: Decrypted Message: " << decrypted_message << "\n";

    return 0;
}