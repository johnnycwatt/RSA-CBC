#ifndef RSA_CBC_H
#define RSA_CBC_H

#include <vector>
#include <string>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>

using namespace boost::multiprecision;
using namespace boost::random;

cpp_int mod_exp(cpp_int base, cpp_int exp, cpp_int mod);
cpp_int mod_inverse(cpp_int e, cpp_int phi);
bool miller_rabin_test(cpp_int n, int k = 10);
cpp_int random_number(int bits);
cpp_int generate_prime(int bits);
void generate_rsa_keys(cpp_int& n, cpp_int& e, cpp_int& d, int bits);
cpp_int rsa_encrypt(cpp_int m, cpp_int e, cpp_int n);
cpp_int rsa_decrypt(cpp_int c, cpp_int d, cpp_int n);
std::vector<cpp_int> cbc_encrypt(const std::string& plaintext, cpp_int e, cpp_int n, cpp_int iv);
std::string cbc_decrypt(const std::vector<cpp_int>& cipher, cpp_int d, cpp_int n, cpp_int iv);

#endif