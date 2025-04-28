/*
*  File: server.cpp
 * Author: Johnny CW
 * Date: April 28, 2025
 * Implementation of Server which generates RSA keys, listens for client connections, sends its public key,
 * receives encrypted messages, decrypts them and sends acknowledgement
 */

#define USE_IPV6 true

#if defined _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <iostream>
#define WSVERS MAKEWORD(2, 2)
WSADATA wsadata;
#else
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <iostream>
#endif

#include <boost/multiprecision/cpp_int.hpp>
#include <vector>
#include <string>
#include <sstream>
#include "rsa_cbc.h"

using namespace boost::multiprecision;
using std::cout;

#define DEFAULT_PORT "1234"
#define BUFFER_SIZE 65536 //64KB or 200-300 characters



int main(int argc, char *argv[]) {
 bool debug_mode = true;


#if defined _WIN32
 if (WSAStartup(WSVERS, &wsadata) != 0) {
  printf("WSAStartup failed with error: %d\n", WSAGetLastError());
  WSACleanup();
  return 1;
 }
 cout << "Winsock 2.2 initialized.\n";
#endif

 cout << "\n<<<RSA-CBC TCP Server>>>\n";
 cout << "IPv6 mode: " << (USE_IPV6 ? "enabled" : "disabled") << "\n";

 //Generate RSA Keys
 int bits = 512;
 cpp_int n, e, d;
 generate_rsa_keys(n, e, d, bits);
 cout << "Generated RSA keys:\n";
 cout << "n: " << n << "\n";
 cout << "e: " << e << "\n";
 cout << "d: " << d << "\n";

 //Servers address
 struct addrinfo hints, *result = nullptr;
 memset(&hints, 0, sizeof(hints));
 hints.ai_family = USE_IPV6 ? AF_INET6 : AF_INET;
 hints.ai_socktype = SOCK_STREAM;
 hints.ai_protocol = IPPROTO_TCP;
 hints.ai_flags = AI_PASSIVE;

 char portNum[12];
 if (argc==2) {
  strncpy(portNum, argv[1], sizeof(portNum) - 1);
  portNum[sizeof(portNum) - 1] = '\0';
 }else {
  strncpy(portNum, DEFAULT_PORT, sizeof(portNum) - 1);
  portNum[sizeof(portNum) - 1] = '\0';
  cout << "Using default port: " << DEFAULT_PORT << std::endl;
 }

 if (getaddrinfo(nullptr, portNum, &hints, &result) != 0) {
   std::cerr << "getaddrinfo failed with error: " << strerror(errno) << std::endl;
#if defined _WIN32
  WSACleanup();
#endif
  return 1;
 }

 //Server Socket
#if defined _WIN32
 SOCKET s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
 if (s == INVALID_SOCKET) {
  std::cerr << "socket failed: " << WSAGetLastError() << "\n";
  freeaddrinfo(result);
  WSACleanup();
  return 1;
 }
#else
 int s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
 if (s < 0) {
  std::cerr << "socket failed: " << errno << "\n";
  freeaddrinfo(result);
  return 1;
 }
#endif

 //Binding
 if (bind(s, result->ai_addr, result->ai_addrlen) < 0){
  std::cerr << "bind failed: " << errno << "\n";
  freeaddrinfo(result);
#if defined _WIN32
  closesocket(s);
  WSACleanup();
#else
  close(s);
#endif
  return 1;
 }

 //Listen
 if (listen(s, SOMAXCONN) != 0) {
  std::cerr << "listen failed: " << WSAGetLastError() << "\n";
  freeaddrinfo(result);
#if defined _WIN32
  closesocket(s);
  WSACleanup();
#else
  close(s);
#endif
  return 1;
 }

 cout << "Server is listening on port " << portNum << "...\n";
 freeaddrinfo(result);

 while (true){
  struct sockaddr_storage clientAddress;
  socklen_t addrlen = sizeof(clientAddress);

#if defined _WIN32
  SOCKET ns = accept(s, (struct sockaddr *)&clientAddress, &addrlen);
  if (ns == INVALID_SOCKET) {
   std::cerr << "accept failed: " << WSAGetLastError() << "\n";
   continue;
  }
#else
  int ns = accept(s, (struct sockaddr *)&clientAddress, &addrlen);
  if (ns < 0) {
   std::cerr << "accept failed: " << errno << "\n";
   continue;
  }
#endif

  char clientHost[NI_MAXHOST], clientService[NI_MAXSERV];
  getnameinfo((struct sockaddr *)&clientAddress, addrlen, clientHost, sizeof(clientHost), clientService, sizeof(clientService), NI_NUMERICSERV);
  cout << "Client connected: " << clientHost << ":" << clientService << "\n";

  //Send the public key (e|n) to the client
  std::string public_key = e.str() + "|" + n.str();
  int bytes = send(ns, public_key.c_str(), public_key.size(), 0);
  if (bytes <= 0){
   std::cerr << "send public key failed: " << WSAGetLastError() << "\n";
#if defined _WIN32
   closesocket(ns);
#else
   close(ns);
#endif
   continue;
  }

  //Handling messages from the same client
  while (true) {
   char buffer[BUFFER_SIZE];
   memset(buffer, 0, BUFFER_SIZE);
   bytes = recv(ns, buffer, BUFFER_SIZE-1, 0);
   if (bytes <= 0) {
    std::cout << "Client disconnected\n";
    break;
   }
   buffer[bytes] = '\0';

   // Debug: Show raw received data
   if (debug_mode){
    cout << "[DEBUG] Received data: " << buffer << std::endl;
   }

   std::string data(buffer);
   size_t delimiter_pos = data.find('|');
   if (delimiter_pos == std::string::npos) {
    cout << "Invalid data format.\n";
    continue;
   }

   std::string encrypted_nonce_str = data.substr(0, delimiter_pos);
   std::string cipher_str = data.substr(delimiter_pos + 1);

   // Debug: Show encrypted nonce and ciphertext
   if (debug_mode) {
    cout << "[DEBUG] Encrypted nonce: " << encrypted_nonce_str << std::endl;
    cout << "[DEBUG] Ciphertext blocks: " << cipher_str << std::endl;
   }

   //Decrypt Nonce to use it as the IV
   cpp_int encrypted_nonce(encrypted_nonce_str);
   cpp_int iv = rsa_decrypt(encrypted_nonce, d, n);

   // Debug: Show decrypted IV
   if (debug_mode) {
    cout << "[DEBUG] Decrypted IV: " << iv << std::endl;
   }


   //Parse the ciphertext blocks
   std::vector<cpp_int> cipher;
   std::stringstream ss(cipher_str);
   std::string block;
   while (getline(ss, block, ',')) {
    if (!block.empty()) {
     cipher.push_back(cpp_int(block));
    }
   }

   // Debug: Show number of parsed blocks
   if (debug_mode) {
    cout << "[DEBUG] Parsed " << cipher.size() << " ciphertext blocks." << std::endl;
   }

   //Decrypt Message Blocks
   std::string decrypted_message = cbc_decrypt(cipher, d, n, iv);
   std::cout << "Decrypted message: " << decrypted_message << std::endl;

   //Send Response to the client
   std::string response = "Message received: " + decrypted_message + "\r\n";
   bytes = send(ns, response.c_str(), response.size(), 0);
   if(bytes <= 0) {
    std::cerr << "send failed: " << WSAGetLastError() << "\n";
    break;
   }
  }


#if defined _WIN32
  closesocket(ns);
#else
  close(ns);
#endif
 }

#if defined _WIN32
 closesocket(s);
 WSACleanup();
#else
 close(s);
#endif

 return 0;
}