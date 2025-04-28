/*
 *  File: client.cpp
 * Author: Johnny CW
 * Date: April 28, 2025
 * Connects to the server, receives the public key, encrypts user-input messages with a random nonce, sends them, and displays the server’s response.
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
#include <random>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include "rsa_cbc.h"

using namespace boost::multiprecision;
using namespace boost::random;
using std::cout;

#define DEFAULT_PORT "1234"
#define BUFFER_SIZE 4096

int main(int argc, char *argv[]) {
    // Initialize Winsock on Windows
#if defined _WIN32
    if (WSAStartup(WSVERS, &wsadata) != 0){
        printf("WSAStartup failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    cout << "Winsock 2.2 initialized.\n";
#endif

    cout << "\n<<<RSA-CBC TCP Client>>>\n";
    cout << "IPv6 mode: " << (USE_IPV6 ? "enabled" : "disabled") << "\n";

    // Set up server address
    struct addrinfo hints, *result = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = USE_IPV6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const char *host = (argc >= 2) ? argv[1] : (USE_IPV6 ? "::1" : "127.0.0.1");
    const char *port = (argc == 3) ? argv[2] : DEFAULT_PORT;
    cout << "Connecting to " << host << ":" << port << "\n";

    int res = getaddrinfo(host, port, &hints, &result);
    if (res != 0){
#if defined _WIN32
        std::cerr << "getaddrinfo failed: " << res << " (WSAGetLastError: " << WSAGetLastError() << ")\n";
#else
        std::cerr << "getaddrinfo failed: " << gai_strerror(res) << "\n";
#endif
#if defined _WIN32
        WSACleanup();
#endif
        return 1;
    }

    // Create client socket
#if defined _WIN32
    SOCKET s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s == INVALID_SOCKET){
        std::cerr << "socket failed: " << WSAGetLastError() << "\n";
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }
#else
    int s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s < 0){
        std::cerr << "socket failed: " << strerror(errno) << "\n";
        freeaddrinfo(result);
        return 1;
    }
#endif

    // Connect to server
    if (connect(s, result->ai_addr, result->ai_addrlen)!= 0){
#if defined _WIN32
        std::cerr << "connect failed: " << WSAGetLastError() << "\n";
#else
        std::cerr << "connect failed: " << strerror(errno) << "\n";
#endif
        freeaddrinfo(result);
#if defined _WIN32
        closesocket(s);
        WSACleanup();
#else
        close(s);
#endif
        return 1;
    }

    char serverHost[NI_MAXHOST], serverService[NI_MAXSERV];
    getnameinfo(result->ai_addr, result->ai_addrlen, serverHost, sizeof(serverHost),
                serverService, sizeof(serverService), NI_NUMERICHOST);
    cout << "Connected to " << serverHost << ":" << serverService << "\n";
    freeaddrinfo(result);

    // Receive server's public key: e|n
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    int bytes = recv(s, buffer, BUFFER_SIZE - 1, 0);
    if (bytes <= 0){
#if defined _WIN32
        std::cerr << "recv public key failed: " << WSAGetLastError() << "\n";
#else
        std::cerr << "recv public key failed: " << strerror(errno) << "\n";
#endif
#if defined _WIN32
        closesocket(s);
        WSACleanup();
#else
        close(s);
#endif
        return 1;
    }
    buffer[bytes] = '\0';

    // Parse public key
    std::string public_key(buffer);
    size_t delimiter_pos = public_key.find('|');
    if (delimiter_pos == std::string::npos) {
        cout << "Invalid public key format.\n";
#if defined _WIN32
        closesocket(s);
        WSACleanup();
#else
        close(s);
#endif
        return 1;
    }
    std::string e_str = public_key.substr(0, delimiter_pos);
    std::string n_str = public_key.substr(delimiter_pos + 1);
    cpp_int e(e_str);
    cpp_int n(n_str);
    cout << "Received public key: e = " << e << ", n = " << n << "\n";

    while (true){
        cout << "Enter message (or '.' to quit): ";
        std::string message;
        std::getline(std::cin, message);
        if (message == ".") break;

        // Generate random nonce
        mt19937_64 gen(std::random_device{}());
        uniform_int_distribution<cpp_int> dis(1, n - 1);
        cpp_int nonce = dis(gen);

        // Encrypt nonce with server's public key
        cpp_int encrypted_nonce = rsa_encrypt(nonce, e, n);

        // Encrypt message using RSA-CBC with nonce as IV
        std::vector<cpp_int> encrypted_message = cbc_encrypt(message, e, n, nonce);
        std::stringstream send_data;
        send_data << encrypted_nonce.str() << "|";
        for (size_t i = 0; i < encrypted_message.size(); ++i){
            send_data << encrypted_message[i].str();
            if (i < encrypted_message.size() - 1) send_data << ",";
        }

        std::string send_str = send_data.str();
        bytes = send(s, send_str.c_str(), send_str.size(), 0);
        if (bytes <= 0) {
#if defined _WIN32
            std::cerr << "send failed: " << WSAGetLastError() << "\n";
#else
            std::cerr << "send failed: " << strerror(errno) << "\n";
#endif
            break;
        }
        cout << "Message sent.\n";

        // Receive and display the response
        memset(buffer, 0, BUFFER_SIZE);
        bytes = recv(s, buffer, BUFFER_SIZE - 1, 0);
        if (bytes <= 0) {
#if defined _WIN32
            std::cerr << "recv failed: " << WSAGetLastError() << "\n";
#else
            std::cerr << "recv failed: " << strerror(errno) << "\n";
#endif
            break;
        }
        buffer[bytes] = '\0';
        cout << "Server response: " << buffer << "\n";
    }

    cout << "Shutting down...\n";
#if defined _WIN32
    closesocket(s);
    WSACleanup();
#else
    close(s);
#endif
    return 0;
}