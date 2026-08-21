/**
 * @file primitive_vault.c
 * @brief ARES v32.0 Kinetic Sovereignty — Hardened Offensive Primitive Vault
 * Provides true direct syscall stubs (bypassing libc socket/connect wrappers),
 * real socket timeout enforcement via setsockopt, and memory obfuscation.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/time.h>

// True direct syscall stub for raw TCP port probe bypassing libc hooks
int primitive_raw_tcp_probe(const char* ip_str, int port) {
    // Direct syscall for socket: sys_socket(domain, type, protocol)
    int sock = (int)syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip_str, &target.sin_addr) <= 0) {
        syscall(SYS_close, sock);
        return -1;
    }

    // Set connection timeout (e.g., 2 seconds) using setsockopt
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // Direct syscall for connect: sys_connect(fd, addr, addrlen)
    long res = syscall(SYS_connect, sock, (struct sockaddr*)&target, sizeof(target));
    syscall(SYS_close, sock);

    return res == 0 ? 1 : 0;
}

// Memory obfuscation primitive (Multi-byte XOR cipher key rotation)
void primitive_xor_obfuscate(unsigned char* data, size_t len, const unsigned char* key, size_t key_len) {
    if (key_len == 0) return;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

// Process disguise primitive via prctl
void primitive_disguise_process(const char* name) {
    prctl(PR_SET_NAME, name, 0, 0, 0);
}
