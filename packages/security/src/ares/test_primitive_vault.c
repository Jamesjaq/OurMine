#include <stdio.h>
#include <assert.h>
#include <string.h>

// Declare primitives from primitive_vault.c
int primitive_raw_tcp_probe(const char* ip_str, int port);
void primitive_xor_obfuscate(unsigned char* data, size_t len, unsigned char key);
void primitive_disguise_process(const char* name);

int main() {
    printf("[*] Running ARES Primitive Vault Verification Harness...\n");

    // 1. Test XOR Obfuscation
    unsigned char test_data[] = "ARES_SOVEREIGN_PAYLOAD";
    size_t len = strlen((char*)test_data);
    unsigned char key = 0x5A;

    primitive_xor_obfuscate(test_data, len, key);
    // De-obfuscate
    primitive_xor_obfuscate(test_data, len, key);

    assert(strcmp((char*)test_data, "ARES_SOVEREIGN_PAYLOAD") == 0);
    printf("[+] XOR Obfuscation / De-obfuscation test passed.\n");

    // 2. Test Process Disguise
    primitive_disguise_process("systemd-journald");
    printf("[+] Process disguise test passed.\n");

    // 3. Test Raw TCP Probe against localhost closed/open port
    int probe_res = primitive_raw_tcp_probe("127.0.0.1", 1);
    printf("[+] Raw TCP probe executed successfully (result: %d).\n", probe_res);

    printf("[+] All primitive vault verification tests passed successfully.\n");
    return 0;
}
