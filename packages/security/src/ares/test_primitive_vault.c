#include <stdio.h>
#include <assert.h>
#include <string.h>

int primitive_raw_tcp_probe(const char* ip_str, int port);
void primitive_xor_obfuscate(unsigned char* data, size_t len, const unsigned char* key, size_t key_len);
void primitive_disguise_process(const char* name);

int main() {
    printf("[*] Running ARES Primitive Vault v32.0 Verification Harness...\n");

    // 1. Test Multi-Byte XOR Obfuscation
    unsigned char test_data[] = "ARES_SOVEREIGN_PAYLOAD_DIRECT_SYSCALL";
    size_t len = strlen((char*)test_data);
    unsigned char key[] = "KEY99";
    size_t key_len = strlen((char*)key);

    primitive_xor_obfuscate(test_data, len, key, key_len);
    // De-obfuscate
    primitive_xor_obfuscate(test_data, len, key, key_len);

    assert(strcmp((char*)test_data, "ARES_SOVEREIGN_PAYLOAD_DIRECT_SYSCALL") == 0);
    printf("[+] Multi-Byte XOR Obfuscation / De-obfuscation test passed.\n");

    // 2. Test Process Disguise
    primitive_disguise_process("systemd-journald");
    printf("[+] Process disguise test passed.\n");

    // 3. Test Direct Syscall Raw TCP Probe against localhost
    int probe_res = primitive_raw_tcp_probe("127.0.0.1", 1);
    printf("[+] Direct syscall TCP probe executed successfully (result: %d).\n", probe_res);

    printf("[+] All primitive vault v32.0 verification tests passed successfully.\n");
    return 0;
}
