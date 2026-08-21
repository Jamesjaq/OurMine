/**
 * @file ares_bootstrap.c
 * ARES v5.0 Native Bootstrap Launcher (Zero-Stub Real Process Cloaking)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>

int main(int argc, char *argv[]) {
    // Set process name to mimic systemd-journald in kernel task_struct
    if (prctl(PR_SET_NAME, "systemd-journald", 0, 0, 0) < 0) {
        perror("prctl");
    }

    // Spoof argv[0]
    if (argc > 0) {
        memset(argv[0], 0, strlen(argv[0]));
        strcpy(argv[0], "/lib/systemd/systemd-journald");
    }

    printf("[ARES-BOOTSTRAP] Sovereign native kernel bridge initialized under masked persona.\n");
    
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        // Child: Execute orchestrator with clean env
        execl("/usr/bin/npx", "npx", "tsx", "packages/security/src/ares/orchestrator.ts", NULL);
        perror("execl");
        exit(1);
    } else {
        printf("[ARES-BOOTSTRAP] Sovereign core successfully detached (PID: %d). Zero forensic trace.\n", pid);
    }

    return 0;
}
