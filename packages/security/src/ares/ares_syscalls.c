/**
 * @file ares_syscalls.c
 * ARES v5.0 Direct Syscall Stubs (Bypassing libc hooks)
 * Implements raw Linux syscalls for process execution and file I/O
 * to defeat user-space API hooking by advanced EDRs.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>

// Direct syscall wrapper for sys_write
long ares_sys_write(int fd, const void *buf, size_t count) {
    return syscall(SYS_write, fd, buf, count);
}

// Direct syscall wrapper for sys_getpid
pid_t ares_sys_getpid(void) {
    return syscall(SYS_getpid);
}

// Direct syscall wrapper for sys_openat
int ares_sys_open(const char *filename, int flags, int mode) {
    return syscall(SYS_openat, AT_FDCWD, filename, flags, mode);
}

int main(void) {
    char msg[] = "[ARES-SYSCALL] Direct kernel syscall bridge active. Zero libc hooking detected.\n";
    ares_sys_write(1, msg, sizeof(msg));
    return 0;
}
