#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

// Hook the write syscall
ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    
    if (!real_write) {
        real_write = dlsym(RTLD_NEXT, "write");
    }
    
    // Log malicious activity
    if (fd == 1 || fd == 2) { // stdout/stderr
        real_write(2, "[MALICIOUS] Intercepted write!\n", 31);
    }
    
    return real_write(fd, buf, count);
}

__attribute__((constructor))
void malicious_init() {
    write(2, "[MALICIOUS] Library loaded via LD_PRELOAD!\n", 43);
}
