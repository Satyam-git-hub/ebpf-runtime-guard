#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>

#define TEST_FILE "/tmp/test_binary"
#define MALICIOUS_FILE "/tmp/malicious_binary"

// Thread function to race and change the binary
void* race_thread(void* arg) {
    sleep(1); // Give main thread time to start execve
    
    // Create malicious content
    FILE *f = fopen(MALICIOUS_FILE, "w");
    if (f) {
        fprintf(f, "#!/bin/bash\necho 'MALICIOUS CODE EXECUTED!'\n");
        fclose(f);
        chmod(MALICIOUS_FILE, 0755);
    }
    
    // Try to replace the original file with malicious one
    // This simulates a TOCTOU attack
    if (rename(MALICIOUS_FILE, TEST_FILE) == 0) {
        printf("Race condition: Successfully replaced binary!\n");
    }
    
    return NULL;
}

int main() {
    pthread_t race_tid;
    
    printf("=== TOCTOU Attack Test ===\n");
    
    // Create initial benign binary
    FILE *f = fopen(TEST_FILE, "w");
    if (!f) {
        perror("Failed to create test file");
        return 1;
    }
    fprintf(f, "#!/bin/bash\necho 'Benign program executed'\n");
    fclose(f);
    chmod(TEST_FILE, 0755);
    
    printf("Created benign binary: %s\n", TEST_FILE);
    
    // Start the racing thread
    if (pthread_create(&race_tid, NULL, race_thread, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }
    
    printf("Starting execve of benign binary...\n");
    
    // Fork and exec the test binary
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - execute the binary
        execl(TEST_FILE, TEST_FILE, NULL);
        perror("execl failed");
        exit(1);
    } else if (pid > 0) {
        // Parent process - wait for child
        int status;
        waitpid(pid, &status, 0);
        printf("Child process completed with status: %d\n", status);
    } else {
        perror("fork failed");
        return 1;
    }
    
    // Wait for race thread to complete
    pthread_join(race_tid, NULL);
    
    // Clean up
    unlink(TEST_FILE);
    unlink(MALICIOUS_FILE);
    
    printf("Test completed. Check eBPF output for TOCTOU detection.\n");
    
    return 0;
}
