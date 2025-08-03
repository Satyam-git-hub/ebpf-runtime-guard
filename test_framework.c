#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>

#define TEST_BINARY "/tmp/toctou_test_binary"

void test_basic_toctou() {
    printf("\n=== Test 1: Basic TOCTOU Race Condition ===\n");
    
    // Create initial benign binary
    FILE *f = fopen(TEST_BINARY, "w");
    fprintf(f, "#!/bin/bash\necho 'Original benign binary'\n");
    fclose(f);
    chmod(TEST_BINARY, 0755);
    
    if (fork() == 0) {
        // Child process: Race to replace file
        usleep(25000); // 25ms delay
        printf("🔥 ATTACK: Replacing binary during execution window\n");
        
        f = fopen(TEST_BINARY, "w");
        fprintf(f, "#!/bin/bash\necho '💀 MALICIOUS PAYLOAD EXECUTED!'\n");
        fclose(f);
        exit(0);
    } else {
        // Parent: Execute the binary after small delay
        usleep(50000); // 50ms delay
        printf("📋 VICTIM: Attempting to execute trusted binary\n");
        
        if (fork() == 0) {
            execl(TEST_BINARY, TEST_BINARY, NULL);
            exit(1);
        } else {
            wait(NULL);
        }
        wait(NULL);
    }
}

void test_symlink_toctou() {
    printf("\n=== Test 2: Symlink TOCTOU Attack ===\n");
    
    // Create good and bad targets
    FILE *f1 = fopen("/tmp/good_target", "w");
    fprintf(f1, "#!/bin/bash\necho 'Legitimate program'\n");
    fclose(f1);
    chmod("/tmp/good_target", 0755);
    
    FILE *f2 = fopen("/tmp/bad_target", "w");
    fprintf(f2, "#!/bin/bash\necho '🚨 SYMLINK ATTACK SUCCESS!'\n");
    fclose(f2);
    chmod("/tmp/bad_target", 0755);
    
    // Create symlink to good target
    symlink("/tmp/good_target", TEST_BINARY);
    
    if (fork() == 0) {
        // Child: Race to change symlink target
        usleep(30000);
        printf("🔗 ATTACK: Changing symlink target during execution\n");
        unlink(TEST_BINARY);
        symlink("/tmp/bad_target", TEST_BINARY);
        exit(0);
    } else {
        // Parent: Execute through symlink
        usleep(60000);
        printf("🎯 VICTIM: Executing through symlink\n");
        
        if (fork() == 0) {
            execl(TEST_BINARY, TEST_BINARY, NULL);
            exit(1);
        } else {
            wait(NULL);
        }
        wait(NULL);
    }
    
    // Cleanup
    unlink(TEST_BINARY);
    unlink("/tmp/good_target");
    unlink("/tmp/bad_target");
}

void* race_thread(void* arg) {
    usleep(40000); // 40ms
    printf("🏃 ATTACK: Multi-threaded file replacement\n");
    
    FILE *f = fopen(TEST_BINARY, "w");
    fprintf(f, "#!/bin/bash\necho '🧵 THREAD RACE ATTACK!'\n");
    fclose(f);
    return NULL;
}

void test_multithreaded_toctou() {
    printf("\n=== Test 3: Multi-threaded TOCTOU ===\n");
    
    FILE *f = fopen(TEST_BINARY, "w");
    fprintf(f, "#!/bin/bash\necho 'Original threaded binary'\n");
    fclose(f);
    chmod(TEST_BINARY, 0755);
    
    pthread_t thread;
    pthread_create(&thread, NULL, race_thread, NULL);
    
    usleep(20000); // 20ms
    printf("🎭 VICTIM: Executing in threaded environment\n");
    
    if (fork() == 0) {
        execl(TEST_BINARY, TEST_BINARY, NULL);
        exit(1);
    } else {
        wait(NULL);
    }
    
    pthread_join(thread, NULL);
}

void test_rapid_execution() {
    printf("\n=== Test 4: Rapid Execution Sequence ===\n");
    
    for (int i = 0; i < 3; i++) {
        printf("🔄 Execution round %d\n", i + 1);
        
        FILE *f = fopen(TEST_BINARY, "w");
        fprintf(f, "#!/bin/bash\necho 'Rapid execution %d'\n", i);
        fclose(f);
        chmod(TEST_BINARY, 0755);
        
        if (fork() == 0) {
            execl(TEST_BINARY, TEST_BINARY, NULL);
            exit(1);
        } else {
            wait(NULL);
        }
        
        usleep(100000); // 100ms between executions
    }
}

void test_false_positive_check() {
    printf("\n=== Test 5: Normal Execution (False Positive Check) ===\n");
    
    FILE *f = fopen(TEST_BINARY, "w");
    fprintf(f, "#!/bin/bash\necho '✅ Normal execution - should NOT trigger TOCTOU detection'\n");
    fclose(f);
    chmod(TEST_BINARY, 0755);
    
    printf("📝 NORMAL: Standard execution without race conditions\n");
    
    if (fork() == 0) {
        execl(TEST_BINARY, TEST_BINARY, NULL);
        exit(1);
    } else {
        wait(NULL);
    }
}

int main() {
    printf("🛡️  TOCTOU Attack Simulation Test Suite 🛡️\n");
    printf("==========================================\n");
    printf("Make sure your eBPF detector is running!\n");
    printf("Watch for TOCTOU detection messages...\n");
    
    sleep(2);
    
    // Run all tests
    test_basic_toctou();
    sleep(2);
    
    test_symlink_toctou();
    sleep(2);
    
    test_multithreaded_toctou();
    sleep(2);
    
    test_rapid_execution();
    sleep(2);
    
    test_false_positive_check();
    
    // Final cleanup
    unlink(TEST_BINARY);
    
    printf("\n🎯 All tests completed!\n");
    printf("Check your detector output and kernel logs:\n");
    printf("  sudo dmesg | tail -20\n");
    
    return 0;
}
