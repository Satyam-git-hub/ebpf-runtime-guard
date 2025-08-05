#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>

#define TEST_BINARY "/tmp/enhanced_toctou_test"
#define ATTACK_DELAY 10000  // 10ms - shorter window

void run_enhanced_toctou_test() {
    printf("🎯 Enhanced TOCTOU Test - Aggressive Race Condition\n");
    
    // Create initial legitimate binary
    FILE *f = fopen(TEST_BINARY, "w");
    if (!f) {
        perror("Failed to create test binary");
        return;
    }
    fprintf(f, "#!/bin/bash\necho 'LEGITIMATE: Original program execution'\n");
    fclose(f);
    chmod(TEST_BINARY, 0755);
    
    printf("📝 Created legitimate binary: %s\n", TEST_BINARY);
    
    pid_t race_pid = fork();
    if (race_pid == 0) {
        // Child: Aggressive race attack
        printf("🔥 ATTACKER: Starting race attack...\n");
        usleep(ATTACK_DELAY);
        
        // Overwrite with malicious content
        f = fopen(TEST_BINARY, "w");
        if (f) {
            fprintf(f, "#!/bin/bash\necho '💀 MALICIOUS: Attack successful! File was replaced during execution!'\n");
            fclose(f);
            printf("🚨 ATTACKER: Binary replaced with malicious payload!\n");
        }
        exit(0);
    } else {
        // Parent: Victim execution
        usleep(ATTACK_DELAY * 2); // Give attacker time to set up race
        
        printf("👤 VICTIM: Attempting to execute trusted binary...\n");
        
        pid_t exec_pid = fork();
        if (exec_pid == 0) {
            // Execute the binary
            printf("🚀 VICTIM: Executing %s\n", TEST_BINARY);
            execl(TEST_BINARY, TEST_BINARY, NULL);
            perror("execl failed");
            exit(1);
        } else {
            int status;
            waitpid(exec_pid, &status, 0);
            printf("✅ Execution completed (exit code: %d)\n", WEXITSTATUS(status));
        }
        
        // Wait for race process
        waitpid(race_pid, NULL, 0);
    }
}

void run_symlink_attack() {
    printf("\n🔗 Enhanced Symlink TOCTOU Attack\n");
    
    // Create legitimate target
    FILE *f = fopen("/tmp/legitimate_target", "w");
    fprintf(f, "#!/bin/bash\necho 'LEGITIMATE: Safe program'\n");
    fclose(f);
    chmod("/tmp/legitimate_target", 0755);
    
    // Create malicious target
    f = fopen("/tmp/malicious_target", "w");
    fprintf(f, "#!/bin/bash\necho '💀 MALICIOUS: Symlink attack succeeded!'\n");
    fclose(f);
    chmod("/tmp/malicious_target", 0755);
    
    // Create initial symlink to legitimate target
    unlink(TEST_BINARY);
    symlink("/tmp/legitimate_target", TEST_BINARY);
    
    printf("🎯 Created symlink: %s -> /tmp/legitimate_target\n", TEST_BINARY);
    
    pid_t attack_pid = fork();
    if (attack_pid == 0) {
        // Attacker: Change symlink target
        usleep(5000); // 5ms
        printf("🔗 ATTACKER: Changing symlink target to malicious binary\n");
        unlink(TEST_BINARY);
        symlink("/tmp/malicious_target", TEST_BINARY);
        exit(0);
    } else {
        // Victim: Execute through symlink
        usleep(10000); // 10ms
        printf("👤 VICTIM: Executing through symlink\n");
        
        pid_t exec_pid = fork();
        if (exec_pid == 0) {
            execl(TEST_BINARY, TEST_BINARY, NULL);
            exit(1);
        } else {
            int status;
            waitpid(exec_pid, &status, 0);
        }
        
        waitpid(attack_pid, NULL, 0);
    }
    
    // Cleanup
    unlink(TEST_BINARY);
    unlink("/tmp/legitimate_target");
    unlink("/tmp/malicious_target");
}

int main() {
    printf("🛡️ Enhanced TOCTOU Attack Test Suite 🛡️\n");
    printf("========================================\n");
    printf("This test creates more aggressive race conditions\n");
    printf("Watch your detector terminal for TOCTOU alerts!\n\n");
    
    sleep(2);
    
    // Run enhanced tests
    run_enhanced_toctou_test();
    sleep(2);
    
    run_symlink_attack();
    
    printf("\n🎯 Enhanced tests completed!\n");
    printf("Check detector output for TOCTOU DETECTED messages\n");
    
    return 0;
}
