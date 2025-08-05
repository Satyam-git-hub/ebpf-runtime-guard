#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>

#define TEST_BINARY "/tmp/toctou_test_binary"
#define BACKUP_BINARY "/tmp/backup_binary"

// Test 1: Basic Content Modification TOCTOU (size/mtime change)
void test_basic_content_toctou() {
    printf("\n=== Test 1: Basic Content Modification TOCTOU ===\n");
    
    // Create initial small binary
    FILE *f = fopen(TEST_BINARY, "w");
    fprintf(f, "#!/bin/bash\necho 'Original small content'\n");
    fclose(f);
    chmod(TEST_BINARY, 0755);
    
    if (fork() == 0) {
        // Child process: Replace with larger content (changes size and mtime)
        usleep(25000); // 25ms delay
        printf("🔥 ATTACK: Replacing with larger malicious content\n");
        
        f = fopen(TEST_BINARY, "w");
        fprintf(f, "#!/bin/bash\n"
                  "echo '💀 MALICIOUS CONTENT MODIFICATION ATTACK!'\n"
                  "echo 'This is much longer content that changes file size and mtime'\n"
                  "echo 'Should trigger size and mtime change detection'\n");
        fclose(f);
        exit(0);
    } else {
        // Parent: Execute the binary after small delay
        usleep(50000); // 50ms delay
        printf("📋 VICTIM: Executing binary after content modification\n");
        
        if (fork() == 0) {
            execl(TEST_BINARY, TEST_BINARY, NULL);
            exit(1);
        } else {
            wait(NULL);
        }
        wait(NULL);
    }
}

// Test 2: File Replacement TOCTOU (inode change)
void test_file_replacement_toctou() {
    printf("\n=== Test 2: File Replacement TOCTOU (Inode Change) ===\n");
    
    // Create initial binary
    FILE *f = fopen(TEST_BINARY, "w");
    fprintf(f, "#!/bin/bash\necho 'Original file with original inode'\n");
    fclose(f);
    chmod(TEST_BINARY, 0755);
    
    // Create replacement binary with different content
    f = fopen(BACKUP_BINARY, "w");
    fprintf(f, "#!/bin/bash\necho '🔄 MALICIOUS: File replacement attack (different inode)!'\n");
    fclose(f);
    chmod(BACKUP_BINARY, 0755);
    
    if (fork() == 0) {
        // Child: Replace file entirely (different inode)
        usleep(25000); // 25ms delay
        printf("🔄 ATTACK: Replacing file with different inode\n");
        
        unlink(TEST_BINARY);                    // Remove original
        rename(BACKUP_BINARY, TEST_BINARY);     // Replace with different file (new inode)
        exit(0);
    } else {
        // Parent: Execute after replacement
        usleep(50000); // 50ms delay
        printf("📋 VICTIM: Executing replaced file\n");
        
        if (fork() == 0) {
            execl(TEST_BINARY, TEST_BINARY, NULL);
            exit(1);
        } else {
            wait(NULL);
        }
        wait(NULL);
    }
}

// Test 3: Symlink TOCTOU with Content Change
void test_symlink_content_toctou() {
    printf("\n=== Test 3: Symlink TOCTOU with Content Change ===\n");
    
    // Create good target with small content
    FILE *f1 = fopen("/tmp/good_target", "w");
    fprintf(f1, "#!/bin/bash\necho 'Good content'\n");
    fclose(f1);
    chmod("/tmp/good_target", 0755);
    
    // Create bad target with different size content
    FILE *f2 = fopen("/tmp/bad_target", "w");
    fprintf(f2, "#!/bin/bash\n"
              "echo '🚨 SYMLINK CONTENT ATTACK SUCCESS!'\n"
              "echo 'Different content size and mtime from good target'\n");
    fclose(f2);
    chmod("/tmp/bad_target", 0755);
    
    // Create symlink to good target
    symlink("/tmp/good_target", TEST_BINARY);
    
    if (fork() == 0) {
        // Child: Race to change symlink target
        usleep(30000);
        printf("🔗 ATTACK: Changing symlink to different content file\n");
        unlink(TEST_BINARY);
        symlink("/tmp/bad_target", TEST_BINARY);
        exit(0);
    } else {
        // Parent: Execute through symlink
        usleep(60000);
        printf("🎯 VICTIM: Executing through modified symlink\n");
        
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

// Thread for content race
void* content_race_thread(void* arg) {
    usleep(40000); // 40ms
    printf("🏃 THREAD ATTACK: Multi-threaded content modification\n");
    
    FILE *f = fopen(TEST_BINARY, "w");
    fprintf(f, "#!/bin/bash\n"
              "echo '🧵 THREAD CONTENT RACE ATTACK!'\n"
              "echo 'Modified by thread - different size and mtime'\n");
    fclose(f);
    return NULL;
}

// Test 4: Multi-threaded Content Modification
void test_multithreaded_content_toctou() {
    printf("\n=== Test 4: Multi-threaded Content Modification ===\n");
    
    // Create small original file
    FILE *f = fopen(TEST_BINARY, "w");
    fprintf(f, "#!/bin/bash\necho 'Small original'\n");
    fclose(f);
    chmod(TEST_BINARY, 0755);
    
    pthread_t thread;
    pthread_create(&thread, NULL, content_race_thread, NULL);
    
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

// Test 5: Rapid Content Changes (Multiple Mtime Updates)
void test_rapid_content_changes() {
    printf("\n=== Test 5: Rapid Content Changes ===\n");
    
    // Create initial file
    FILE *f = fopen(TEST_BINARY, "w");
    fprintf(f, "#!/bin/bash\necho 'Initial version'\n");
    fclose(f);
    chmod(TEST_BINARY, 0755);
    
    if (fork() == 0) {
        // Child: Rapid modifications with increasing content size
        usleep(15000); // 15ms delay
        printf("🚀 ATTACK: Rapid content modifications\n");
        
        for (int i = 1; i <= 2; i++) {
            f = fopen(TEST_BINARY, "w");
            fprintf(f, "#!/bin/bash\n"
                      "echo '🔄 RAPID ATTACK VERSION %d'\n"
                      "echo 'Size increases with each modification - iteration %d'\n", i, i);
            fclose(f);
            usleep(5000); // 5ms between modifications
        }
        exit(0);
    } else {
        // Parent: Execute during modifications
        usleep(25000); // 25ms delay
        printf("📋 VICTIM: Executing during rapid modifications\n");
        
        if (fork() == 0) {
            execl(TEST_BINARY, TEST_BINARY, NULL);
            exit(1);
        } else {
            wait(NULL);
        }
        wait(NULL);
    }
}

// Test 6: Same Size, Different Content (Mtime Change Only)
void test_same_size_content_change() {
    printf("\n=== Test 6: Same Size Content Change (Mtime Only) ===\n");
    
    // Create file with specific content length
    FILE *f = fopen(TEST_BINARY, "w");
    fprintf(f, "#!/bin/bash\necho 'SAFE_CONTENT_EXACT_SIZE_HERE'\n");
    fclose(f);
    chmod(TEST_BINARY, 0755);
    
    if (fork() == 0) {
        // Child: Change content but keep same approximate size
        usleep(25000); // 25ms delay
        printf("📏 ATTACK: Changing content same size (mtime change)\n");
        
        f = fopen(TEST_BINARY, "w");
        fprintf(f, "#!/bin/bash\necho 'EVIL_CONTENT_EXACT_SIZE_HERE'\n");
        fclose(f);
        exit(0);
    } else {
        // Parent: Execute after content change
        usleep(50000); // 50ms delay
        printf("📋 VICTIM: Executing after same-size content change\n");
        
        if (fork() == 0) {
            execl(TEST_BINARY, TEST_BINARY, NULL);
            exit(1);
        } else {
            wait(NULL);
        }
        wait(NULL);
    }
}

// Test 7: Control Test (No Changes)
void test_normal_execution() {
    printf("\n=== Test 7: Normal Execution (Control Test) ===\n");
    
    FILE *f = fopen(TEST_BINARY, "w");
    fprintf(f, "#!/bin/bash\necho '✅ Normal execution - no race conditions'\n");
    fclose(f);
    chmod(TEST_BINARY, 0755);
    
    printf("📝 CONTROL: Standard execution without any modifications\n");
    
    if (fork() == 0) {
        execl(TEST_BINARY, TEST_BINARY, NULL);
        exit(1);
    } else {
        wait(NULL);
    }
}

int main() {
    printf("🛡️  Enhanced TOCTOU Content Detection Test Suite 🛡️\n");
    printf("====================================================\n");
    printf("🎯 Tests file content change detection capabilities:\n");
    printf("  - Content modification (size/mtime changes)\n");
    printf("  - File replacement (inode changes)\n");
    printf("  - Multi-threaded content races\n");
    printf("  - Rapid content modifications\n");
    printf("\nMake sure your enhanced eBPF detector is running!\n");
    printf("Watch for content-based TOCTOU detection messages...\n");
    
    sleep(2);
    
    // Run enhanced tests
    test_basic_content_toctou();
    sleep(2);
    
    test_file_replacement_toctou();
    sleep(2);
    
    test_symlink_content_toctou();
    sleep(2);
    
    test_multithreaded_content_toctou();
    sleep(2);
    
    test_rapid_content_changes();
    sleep(2);
    
    test_same_size_content_change();
    sleep(2);
    
    test_normal_execution();
    
    // Final cleanup
    unlink(TEST_BINARY);
    unlink(BACKUP_BINARY);
    
    printf("\n🎯 Enhanced content detection tests completed!\n");
    printf("\n📊 Expected detections:\n");
    printf("  🔥 Test 1: SIZE + MTIME change detection\n");
    printf("  🔄 Test 2: INODE change detection\n");
    printf("  🔗 Test 3: SYMLINK + CONTENT change detection\n");
    printf("  🧵 Test 4: THREAD + CONTENT change detection\n");
    printf("  🚀 Test 5: RAPID MTIME changes detection\n");
    printf("  📏 Test 6: MTIME-only change detection\n");
    printf("  ❌ Test 7: NO detection (control)\n");
    printf("\nCheck your detector output and kernel logs:\n");
    printf("  sudo dmesg | tail -30\n");
    printf("  sudo cat /sys/kernel/debug/tracing/trace_pipe | grep -E '(CONTENT|SIZE|INODE|MTIME)'\n");
    
    return 0;
}
