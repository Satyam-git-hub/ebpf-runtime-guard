// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <signal.h>
// #include <string.h>
// #include <errno.h>
// #include <sys/resource.h>
// #include <time.h>
// #include <bpf/libbpf.h>
// #include <bpf/bpf.h>

// struct toctou_detection {
//     unsigned int pid;
//     unsigned int uid;
//     char original_path[256];
//     char executed_path[256];
//     unsigned char is_toctou_attack;
//     unsigned long long detection_time;
//     unsigned int time_gap_ms;
// };

// static volatile int running = 1;
// static int detection_count = 0;
// static int toctou_attacks_detected = 0;

// static void sig_handler(int sig) {
//     running = 0;
//     printf("\n🛑 Stopping TOCTOU detector...\n");
// }

// static const char* get_timestamp() {
//     static char timestamp[64];
//     time_t now = time(NULL);
//     struct tm *tm_info = localtime(&now);
//     strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm_info);
//     return timestamp;
// }

// static int handle_toctou_event(void *ctx, void *data, size_t data_sz) {
//     const struct toctou_detection *event = data;
//     detection_count++;
    
//     printf("\n[%s] 🔍 Detection Event #%d:\n", get_timestamp(), detection_count);
//     printf("  PID: %d | UID: %d | Gap: %u ms\n", 
//            event->pid, event->uid, event->time_gap_ms);
//     printf("  Original Path: %s\n", event->original_path);
//     printf("  Executed Path: %s\n", event->executed_path);
    
//     if (event->is_toctou_attack) {
//         toctou_attacks_detected++;
//         printf("  🚨 *** TOCTOU ATTACK DETECTED *** 🚨\n");
//         printf("  🔥 Attack #%d - File was modified between check and use!\n", 
//                toctou_attacks_detected);
//         printf("  ⚡ Timing gap: %u milliseconds\n", event->time_gap_ms);
//     } else {
//         printf("  ✅ Normal execution - No TOCTOU detected\n");
//     }
    
//     printf("  " "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─" "─\n");
    
//     return 0;
// }

// static int check_kernel_support() {
//     // Check LSM support
//     FILE *f = fopen("/sys/kernel/security/lsm", "r");
//     if (!f) {
//         printf("❌ Cannot access LSM information\n");
//         return -1;
//     }
    
//     char lsm_list[1024];
//     if (!fgets(lsm_list, sizeof(lsm_list), f)) {
//         fclose(f);
//         return -1;
//     }
//     fclose(f);
    
//     if (!strstr(lsm_list, "bpf")) {
//         printf("❌ BPF LSM is not active. Current LSMs: %s", lsm_list);
//         printf("💡 Add 'lsm=...,bpf' to kernel boot parameters\n");
//         return -1;
//     }
    
//     printf("✅ BPF LSM is active: %s", lsm_list);
//     return 0;
// }

// int main(int argc, char **argv) {
//     struct bpf_object *obj;
//     struct bpf_program *prog;
//     struct bpf_link *links[10] = {};
//     struct bpf_map *events_map;
//     struct ring_buffer *rb;
//     int err, link_count = 0;
    
//     printf("🛡️  Enhanced TOCTOU Detection System v2.0 🛡️\n");
//     printf("=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=\n");
    
//     // Check kernel support
//     if (check_kernel_support() < 0) {
//         return 1;
//     }
    
//     // Set resource limits
//     struct rlimit rlim_new = {
//         .rlim_cur = RLIM_INFINITY,
//         .rlim_max = RLIM_INFINITY,
//     };
    
//     if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
//         fprintf(stderr, "❌ Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
//         return 1;
//     }
    
//     signal(SIGINT, sig_handler);
//     signal(SIGTERM, sig_handler);
    
//     // Load eBPF object
//     obj = bpf_object__open_file("bpf_toctou_detector.o", NULL);
//     if (libbpf_get_error(obj)) {
//         fprintf(stderr, "❌ Failed to open eBPF object: %s\n", strerror(errno));
//         return 1;
//     }
    
//     err = bpf_object__load(obj);
//     if (err) {
//         fprintf(stderr, "❌ Failed to load eBPF object: %s\n", strerror(-err));
//         bpf_object__close(obj);
//         return 1;
//     }
    
//     printf("📦 eBPF programs loaded successfully\n");
    
//     // Attach all programs
//     bpf_object__for_each_program(prog, obj) {
//         const char *prog_name = bpf_program__name(prog);
//         enum bpf_prog_type prog_type = bpf_program__type(prog);
        
//         printf("🔗 Attaching: %s (type: %d)... ", prog_name, prog_type);
//         fflush(stdout);
        
//         if (prog_type == BPF_PROG_TYPE_LSM) {
//             links[link_count] = bpf_program__attach_lsm(prog);
//         } else {
//             links[link_count] = bpf_program__attach(prog);
//         }
        
//         if (libbpf_get_error(links[link_count])) {
//             printf("❌ FAILED\n");
//             fprintf(stderr, "Error: %s\n", strerror(-libbpf_get_error(links[link_count])));
            
//             // Cleanup on failure
//             for (int i = 0; i < link_count; i++) {
//                 bpf_link__destroy(links[i]);
//             }
//             bpf_object__close(obj);
//             return 1;
//         }
        
//         printf("✅ SUCCESS\n");
//         link_count++;
//     }
    
//     printf("🎯 All programs attached successfully!\n\n");
    
//     // Set up event monitoring
//     events_map = bpf_object__find_map_by_name(obj, "toctou_events");
//     if (!events_map) {
//         fprintf(stderr, "❌ Failed to find events map\n");
//         goto cleanup;
//     }
    
//     rb = ring_buffer__new(bpf_map__fd(events_map), handle_toctou_event, NULL, NULL);
//     if (!rb) {
//         fprintf(stderr, "❌ Failed to create ring buffer\n");
//         goto cleanup;
//     }
    
//     printf("🔍 TOCTOU Detection Active - Monitoring all executions...\n");
//     printf("📊 Statistics will be shown for each detection event\n");
//     printf("🚨 TOCTOU attacks will be highlighted with alerts\n");
//     printf("\nPress Ctrl+C to stop monitoring.\n");
//     printf("=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=" "=\n");
    
//     // Event monitoring loop
//     while (running) {
//         err = ring_buffer__poll(rb, 100);
//         if (err == -EINTR) {
//             break;
//         }
//         if (err < 0) {
//             printf("❌ Ring buffer polling error: %d\n", err);
//             break;
//         }
//     }
    
//     // Print final statistics
//     printf("\n📊 Final Detection Statistics:\n");
//     printf("  Total Events: %d\n", detection_count);
//     printf("  TOCTOU Attacks Detected: %d\n", toctou_attacks_detected);
//     if (detection_count > 0) {
//         printf("  Attack Rate: %.1f%%\n", 
//                (float)toctou_attacks_detected / detection_count * 100);
//     }
    
// cleanup:
//     if (rb) ring_buffer__free(rb);
    
//     for (int i = 0; i < link_count; i++) {
//         bpf_link__destroy(links[i]);
//     }
    
//     bpf_object__close(obj);
//     printf("\n🛡️  TOCTOU detector stopped successfully.\n");
    
//     return 0;
// }


// try 4 loader
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// Match your eBPF program's event structure
struct toctou_event {
    unsigned int pid;
    unsigned int uid;
    char syscall_path[256];
    char actual_path[256];
    unsigned char is_toctou;
    unsigned long long timestamp;
    unsigned int tgid;
};

static volatile int running = 1;
static int detection_count = 0;
static int toctou_attacks_detected = 0;

static void sig_handler(int sig) {
    running = 0;
    printf("\n🛑 Stopping TOCTOU detector...\n");
}

static const char* get_timestamp() {
    static char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm_info);
    return timestamp;
}

static int handle_toctou_event(void *ctx, void *data, size_t data_sz) {
    const struct toctou_event *e = data;
    detection_count++;
    
    printf("\n[%s] 🔍 Detection Event #%d:\n", get_timestamp(), detection_count);
    printf("  PID: %d | UID: %d | TGID: %d\n", e->pid, e->uid, e->tgid);
    printf("  Syscall Path: %s\n", e->syscall_path);
    printf("  Actual Path:  %s\n", e->actual_path);
    
    if (e->is_toctou) {
        toctou_attacks_detected++;
        printf("  🚨 *** TOCTOU ATTACK DETECTED *** 🚨\n");
        printf("  🔥 Attack #%d - modified between check and use!\n", 
               toctou_attacks_detected);
        printf("  ⚡ Timestamp: %llu\n", e->timestamp);
    } else {
        printf("  ✅ Normal execution - No TOCTOU detected\n");
    }
    
    printf("  ──────────────────────────────────────────────────\n");
    return 0;
}

static int check_lsm_support() {
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) {
        printf(" Cannot access LSM information\n");
        return -1;
    }
    
    char lsm_list[1024];
    if (!fgets(lsm_list, sizeof(lsm_list), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    
    if (!strstr(lsm_list, "bpf")) {
        printf(" BPF LSM is not active. Current LSMs: %s", lsm_list);
        return -1;
    }
    
    printf("✅ BPF LSM is active: %s", lsm_list);
    return 0;
}

// Enhanced map finder that tries multiple possible names
static struct bpf_map* find_events_map(struct bpf_object *obj) {
    const char* possible_names[] = {
        "events",                    // Original name
        "toctou_events",            // Standard name
        "enhanced_toctou_events",   // Enhanced version name
        NULL
    };
    
    struct bpf_map *map = NULL;
    
    for (int i = 0; possible_names[i] != NULL; i++) {
        map = bpf_object__find_map_by_name(obj, possible_names[i]);
        if (map) {
            printf("✅ Found events map: '%s'\n", possible_names[i]);
            return map;
        } else {
            printf("⚠️  Map '%s' not found, trying next...\n", possible_names[i]);
        }
    }
    
    return NULL;
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link **links = NULL;
    struct bpf_map *events_map = NULL;
    struct ring_buffer *rb = NULL;
    int err, link_count = 0;
    
    printf("🛡️  Enhanced TOCTOU Detection System v2.0 🛡️\n");
    printf("==================================================\n");
    
    // Check kernel support
    if (check_lsm_support() < 0) {
        return 1;
    }
    
    // Set resource limits
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "❌ Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return 1;
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Open eBPF object
    obj = bpf_object__open_file("bpf_toctou_detector.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "❌ Failed to open eBPF object: %s\n", strerror(errno));
        return 1;
    }
    
    // Load eBPF object
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "❌ Failed to load eBPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    
    printf("📦 eBPF programs loaded successfully\n");
    
    // Count programs and allocate links array
    int prog_count = 0;
    bpf_object__for_each_program(prog, obj) {
        prog_count++;
    }
    
    links = calloc(prog_count, sizeof(struct bpf_link*));
    if (!links) {
        fprintf(stderr, "❌ Failed to allocate links array\n");
        bpf_object__close(obj);
        return 1;
    }
    
    // Attach all programs
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);
        enum bpf_prog_type prog_type = bpf_program__type(prog);
        
        printf("🔗 Attaching: %s (type: %d)... ", prog_name, prog_type);
        fflush(stdout);
        
        if (prog_type == BPF_PROG_TYPE_LSM) {
            links[link_count] = bpf_program__attach_lsm(prog);
        } else {
            links[link_count] = bpf_program__attach(prog);
        }
        
        if (libbpf_get_error(links[link_count])) {
            printf("❌ FAILED\n");
            fprintf(stderr, "Error: %s\n", strerror(-libbpf_get_error(links[link_count])));
            goto cleanup;
        }
        
        printf("✅ SUCCESS\n");
        link_count++;
    }
    
    printf("🎯 All programs attached successfully!\n\n");
    
    // *** FIX: Use enhanced map finder ***
    events_map = find_events_map(obj);
    if (!events_map) {
        fprintf(stderr, "❌ Failed to find any events map. Available maps:\n");
        
        // List all available maps for debugging
        struct bpf_map *map;
        bpf_object__for_each_map(map, obj) {
            printf("  📋 Available map: '%s'\n", bpf_map__name(map));
        }
        goto cleanup;
    }
    
    // Create ring buffer
    rb = ring_buffer__new(bpf_map__fd(events_map), handle_toctou_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "❌ Failed to create ring buffer\n");
        goto cleanup;
    }
    
    printf("🔍 TOCTOU Detection Active - Monitoring all executions...\n");
    printf("📊 Statistics will be shown for each detection event\n");
    printf("🚨 TOCTOU attacks will be highlighted with alerts\n");
    printf("\nPress Ctrl+C to stop monitoring.\n");
    printf("==================================================\n");
    
    // Event monitoring loop
    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            printf("❌ Ring buffer polling error: %d\n", err);
            break;
        }
    }
    
    // Print final statistics
    printf("\n📊 Final Detection Statistics:\n");
    printf("  Total Events: %d\n", detection_count);
    printf("  TOCTOU Attacks Detected: %d\n", toctou_attacks_detected);
    if (detection_count > 0) {
        printf("  Attack Rate: %.1f%%\n", 
               (float)toctou_attacks_detected / detection_count * 100);
    }

cleanup:
    if (rb) ring_buffer__free(rb);
    
    if (links) {
        for (int i = 0; i < link_count; i++) {
            if (links[i]) bpf_link__destroy(links[i]);
        }
        free(links);
    }
    
    if (obj) bpf_object__close(obj);
    
    printf("\n🛡️  TOCTOU detector stopped successfully.\n");
    return 0;
}
