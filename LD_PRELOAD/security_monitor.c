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

// Match your eBPF program's event structure exactly
struct security_event {
    unsigned int pid;
    unsigned int uid;
    unsigned int attack_type;      // 1=TOCTOU, 2=LD_PRELOAD, 3=LD_LIBRARY_PATH
    char binary_path[256];
    char preload_lib[256];
    char env_value[512];
    unsigned long long timestamp;
    unsigned char risk_level;      // 1-10 risk assessment
};

static volatile int running = 1;
static int total_events = 0;
static int toctou_attacks = 0;
static int preload_detections = 0;

static void sig_handler(int sig) {
    running = 0;
    printf("\n🛑 Stopping security monitor...\n");
}

static const char* get_attack_type_name(unsigned int type) {
    switch(type) {
        case 1: return "TOCTOU ATTACK";
        case 2: return "LD_PRELOAD INJECTION";
        case 3: return "LD_LIBRARY_PATH MANIPULATION";
        case 4: return "SUSPICIOUS DLOPEN";
        default: return "UNKNOWN";
    }
}

static const char* get_risk_level_desc(unsigned char level) {
    if (level >= 8) return "CRITICAL";
    if (level >= 6) return "HIGH";
    if (level >= 4) return "MEDIUM";
    return "LOW";
}

static const char* get_timestamp() {
    static char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm_info);
    return timestamp;
}

static int handle_security_event(void *ctx, void *data, size_t data_sz) {
    const struct security_event *e = data;
    total_events++;
    
    printf("\n[%s] 🔍 Security Event #%d:\n", get_timestamp(), total_events);
    printf("  Timestamp: %llu\n", e->timestamp);
    printf("  PID: %d | UID: %d\n", e->pid, e->uid);
    printf("  Binary: %s\n", e->binary_path);
    printf("  Attack Type: %s\n", get_attack_type_name(e->attack_type));
    printf("  Risk Level: %s (%d/10)\n", get_risk_level_desc(e->risk_level), e->risk_level);
    
    if (e->attack_type == 1) {
        // TOCTOU attack
        toctou_attacks++;
        printf("  🚨 FILE MODIFICATION DETECTED DURING EXECUTION\n");
        
    } else if (e->attack_type == 2) {
        // LD_PRELOAD
        preload_detections++;
        printf("  🔍 LD_PRELOAD Library: %s\n", e->preload_lib);
        printf("  🚨 SHARED LIBRARY INJECTION DETECTED\n");
        
        if (strstr(e->preload_lib, "/tmp/") || strstr(e->preload_lib, "/dev/shm/")) {
            printf("  ⚠️  SUSPICIOUS PATH: Library in temporary directory!\n");
        }
        
    } else if (e->attack_type == 3) {
        // LD_LIBRARY_PATH
        preload_detections++;
        printf("  🔍 LD_LIBRARY_PATH: %s\n", e->env_value);
        printf("  🚨 LIBRARY PATH MANIPULATION DETECTED\n");
        
    } else if (e->attack_type == 4) {
        // Suspicious dlopen
        printf("  🔍 Suspicious Library: %s\n", e->preload_lib);
        printf("  🚨 RUNTIME LIBRARY LOADING FROM SUSPICIOUS LOCATION\n");
    }
    
    printf("  ────────────────────────────────────────────\n");
    return 0;
}

static int check_lsm_support() {
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) {
        printf("❌ Cannot access LSM information\n");
        return -1;
    }
    
    char lsm_list[1024];
    if (!fgets(lsm_list, sizeof(lsm_list), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    
    if (!strstr(lsm_list, "bpf")) {
        printf("❌ BPF LSM is not active. Current LSMs: %s", lsm_list);
        printf("💡 Add 'lsm=...,bpf' to kernel boot parameters\n");
        return -1;
    }
    
    printf("✅ BPF LSM is active: %s", lsm_list);
    return 0;
}

// Enhanced map finder that tries multiple possible names
static struct bpf_map* find_events_map(struct bpf_object *obj) {
    const char* possible_names[] = {
        "security_events",              // Enhanced version name
        "enhanced_toctou_events",       // Alternative name
        "events",                       // Original name
        "toctou_events",               // Standard name
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
    struct ring_buffer *rb = NULL;  // *** FIX: Properly declare rb ***
    int err, link_count = 0;
    
    printf("🛡️  Comprehensive Security Monitor v3.0 🛡️\n");
    printf("============================================\n");
    printf("Monitoring for:\n");
    printf("  • TOCTOU attacks (file content modification)\n");
    printf("  • LD_PRELOAD library injection\n");
    printf("  • LD_LIBRARY_PATH manipulation\n");
    printf("  • Suspicious runtime library loading\n\n");
    
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
    
    // *** FIX: Register signal handler ***
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Open eBPF object
    obj = bpf_object__open_file("bpf_ldpreload_detector.o", NULL);
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
    
    // *** FIX: Find events map with enhanced finder ***
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
    
    // *** FIX: Create ring buffer with proper callback ***
    rb = ring_buffer__new(bpf_map__fd(events_map), handle_security_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "❌ Failed to create ring buffer\n");
        goto cleanup;
    }
    
    printf("🔍 Security monitoring active...\n");
    printf("Press Ctrl+C to stop monitoring.\n");
    printf("════════════════════════════════════════════\n");
    
    // *** FIX: Event monitoring loop with properly declared rb ***
    while (running) {
        err = ring_buffer__poll(rb, 100);  // rb is now properly declared and initialized
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            printf("❌ Ring buffer polling error: %d\n", err);
            break;
        }
    }
    
    // Print final statistics
    printf("\n📊 Security Detection Summary:\n");
    printf("  Total Events: %d\n", total_events);
    printf("  TOCTOU Attacks: %d\n", toctou_attacks);
    printf("  Library Injections: %d\n", preload_detections);
    if (total_events > 0) {
        printf("  Overall Detection Rate: %.1f%%\n", 
               (float)(toctou_attacks + preload_detections) / total_events * 100);
    }

cleanup:
    // Cleanup resources
    if (rb) {
        ring_buffer__free(rb);
    }
    
    if (links) {
        for (int i = 0; i < link_count; i++) {
            if (links[i]) {
                bpf_link__destroy(links[i]);
            }
        }
        free(links);
    }
    
    if (obj) {
        bpf_object__close(obj);
    }
    
    printf("\n🛡️  Security monitor stopped successfully.\n");
    return 0;
}
