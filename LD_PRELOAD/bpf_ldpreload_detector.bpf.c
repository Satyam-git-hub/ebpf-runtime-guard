#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";
// why bother reading the code? it's just a simple BPF program
// that detects LD_PRELOAD and TOCTOU attacks with strict bounds checking. 
//dont trust me? just read the code and see for yourself.:->

// Helper functions with strict bounds checking
static inline int safe_strstr(char *haystack, char *needle, int haystack_max) {
    int needle_len = 0;
    
    // Calculate needle length with bounds
    while (needle[needle_len] && needle_len < 16) needle_len++;
    
    // Search with strict bounds checking
    for (int i = 0; i < haystack_max - needle_len && i < 256; i++) {
        if (haystack[i] == '\0') break;
        
        int match = 1;
        for (int j = 0; j < needle_len; j++) {
            if (haystack[i + j] != needle[j]) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

static inline void safe_zero_memory(void *ptr, int size) {
    char *p = (char *)ptr;
    // Strict bounds to prevent overflow
    for (int i = 0; i < size && i < 512; i++) {
        p[i] = 0;
    }
}

// Reduced event structure to minimize memory usage
struct security_event {
    __u32 pid;
    __u32 uid;
    __u32 attack_type;
    char binary_path[64];   // Reduced from 128
    char preload_lib[64];   // Reduced from 128
    char env_value[128];    // Reduced from 256
    __u64 timestamp;
    __u8 risk_level;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} security_events SEC(".maps");

// Minimal process tracking
struct process_info {
    char syscall_path[64];  // Reduced size
    __u64 syscall_time;
    __u32 uid;
    __u8 has_syscall_path;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32);
    __type(value, struct process_info);
} process_tracker SEC(".maps");

// Per-CPU arrays for large buffers (avoiding stack)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[256]);  // Reduced from 512
} env_buffer SEC(".maps");

// Safe environment variable reader with strict bounds
static inline int safe_read_env_var(char *envp[], const char *var_name, 
                                   char *output, int max_len) {
    char temp_env[128] = {};  // Reduced stack usage
    
    // Limit environment variable scanning
    for (int i = 0; i < 32; i++) {  // Reduced from 64
        char *env_ptr = NULL;
        
        if (bpf_probe_read_user(&env_ptr, sizeof(env_ptr), &envp[i]) < 0) {
            break;
        }
        
        if (!env_ptr) break;
        
        // Safe string read with bounds
        if (bpf_probe_read_user_str(temp_env, sizeof(temp_env), env_ptr) <= 0) {
            continue;
        }
        
        // Check variable name match with bounds
        int var_len = 0;
        while (var_name[var_len] && var_len < 16) var_len++;
        
        int match = 1;
        for (int j = 0; j < var_len && j < 16; j++) {
            if (temp_env[j] != var_name[j]) {
                match = 0;
                break;
            }
        }
        
        if (match && temp_env[var_len] == '=') {
            // Safe value copy with strict bounds
            int value_start = var_len + 1;
            int copy_len = max_len - 1;
            if (copy_len > 127) copy_len = 127;  // Safety limit
            
            for (int k = 0; k < copy_len; k++) {
                if (value_start + k >= 128) break;  // Prevent overflow
                if (!temp_env[value_start + k]) break;
                output[k] = temp_env[value_start + k];
            }
            return 1;
        }
    }
    
    return 0;
}

// Enhanced syscall monitor with verifier-safe operations
SEC("tp/syscalls/sys_enter_execve")
int safe_execve_monitor(struct trace_event_raw_sys_enter* ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 current_time = bpf_ktime_get_ns();
    
    // Use minimal stack variables
    struct process_info proc_info = {};
    proc_info.syscall_time = current_time;
    proc_info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // Capture binary path safely
    char *filename_arg = (char *)ctx->args[0];
    long ret = bpf_probe_read_user_str(proc_info.syscall_path, 
                                      sizeof(proc_info.syscall_path), 
                                      filename_arg);
    if (ret > 0) {
        proc_info.has_syscall_path = 1;
    }
    
    bpf_map_update_elem(&process_tracker, &pid, &proc_info, BPF_ANY);
    
    // LD_PRELOAD Detection with map-based buffer
    char **envp = (char **)ctx->args[2];
    __u32 zero = 0;
    char *env_buffer_ptr = bpf_map_lookup_elem(&env_buffer, &zero);
    
    if (!env_buffer_ptr) return 0;
    
    safe_zero_memory(env_buffer_ptr, 256);
    
    // Check for LD_PRELOAD with safe bounds
    int has_ld_preload = safe_read_env_var(envp, "LD_PRELOAD", env_buffer_ptr, 256);
    
    if (has_ld_preload) {
        struct security_event *event = bpf_ringbuf_reserve(&security_events, sizeof(*event), 0);
        if (!event) return 0;
        
        safe_zero_memory(event, sizeof(*event));
        event->pid = pid;
        event->uid = proc_info.uid;
        event->attack_type = 2; // LD_PRELOAD
        event->timestamp = current_time;
        event->risk_level = 7;
        
        // Safe memory copying with bounds
        __builtin_memcpy(event->binary_path, proc_info.syscall_path, 
                        sizeof(event->binary_path));
        __builtin_memcpy(event->preload_lib, env_buffer_ptr, 
                        sizeof(event->preload_lib));
        
        // Risk assessment with safe string operations
        if (safe_strstr(env_buffer_ptr, "/tmp/", 256) || 
            safe_strstr(env_buffer_ptr, "/dev/shm/", 256)) {
            event->risk_level = 9;
        }
        
        bpf_printk("🚨 LD_PRELOAD DETECTED! PID=%d", pid);
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

// Simplified TOCTOU detection LSM hook
SEC("lsm/bprm_check_security")
int BPF_PROG(safe_toctou_detector, struct linux_binprm *bprm)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 current_time = bpf_ktime_get_ns();
    
    char actual_path[64] = {};  // Minimal stack usage
    const char *filename = BPF_CORE_READ(bprm, filename);
    
    long ret = bpf_probe_read_kernel_str(actual_path, sizeof(actual_path), filename);
    if (ret <= 0) return 0;
    
    struct process_info *stored_context = bpf_map_lookup_elem(&process_tracker, &pid);
    
    if (stored_context && stored_context->has_syscall_path) {
        // Safe path comparison
        int path_differs = 0;
        for (int i = 0; i < 63; i++) {  // Safe bounds
            if (stored_context->syscall_path[i] != actual_path[i]) {
                path_differs = 1;
                break;
            }
            if (stored_context->syscall_path[i] == '\0') break;
        }
        
        if (path_differs) {
            struct security_event *event = bpf_ringbuf_reserve(&security_events, sizeof(*event), 0);
            if (event) {
                safe_zero_memory(event, sizeof(*event));
                event->pid = pid;
                event->uid = stored_context->uid;
                event->attack_type = 1; // TOCTOU
                event->timestamp = current_time;
                event->risk_level = 8;
                
                __builtin_memcpy(event->binary_path, actual_path, sizeof(actual_path));
                
                bpf_printk("🚨 TOCTOU ATTACK DETECTED! PID=%d", pid);
                bpf_ringbuf_submit(event, 0);
            }
        }
        
        bpf_map_delete_elem(&process_tracker, &pid);
    }
    
    return 0;
}
