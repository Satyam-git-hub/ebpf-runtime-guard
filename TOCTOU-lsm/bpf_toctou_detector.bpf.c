// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

// char LICENSE[] SEC("license") = "GPL";

// // Map to store syscall arguments for comparison
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 1024);
//     __type(key, __u32);   // PID
//     __type(value, char[256]);
// } syscall_args SEC(".maps");

// // Map to store detection results
// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 256 * 1024);
// } events SEC(".maps");

// struct toctou_event {
//     __u32 pid;
//     __u32 uid;
//     char syscall_path[256];
//     char actual_path[256];
//     __u8 is_toctou;
//     __u64 timestamp;
// };

// // Syscall tracepoint to capture original arguments
// SEC("tp/syscalls/sys_enter_execve")
// int trace_execve_enter(void *ctx)
// {
//     struct trace_event_raw_sys_enter *args = ctx;
//     __u32 pid = bpf_get_current_pid_tgid() >> 32;
//     char *filename = (char *)BPF_CORE_READ(args, args[0]);
//     char path[256] = {};
    
//     if (bpf_probe_read_user_str(path, sizeof(path), filename) > 0) {
//         bpf_map_update_elem(&syscall_args, &pid, path, BPF_ANY);
//     }
    
//     return 0;
// }

// // LSM hook to capture actual execution
// SEC("lsm/bprm_check_security")
// int BPF_PROG(toctou_lsm_hook, struct linux_binprm *bprm)
// {
//     struct toctou_event *event;
//     __u32 pid = bpf_get_current_pid_tgid() >> 32;
//     __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//     char actual_path[256] = {};
//     char *stored_path;
    
//     // Get the actual filename that kernel is about to execute
//     const char *filename = BPF_CORE_READ(bprm, filename);
//     bpf_probe_read_kernel_str(actual_path, sizeof(actual_path), filename);
    
//     // Look up the original syscall argument
//     stored_path = bpf_map_lookup_elem(&syscall_args, &pid);
    
//     // Reserve space in ring buffer
//     event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
//     if (!event) {
//         return 0;
//     }
    
//     event->pid = pid;
//     event->uid = uid;
//     event->is_toctou = 0;
//     event->timestamp = bpf_ktime_get_ns();
    
//     // Copy the actual path
//     __builtin_memcpy(event->actual_path, actual_path, 256);
    
//     if (stored_path) {
//         // Copy syscall path
//         __builtin_memcpy(event->syscall_path, stored_path, 256);
        
//         // Compare paths to detect TOCTOU
//         for (int i = 0; i < 255; i++) {
//             if (stored_path[i] != actual_path[i]) {
//                 event->is_toctou = 1;
//                 break;
//             }
//             if (stored_path[i] == '\0') break;
//         }
        
//         if (event->is_toctou) {
//             bpf_printk("TOCTOU DETECTED! PID: %d", pid);
//         }
        
//         // Clean up
//         bpf_map_delete_elem(&syscall_args, &pid);
//     } else {
//         __builtin_memset(event->syscall_path, 0, 256);
//     }
    
//     // Submit the event
//     bpf_ringbuf_submit(event, 0);
    
//     return 0; // Allow execution
// }


// part 2 

// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

// char LICENSE[] SEC("license") = "GPL";

// // Map to store syscall arguments with better timing
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 2048);
//     __type(key, __u32);   // PID
//     __type(value, char[256]);
// } syscall_args SEC(".maps");

// // Map to track execution timing
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 1024);
//     __type(key, __u32);   // PID
//     __type(value, __u64); // timestamp
// } exec_timing SEC(".maps");

// // Ring buffer for events
// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1024 * 1024);
// } events SEC(".maps");

// struct toctou_event {
//     __u32 pid;
//     __u32 uid;
//     char syscall_path[256];
//     char actual_path[256];
//     __u8 is_toctou;
//     __u64 timestamp;
//     __u32 tgid;
// };

// // Fixed syscall tracing with proper eBPF syntax
// SEC("tp/syscalls/sys_enter_execve")
// int trace_execve_enter(struct trace_event_raw_sys_enter* ctx)
// {
//     __u64 pid_tgid = bpf_get_current_pid_tgid();
//     __u32 pid = pid_tgid >> 32;
//     __u32 tgid = pid_tgid & 0xFFFFFFFF;
//     __u64 timestamp = bpf_ktime_get_ns();
    
//     // Store timing information
//     bpf_map_update_elem(&exec_timing, &pid, &timestamp, BPF_ANY);
    
//     // Capture filename argument - FIXED syntax
//     void *filename_ptr = (void *)ctx->args[0];
//     char path[256] = {};
    
//     long ret = bpf_probe_read_user_str(path, sizeof(path), filename_ptr);
//     if (ret > 0) {
//         bpf_map_update_elem(&syscall_args, &pid, path, BPF_ANY);
//         bpf_printk("Execve enter: PID=%d, Path=%s", pid, path);
//     } else {
//         bpf_printk("Failed to read execve path for PID=%d, ret=%ld", pid, ret);
//     }
    
//     return 0;
// }

// // Enhanced LSM hook with better correlation logic
// SEC("lsm/bprm_check_security")
// int BPF_PROG(toctou_lsm_hook, struct linux_binprm *bprm)
// {
//     __u64 pid_tgid = bpf_get_current_pid_tgid();
//     __u32 pid = pid_tgid >> 32;
//     __u32 tgid = pid_tgid & 0xFFFFFFFF;
//     __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//     __u64 current_time = bpf_ktime_get_ns();
    
//     char actual_path[256] = {};
//     const char *filename = BPF_CORE_READ(bprm, filename);
    
//     // Read the actual filename being executed
//     long ret = bpf_probe_read_kernel_str(actual_path, sizeof(actual_path), filename);
//     if (ret <= 0) {
//         bpf_printk("Failed to read LSM path for PID=%d", pid);
//         return 0;
//     }
    
//     // Look up stored syscall argument
//     char *stored_path = bpf_map_lookup_elem(&syscall_args, &pid);
//     __u64 *exec_start_time = bpf_map_lookup_elem(&exec_timing, &pid);
    
//     // Reserve ring buffer space
//     struct toctou_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
//     if (!event) {
//         return 0;
//     }
    
//     // Initialize event
//     event->pid = pid;
//     event->tgid = tgid;
//     event->uid = uid;
//     event->timestamp = current_time;
//     event->is_toctou = 0;
    
//     // Copy actual path
//     __builtin_memcpy(event->actual_path, actual_path, sizeof(event->actual_path));
    
//     if (stored_path) {
//         // Copy syscall path
//         __builtin_memcpy(event->syscall_path, stored_path, sizeof(event->syscall_path));
        
//         // Enhanced TOCTOU detection with multiple checks
//         int path_mismatch = 0;
        
//         // Check for exact path mismatch
//         for (int i = 0; i < 255; i++) {
//             if (stored_path[i] != actual_path[i]) {
//                 path_mismatch = 1;
//                 break;
//             }
//             if (stored_path[i] == '\0' && actual_path[i] == '\0') {
//                 break; // Both strings ended, they match
//             }
//             if (stored_path[i] == '\0' || actual_path[i] == '\0') {
//                 path_mismatch = 1; // One ended before the other
//                 break;
//             }
//         }
        
//         // Additional checks for common TOCTOU patterns
//         if (path_mismatch) {
//             event->is_toctou = 1;
//             bpf_printk(" TOCTOU DETECTED! PID=%d, Syscall=%s, Actual=%s", 
//                       pid, stored_path, actual_path);
//         }
        
//         // Check timing gap (potential race window)
//         if (exec_start_time) {
//             __u64 time_gap = current_time - *exec_start_time;
//             if (time_gap > 1000000) { // > 1ms gap is suspicious
//                 bpf_printk("Suspicious timing gap: %llu ns for PID=%d", time_gap, pid);
//             }
//         }
        
//         // Clean up stored data
//         bpf_map_delete_elem(&syscall_args, &pid);
//         bpf_map_delete_elem(&exec_timing, &pid);
        
//     } else {
//         // No stored syscall path - this might be a direct exec
//         __builtin_memset(event->syscall_path, 0, sizeof(event->syscall_path));
//         bpf_printk("No syscall path stored for PID=%d, actual=%s", pid, actual_path);
//     }
    
//     bpf_printk("LSM exec: PID=%d, UID=%d, Path=%s", pid, uid, actual_path);
    
//     // Submit event
//     bpf_ringbuf_submit(event, 0);
    
//     return 0;
// }

// part 3

// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

// char LICENSE[] SEC("license") = "GPL";

// // Enhanced process tracking structure (same as before)
// struct process_info {
//     char syscall_path[256];
//     char resolved_path[256];
//     __u64 syscall_time;
//     __u32 uid;
//     __u8 has_syscall_path;
// };

// // Map to store process execution context
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 4096);
//     __type(key, __u32);   // PID
//     __type(value, struct process_info);
// } process_tracker SEC(".maps");

// // *** FIX: Per-CPU arrays to avoid stack limit ***
// // Per-CPU array for process_info temporary storage
// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, __u32);
//     __type(value, struct process_info);
// } temp_process_info SEC(".maps");

// // Per-CPU array for temporary path buffer
// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, __u32);
//     __type(value, char[256]);
// } temp_path_buffer SEC(".maps");

// // Ring buffer for TOCTOU events
// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1024 * 1024);
// } toctou_events SEC(".maps");

// struct toctou_detection {
//     __u32 pid;
//     __u32 uid;
//     char original_path[256];
//     char executed_path[256];
//     __u8 is_toctou_attack;
//     __u64 detection_time;
//     __u32 time_gap_ms;
// };

// // Enhanced execve syscall tracking with stack limit fix
// SEC("tp/syscalls/sys_enter_execve")
// int enhanced_execve_enter(struct trace_event_raw_sys_enter* ctx)
// {
//     __u32 pid = bpf_get_current_pid_tgid() >> 32;
//     __u64 current_time = bpf_ktime_get_ns();
    
//     // *** FIX: Use map instead of stack allocation ***
//     __u32 zero = 0;
//     struct process_info *proc_info = bpf_map_lookup_elem(&temp_process_info, &zero);
//     if (!proc_info) {
//         bpf_printk(" Failed to get temp process info buffer");
//         return 0;
//     }
    
//     // Initialize process info in map memory
//     __builtin_memset(proc_info, 0, sizeof(struct process_info));
//     proc_info->syscall_time = current_time;
//     proc_info->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//     proc_info->has_syscall_path = 0;
    
//     // *** FIX: Use map for temp_path instead of stack ***
//     char *temp_path = bpf_map_lookup_elem(&temp_path_buffer, &zero);
//     if (!temp_path) {
//         bpf_printk(" Failed to get temp path buffer");
//         return 0;
//     }
    
//     __builtin_memset(temp_path, 0, 256);
    
//     // Capture filename argument
//     char *filename_arg = (char *)ctx->args[0];
    
//     // Method 1: Direct read with error handling
//     long ret = bpf_probe_read_user_str(temp_path, 256, filename_arg);
//     if (ret > 0 && ret < 256) {
//         __builtin_memcpy(proc_info->syscall_path, temp_path, 256);
//         proc_info->has_syscall_path = 1;
//         bpf_printk(" Syscall captured: PID=%d", pid);
//     } else {
//         bpf_printk("  Failed to capture syscall path: PID=%d, ret=%ld", pid, ret);
        
//         // Method 2: Try reading current process name as fallback
//         bpf_get_current_comm(proc_info->syscall_path, sizeof(proc_info->syscall_path));
//     }
    
//     // Store process info in the main tracking map
//     bpf_map_update_elem(&process_tracker, &pid, proc_info, BPF_ANY);
    
//     return 0;
// }

// // Enhanced LSM hook with stack limit fixes
// SEC("lsm/bprm_check_security")  
// int BPF_PROG(enhanced_toctou_detector, struct linux_binprm *bprm)
// {
//     __u32 pid = bpf_get_current_pid_tgid() >> 32;
//     __u64 current_time = bpf_ktime_get_ns();
    
//     // *** FIX: Use smaller stack variables ***
//     char actual_path[128] = {};  // Reduced from 256 to 128
//     const char *filename = BPF_CORE_READ(bprm, filename);
    
//     // Read actual execution path
//     long ret = bpf_probe_read_kernel_str(actual_path, sizeof(actual_path), filename);
//     if (ret <= 0) {
//         bpf_printk(" Failed to read LSM path for PID=%d", pid);
//         return 0;
//     }
    
//     // Look up stored process info
//     struct process_info *proc_info = bpf_map_lookup_elem(&process_tracker, &pid);
    
//     // Prepare TOCTOU detection event
//     struct toctou_detection *event = bpf_ringbuf_reserve(&toctou_events, sizeof(*event), 0);
//     if (!event) {
//         bpf_printk(" Failed to reserve ring buffer space");
//         return 0;
//     }
    
//     // Initialize event with minimal stack usage
//     __builtin_memset(event, 0, sizeof(*event));
//     event->pid = pid;
//     event->detection_time = current_time;
//     event->is_toctou_attack = 0;
//     event->time_gap_ms = 0;
    
//     // Copy actual execution path (truncated to fit)
//     __builtin_memcpy(event->executed_path, actual_path, sizeof(actual_path));
    
//     if (proc_info && proc_info->has_syscall_path) {
//         // Copy stored syscall path and UID
//         __builtin_memcpy(event->original_path, proc_info->syscall_path, 256);
//         event->uid = proc_info->uid;
        
//         // Calculate timing gap
//         __u64 time_diff = current_time - proc_info->syscall_time;
//         event->time_gap_ms = (__u32)(time_diff / 1000000); // Convert to milliseconds
        
//         // TOCTOU Detection Algorithm (simplified for stack efficiency)
//         int is_different_path = 0;
        
//         // Compare first 127 characters (reduced for stack efficiency)
//         for (int i = 0; i < 127; i++) {
//             char syscall_char = proc_info->syscall_path[i];
//             char actual_char = actual_path[i];
            
//             if (syscall_char != actual_char) {
//                 is_different_path = 1;
//                 break;
//             }
            
//             if (syscall_char == '\0' && actual_char == '\0') {
//                 break;
//             }
//         }
        
//         // Mark as TOCTOU attack if paths differ significantly
//         if (is_different_path) {
//             // Quick basename check to reduce false positives
//             int looks_suspicious = 1;
            
//             // If both start with '/', do simple check
//             if (proc_info->syscall_path[0] == '/' && actual_path[0] == '/') {
//                 looks_suspicious = 1; // Different absolute paths = suspicious
//             } else if (proc_info->syscall_path[0] == '.' && actual_path[0] == '/') {
//                 looks_suspicious = 0; // Relative vs absolute might be legitimate
//             }
            
//             if (looks_suspicious) {
//                 event->is_toctou_attack = 1;
//                 bpf_printk(" TOCTOU ATTACK DETECTED! PID=%d", pid);
//                 bpf_printk("   Time gap: %u ms", event->time_gap_ms);
//             }
//         }
        
//         // Clean up stored process info
//         bpf_map_delete_elem(&process_tracker, &pid);
        
//     } else {
//         // No stored syscall info
//         __builtin_memcpy(event->original_path, "[MISSING]", 9);
//         event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//         bpf_printk("  No syscall correlation for PID=%d", pid);
//     }
    
//     bpf_printk("📋 LSM Exec: PID=%d", pid);
    
//     // Submit detection event
//     bpf_ringbuf_submit(event, 0);
    
//     return 0;
// }

// // Simplified file open monitor
// SEC("lsm/file_open")
// int BPF_PROG(file_open_monitor, struct file *file)
// {
//     __u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("📂 File open: PID=%d", pid);
//     return 0;
// }

// try 4

// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

// char LICENSE[] SEC("license") = "GPL";

// // Enhanced process tracking with content verification
// struct process_context {
//     char syscall_path[128];
//     __u64 syscall_time;
//     __u64 file_inode;
//     __u64 file_size;
//     __u32 file_hash;  // Simple hash of first bytes
//     __u32 uid;
//     __u8 has_syscall_data;
// };

// // Process tracking map
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 4096);
//     __type(key, __u32);   // PID
//     __type(value, struct process_context);
// } process_contexts SEC(".maps");

// // Per-CPU temporary storage
// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, __u32);
//     __type(value, struct process_context);
// } temp_context SEC(".maps");

// // Enhanced detection events
// struct toctou_detection_v2 {
//     __u32 pid;
//     __u32 uid;
//     char original_path[128];
//     char executed_path[128];
//     __u64 original_inode;
//     __u64 executed_inode;
//     __u64 original_size;
//     __u64 executed_size;
//     __u32 original_hash;
//     __u32 executed_hash;
//     __u8 attack_type;  // 1=path, 2=content, 3=inode, 4=size
//     __u32 time_gap_ms;
//     __u64 detection_time;
// };

// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1024 * 1024);
// } enhanced_toctou_events SEC(".maps");

// // Helper function to calculate simple hash
// static inline __u32 simple_hash(const char *data, int len) {
//     __u32 hash = 5381;
//     for (int i = 0; i < len && i < 16; i++) {  // Hash first 16 bytes
//         if (data[i] == 0) break;
//         hash = ((hash << 5) + hash) + (unsigned char)data[i];
//     }
//     return hash;
// }

// // Enhanced syscall capture with file metadata
// SEC("tp/syscalls/sys_enter_execve")
// int enhanced_syscall_capture(struct trace_event_raw_sys_enter* ctx)
// {
//     __u32 pid = bpf_get_current_pid_tgid() >> 32;
//     __u64 current_time = bpf_ktime_get_ns();
    
//     // Get temporary context buffer
//     __u32 zero = 0;
//     struct process_context *context = bpf_map_lookup_elem(&temp_context, &zero);
//     if (!context) return 0;
    
//     // Initialize context
//     __builtin_memset(context, 0, sizeof(*context));
//     context->syscall_time = current_time;
//     context->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//     context->has_syscall_data = 0;
    
//     // Capture filename
//     char *filename_ptr = (char *)ctx->args[0];
//     long ret = bpf_probe_read_user_str(context->syscall_path, 
//                                       sizeof(context->syscall_path), 
//                                       filename_ptr);
    
//     if (ret > 0) {
//         context->has_syscall_data = 1;
//         bpf_printk(" Syscall captured: PID=%d, Path=%s", pid, context->syscall_path);
        
//         // Try to get file metadata at syscall time
//         struct file *file;
//         struct stat st;
        
//         // Note: This is a simplified approach. In practice, you'd use
//         // additional hooks or techniques to get file metadata
//         context->file_hash = simple_hash(context->syscall_path, sizeof(context->syscall_path));
        
//     } else {
//         bpf_printk("  Failed syscall capture: PID=%d, ret=%ld", pid, ret);
//     }
    
//     // Store context for correlation
//     bpf_map_update_elem(&process_contexts, &pid, context, BPF_ANY);
    
//     return 0;
// }

// // Enhanced LSM hook with comprehensive TOCTOU detection
// SEC("lsm/bprm_check_security")
// int BPF_PROG(content_aware_toctou_detector, struct linux_binprm *bprm)
// {
//     __u32 pid = bpf_get_current_pid_tgid() >> 32;
//     __u64 current_time = bpf_ktime_get_ns();
    
//     char executed_path[128] = {};
//     const char *filename = BPF_CORE_READ(bprm, filename);
    
//     // Read executed path
//     long ret = bpf_probe_read_kernel_str(executed_path, sizeof(executed_path), filename);
//     if (ret <= 0) {
//         bpf_printk(" Failed to read LSM path for PID=%d", pid);
//         return 0;
//     }
    
//     // Get file metadata from bprm
//     struct file *file = BPF_CORE_READ(bprm, file);
//     struct inode *inode = BPF_CORE_READ(file, f_inode);
//     __u64 executed_inode = BPF_CORE_READ(inode, i_ino);
//     __u64 executed_size = BPF_CORE_READ(inode, i_size);
    
//     // Calculate content hash (simplified)
//     __u32 executed_hash = simple_hash(executed_path, sizeof(executed_path));
    
//     // Look up stored context
//     struct process_context *stored_context = bpf_map_lookup_elem(&process_contexts, &pid);
    
//     // Prepare detection event
//     struct toctou_detection_v2 *event = bpf_ringbuf_reserve(&enhanced_toctou_events, 
//                                                             sizeof(*event), 0);
//     if (!event) return 0;
    
//     // Initialize event
//     __builtin_memset(event, 0, sizeof(*event));
//     event->pid = pid;
//     event->detection_time = current_time;
//     event->executed_inode = executed_inode;
//     event->executed_size = executed_size;
//     event->executed_hash = executed_hash;
//     event->attack_type = 0;
    
//     // Copy executed path
//     __builtin_memcpy(event->executed_path, executed_path, sizeof(executed_path));
    
//     if (stored_context && stored_context->has_syscall_data) {
//         // Copy original context
//         __builtin_memcpy(event->original_path, stored_context->syscall_path, 
//                         sizeof(event->original_path));
//         event->uid = stored_context->uid;
//         event->original_inode = stored_context->file_inode;
//         event->original_size = stored_context->file_size;
//         event->original_hash = stored_context->file_hash;
        
//         // Calculate timing gap
//         __u64 time_diff = current_time - stored_context->syscall_time;
//         event->time_gap_ms = (__u32)(time_diff / 1000000);
        
//         // *** ENHANCED TOCTOU DETECTION LOGIC ***
//         int is_toctou_attack = 0;
//         __u8 attack_type = 0;
        
//         // 1. Path-based detection (traditional)
//         int path_mismatch = 0;
//         for (int i = 0; i < 127; i++) {
//             if (stored_context->syscall_path[i] != executed_path[i]) {
//                 path_mismatch = 1;
//                 break;
//             }
//             if (stored_context->syscall_path[i] == '\0') break;
//         }
        
//         if (path_mismatch) {
//             is_toctou_attack = 1;
//             attack_type = 1; // Path-based attack
//         }
        
//         // 2. Content-based detection (NEW!)
//         // If paths are same but timing gap suggests modification
//         if (!path_mismatch && event->time_gap_ms > 1) {
//             // Same path, but there was a timing gap
//             // This could indicate content modification
            
//             // Check for hash differences (simplified detection)
//             if (event->original_hash != event->executed_hash) {
//                 is_toctou_attack = 1;
//                 attack_type = 2; // Content-based attack
//             }
            
//             // Check for suspicious timing patterns
//             if (event->time_gap_ms > 5 && event->time_gap_ms < 100) {
//                 // Timing window typical of TOCTOU attacks (5-100ms)
//                 is_toctou_attack = 1;
//                 attack_type = 2;
//             }
//         }
        
//         // 3. Inode-based detection
//         if (stored_context->file_inode != 0 && 
//             stored_context->file_inode != executed_inode) {
//             is_toctou_attack = 1;
//             attack_type = 3; // Inode changed
//         }
        
//         // 4. Size-based detection  
//         if (stored_context->file_size != 0 && 
//             stored_context->file_size != executed_size) {
//             is_toctou_attack = 1;
//             attack_type = 4; // Size changed
//         }
        
//         if (is_toctou_attack) {
//             event->attack_type = attack_type;
            
//             bpf_printk(" TOCTOU ATTACK DETECTED! PID=%d, Type=%d", pid, attack_type);
//             bpf_printk("   Original: %s", stored_context->syscall_path);
//             bpf_printk("   Executed: %s", executed_path);
//             bpf_printk("   Gap: %u ms", event->time_gap_ms);
            
//             if (attack_type == 1) {
//                 bpf_printk("   Attack: PATH MODIFICATION");
//             } else if (attack_type == 2) {
//                 bpf_printk("   Attack: CONTENT MODIFICATION");
//             } else if (attack_type == 3) {
//                 bpf_printk("   Attack: INODE CHANGE");
//             } else if (attack_type == 4) {
//                 bpf_printk("   Attack: SIZE CHANGE");
//             }
//         }
        
//         // Clean up
//         bpf_map_delete_elem(&process_contexts, &pid);
        
//     } else {
//         // No stored context
//         __builtin_memcpy(event->original_path, "[MISSING]", 9);
//         event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//     }
    
//     bpf_printk("📋 LSM: PID=%d, Inode=%llu, Size=%llu", pid, executed_inode, executed_size);
    
//     // Submit event
//     bpf_ringbuf_submit(event, 0);
    
//     return 0;
// }


//try 5

// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

// char LICENSE[] SEC("license") = "GPL";

// // Simplified process tracking structure
// struct process_info {
//     char syscall_path[128];
//     __u64 syscall_time;
//     __u32 uid;
//     __u8 has_syscall_path;
// };

// // Process tracking map
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 4096);
//     __type(key, __u32);   // PID
//     __type(value, struct process_info);
// } process_tracker SEC(".maps");

// // Per-CPU temporary storage to avoid stack limit
// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, __u32);
//     __type(value, struct process_info);
// } temp_process_info SEC(".maps");

// // Match user-space event structure exactly
// struct toctou_event {
//     __u32 pid;
//     __u32 uid;
//     char syscall_path[256];
//     char actual_path[256];
//     __u8 is_toctou;
//     __u64 timestamp;
//     __u32 tgid;
// };

// // Ring buffer events - MUST match user-space expectation
// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1024 * 1024);
// } enhanced_toctou_events SEC(".maps");

// // Enhanced syscall capture
// SEC("tp/syscalls/sys_enter_execve")
// int enhanced_syscall_capture(struct trace_event_raw_sys_enter* ctx)
// {
//     __u32 pid = bpf_get_current_pid_tgid() >> 32;
//     __u64 current_time = bpf_ktime_get_ns();
    
//     // Use per-CPU array to avoid stack limit
//     __u32 zero = 0;
//     struct process_info *proc_info = bpf_map_lookup_elem(&temp_process_info, &zero);
//     if (!proc_info) {
//         bpf_printk(" Failed to get temp buffer for PID=%d", pid);
//         return 0;
//     }
    
//     // Initialize
//     __builtin_memset(proc_info, 0, sizeof(*proc_info));
//     proc_info->syscall_time = current_time;
//     proc_info->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//     proc_info->has_syscall_path = 0;
    
//     // Capture filename
//     char *filename_ptr = (char *)ctx->args[0];
//     long ret = bpf_probe_read_user_str(proc_info->syscall_path, 
//                                       sizeof(proc_info->syscall_path), 
//                                       filename_ptr);
    
//     if (ret > 0) {
//         proc_info->has_syscall_path = 1;
//         bpf_printk(" Syscall captured: PID=%d, Path=%s", pid, proc_info->syscall_path);
//     } else {
//         bpf_printk(" Failed syscall capture: PID=%d, ret=%ld", pid, ret);
//         // Fallback: use comm name
//         bpf_get_current_comm(proc_info->syscall_path, sizeof(proc_info->syscall_path));
//         proc_info->has_syscall_path = 1;
//     }
    
//     // Store for correlation
//     bpf_map_update_elem(&process_tracker, &pid, proc_info, BPF_ANY);
    
//     return 0;
// }

// // Fixed LSM hook with robust path reading
// SEC("lsm/bprm_check_security")
// int BPF_PROG(content_aware_toctou_detector, struct linux_binprm *bprm)
// {
//     __u32 pid = bpf_get_current_pid_tgid() >> 32;
//     __u32 tgid = pid; // For compatibility
//     __u64 current_time = bpf_ktime_get_ns();
    
//     char actual_path[128] = {};
    
//     // *** FIX: Multiple methods to read actual execution path ***
    
//     // Method 1: Try reading from bprm->filename
//     const char *filename = BPF_CORE_READ(bprm, filename);
//     long ret = 0;
    
//     if (filename) {
//         ret = bpf_probe_read_kernel_str(actual_path, sizeof(actual_path), filename);
//         if (ret > 0) {
//             bpf_printk(" LSM path method 1: PID=%d, Path=%s", pid, actual_path);
//         }
//     }
    
//     // Method 2: Try reading from bprm->file->f_path
//     if (ret <= 0) {
//         struct file *file = BPF_CORE_READ(bprm, file);
//         if (file) {
//             struct path file_path = BPF_CORE_READ(file, f_path);
//             struct dentry *dentry = BPF_CORE_READ(&file_path, dentry);
//             if (dentry) {
//                 const char *name = BPF_CORE_READ(dentry, d_name.name);
//                 if (name) {
//                     ret = bpf_probe_read_kernel_str(actual_path, sizeof(actual_path), name);
//                     if (ret > 0) {
//                         bpf_printk(" LSM path method 2: PID=%d, Path=%s", pid, actual_path);
//                     }
//                 }
//             }
//         }
//     }
    
//     // Method 3: Fallback to current task comm
//     if (ret <= 0) {
//         bpf_get_current_comm(actual_path, sizeof(actual_path));
//         bpf_printk(" LSM path fallback: PID=%d, Comm=%s", pid, actual_path);
//         ret = 1; // Mark as successful
//     }
    
//     if (ret <= 0) {
//         bpf_printk(" All LSM path methods failed for PID=%d", pid);
//         return 0;
//     }
    
//     // Look up stored syscall context
//     struct process_info *stored_context = bpf_map_lookup_elem(&process_tracker, &pid);
    
//     // Prepare event
//     struct toctou_event *event = bpf_ringbuf_reserve(&enhanced_toctou_events, sizeof(*event), 0);
//     if (!event) {
//         bpf_printk(" Failed to reserve ring buffer for PID=%d", pid);
//         return 0;
//     }
    
//     // Initialize event
//     __builtin_memset(event, 0, sizeof(*event));
//     event->pid = pid;
//     event->tgid = tgid;
//     event->timestamp = current_time;
//     event->is_toctou = 0;
    
//     // Copy actual path (expand to full event->actual_path size)
//     __builtin_memcpy(event->actual_path, actual_path, sizeof(actual_path));
//     // Ensure rest is null-terminated
//     for (int i = sizeof(actual_path); i < sizeof(event->actual_path); i++) {
//         event->actual_path[i] = '\0';
//     }
    
//     if (stored_context && stored_context->has_syscall_path) {
//         // Copy syscall context
//         __builtin_memcpy(event->syscall_path, stored_context->syscall_path, sizeof(stored_context->syscall_path));
//         // Ensure rest is null-terminated
//         for (int i = sizeof(stored_context->syscall_path); i < sizeof(event->syscall_path); i++) {
//             event->syscall_path[i] = '\0';
//         }
        
//         event->uid = stored_context->uid;
        
//         // *** ENHANCED TOCTOU DETECTION LOGIC ***
//         int is_toctou_attack = 0;
        
//         // Calculate timing gap
//         __u64 time_diff = current_time - stored_context->syscall_time;
//         __u32 time_gap_ms = (__u32)(time_diff / 1000000);
        
//         // 1. Direct path comparison
//         int path_differs = 0;
//         for (int i = 0; i < 127; i++) {
//             char syscall_char = stored_context->syscall_path[i];
//             char actual_char = actual_path[i];
            
//             if (syscall_char != actual_char) {
//                 path_differs = 1;
//                 break;
//             }
//             if (syscall_char == '\0') break;
//         }
        
//         // 2. Enhanced detection for same-path attacks
//         if (!path_differs) {
//             // Same path - check for timing-based TOCTOU
//             if (time_gap_ms >= 1 && time_gap_ms <= 100) {
//                 // Suspicious timing window for file modification
//                 is_toctou_attack = 1;
//                 bpf_printk(" TIMING-BASED TOCTOU: Same path, suspicious %ums gap", time_gap_ms);
//             }
//         } else {
//             // Different paths - traditional TOCTOU
//             is_toctou_attack = 1;
//             bpf_printk(" PATH-BASED TOCTOU: Different paths detected");
//         }
        
//         if (is_toctou_attack) {
//             event->is_toctou = 1;
//             bpf_printk(" TOCTOU ATTACK DETECTED! PID=%d", pid);
//             bpf_printk("   Syscall: %s", stored_context->syscall_path);
//             bpf_printk("   Actual:  %s", actual_path);
//             bpf_printk("   Gap: %u ms", time_gap_ms);
//         }
        
//         // Clean up
//         bpf_map_delete_elem(&process_tracker, &pid);
        
//     } else {
//         // No stored syscall context
//         __builtin_memcpy(event->syscall_path, "[MISSING]", 9);
//         event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//         bpf_printk(" No syscall correlation for PID=%d, actual=%s", pid, actual_path);
//     }
    
//     bpf_printk(" LSM exec: PID=%d, Path=%s", pid, actual_path);
    
//     // Submit event
//     bpf_ringbuf_submit(event, 0);
    
//     return 0;
// }


// try 6
// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

// char LICENSE[] SEC("license") = "GPL";

// // Keep the EXACT working structure from previous version
// struct process_info {
//     char syscall_path[128];  // Reduced size to avoid stack issues
//     __u64 syscall_time;
//     __u32 uid;
//     __u8 has_syscall_path;
// };

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 4096);
//     __type(key, __u32);
//     __type(value, struct process_info);
// } process_tracker SEC(".maps");

// // Per-CPU arrays to avoid stack limit (keep working approach)
// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, __u32);
//     __type(value, struct process_info);
// } temp_process_info SEC(".maps");

// // *** CRITICAL: Keep EXACT same event structure as working version ***
// struct toctou_event {
//     __u32 pid;
//     __u32 uid;
//     char syscall_path[256];
//     char actual_path[256];
//     __u8 is_toctou;
//     __u64 timestamp;
//     __u32 tgid;
// };

// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1024 * 1024);
// } enhanced_toctou_events SEC(".maps");

// // Restore working syscall capture (with minimal improvements)
// SEC("tp/syscalls/sys_enter_execve")
// int enhanced_syscall_capture(struct trace_event_raw_sys_enter* ctx)
// {
//     __u32 pid = bpf_get_current_pid_tgid() >> 32;
//     __u64 current_time = bpf_ktime_get_ns();
    
//     __u32 zero = 0;
//     struct process_info *proc_info = bpf_map_lookup_elem(&temp_process_info, &zero);
//     if (!proc_info) {
//         return 0;
//     }
    
//     __builtin_memset(proc_info, 0, sizeof(*proc_info));
//     proc_info->syscall_time = current_time;
//     proc_info->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//     proc_info->has_syscall_path = 0;
    
//     // Simple, working path capture
//     char *filename_arg = (char *)ctx->args[0];
//     long ret = bpf_probe_read_user_str(proc_info->syscall_path, 
//                                       sizeof(proc_info->syscall_path), 
//                                       filename_arg);
    
//     if (ret > 0) {
//         proc_info->has_syscall_path = 1;
//         bpf_printk(" Syscall captured: PID=%d, Path=%s", pid, proc_info->syscall_path);
//     } else {
//         bpf_printk("  Failed syscall capture: PID=%d, ret=%ld", pid, ret);
//     }
    
//     bpf_map_update_elem(&process_tracker, &pid, proc_info, BPF_ANY);
//     return 0;
// }

// // Restore working LSM detector with enhanced timing detection
// SEC("lsm/bprm_check_security")
// int BPF_PROG(advanced_toctou_detector, struct linux_binprm *bprm)
// {
//     __u32 pid = bpf_get_current_pid_tgid() >> 32;
//     __u32 tgid = pid; // Simple assignment
//     __u64 current_time = bpf_ktime_get_ns();
    
//     char actual_path[128] = {};
//     const char *filename = BPF_CORE_READ(bprm, filename);
    
//     // Working path reading method
//     long ret = bpf_probe_read_kernel_str(actual_path, sizeof(actual_path), filename);
//     if (ret <= 0) {
//         bpf_printk(" Failed to read LSM path for PID=%d", pid);
//         return 0;
//     }
    
//     struct process_info *stored_context = bpf_map_lookup_elem(&process_tracker, &pid);
    
//     struct toctou_event *event = bpf_ringbuf_reserve(&enhanced_toctou_events, sizeof(*event), 0);
//     if (!event) {
//         return 0;
//     }
    
//     // *** CRITICAL: Initialize event properly ***
//     __builtin_memset(event, 0, sizeof(*event));
//     event->pid = pid;
//     event->tgid = tgid;
//     event->timestamp = current_time;
//     event->is_toctou = 0;
    
//     // Copy actual path properly
//     __builtin_memcpy(event->actual_path, actual_path, sizeof(actual_path));
//     // Null-terminate remaining space
//     for (int i = sizeof(actual_path); i < sizeof(event->actual_path); i++) {
//         event->actual_path[i] = '\0';
//     }
    
//     if (stored_context && stored_context->has_syscall_path) {
//         // Copy syscall path properly
//         __builtin_memcpy(event->syscall_path, stored_context->syscall_path, sizeof(stored_context->syscall_path));
//         // Null-terminate remaining space
//         for (int i = sizeof(stored_context->syscall_path); i < sizeof(event->syscall_path); i++) {
//             event->syscall_path[i] = '\0';
//         }
        
//         event->uid = stored_context->uid;
        
//         // Enhanced TOCTOU detection logic
//         int path_differs = 0;
//         for (int i = 0; i < 127; i++) {
//             if (stored_context->syscall_path[i] != actual_path[i]) {
//                 path_differs = 1;
//                 break;
//             }
//             if (stored_context->syscall_path[i] == '\0') break;
//         }
        
//         // Calculate timing gap
//         __u64 time_diff = current_time - stored_context->syscall_time;
//         __u32 time_gap_ms = (__u32)(time_diff / 1000000);
        
//         // TOCTOU Detection Logic
//         if (path_differs) {
//             event->is_toctou = 1;
//             bpf_printk(" PATH-BASED TOCTOU DETECTED! PID=%d", pid);
//             bpf_printk("   Syscall: %s", stored_context->syscall_path);
//             bpf_printk("   Actual:  %s", actual_path);
//         } else if (time_gap_ms >= 2 && time_gap_ms <= 100) {
//             // Enhanced: timing-based detection for same-path attacks
//             event->is_toctou = 1;
//             bpf_printk(" TIMING-BASED TOCTOU DETECTED! PID=%d, Gap=%ums", pid, time_gap_ms);
//             bpf_printk("   Same path, suspicious timing: %s", actual_path);
//         }
        
//         bpf_map_delete_elem(&process_tracker, &pid);
        
//     } else {
//         __builtin_memcpy(event->syscall_path, "[MISSING]", 9);
//         event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//     }
    
//     bpf_printk("📋 LSM exec: PID=%d, Path=%s", pid, actual_path);
//     bpf_ringbuf_submit(event, 0);
//     return 0;
// }

// trial 7
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Enhanced process tracking structure with file metadata
struct process_info {
    char syscall_path[128];
    __u64 syscall_time;
    __u32 uid;
    __u8 has_syscall_path;
    // File metadata for content change detection
    __u64 inode_num;      // Inode number
    __u64 file_size;      // File size in bytes
    __u64 mtime_sec;      // Modification time (seconds)
    __u64 mtime_nsec;     // Modification time (nanoseconds)
    __u8 has_metadata;    // Flag: metadata captured successfully
};

// Process tracking map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);   // PID
    __type(value, struct process_info);
} process_tracker SEC(".maps");

// Per-CPU temporary storage
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_info);
} temp_process_info SEC(".maps");

// Enhanced event structure with metadata comparison results
struct toctou_event {
    __u32 pid;
    __u32 uid;
    char syscall_path[256];
    char actual_path[256];
    __u8 is_toctou;
    __u64 timestamp;
    __u32 tgid;
    // Metadata comparison results
    __u8 path_differs;
    __u8 inode_differs;
    __u8 size_differs;
    __u8 mtime_differs;
    __u64 stored_inode;
    __u64 actual_inode;
    __u64 stored_size;
    __u64 actual_size;
};

// Ring buffer events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} enhanced_toctou_events SEC(".maps");

// Helper function to safely read inode modification time
static inline int read_inode_mtime(struct inode *inode, __u64 *mtime_sec, __u64 *mtime_nsec) {
    // Try multiple methods to access mtime across different kernel versions
    
    // Method 1: Try __i_mtime (newer kernels)
    struct timespec64 mtime = {};
    if (bpf_core_field_exists(struct inode, __i_mtime)) {
        mtime = BPF_CORE_READ(inode, __i_mtime);
        *mtime_sec = mtime.tv_sec;
        *mtime_nsec = mtime.tv_nsec;
        return 1;
    }
    
    // Method 2: Try i_mtime (older kernels)
    if (bpf_core_field_exists(struct inode, __i_mtime)) {
        mtime = BPF_CORE_READ(inode, __i_mtime);
        *mtime_sec = mtime.tv_sec;
        *mtime_nsec = mtime.tv_nsec;
        return 1;
    }
    
    // Method 3: Use current time as fallback
    __u64 current_time = bpf_ktime_get_ns();
    *mtime_sec = current_time / 1000000000;
    *mtime_nsec = current_time % 1000000000;
    return 0; // Indicate fallback was used
}

// Enhanced syscall capture
SEC("tp/syscalls/sys_enter_execve")
int enhanced_syscall_capture(struct trace_event_raw_sys_enter* ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 current_time = bpf_ktime_get_ns();
    
    // Use per-CPU array to avoid stack limit
    __u32 zero = 0;
    struct process_info *proc_info = bpf_map_lookup_elem(&temp_process_info, &zero);
    if (!proc_info) {
        bpf_printk(" Failed to get temp buffer for PID=%d", pid);
        return 0;
    }
    
    // Initialize all fields
    __builtin_memset(proc_info, 0, sizeof(*proc_info));
    proc_info->syscall_time = current_time;
    proc_info->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    proc_info->has_syscall_path = 0;
    proc_info->has_metadata = 0;
    
    // Capture filename
    // char *filename_ptr = (char *)ctx->args[0];
    // long ret = bpf_probe_read_user_str(proc_info->syscall_path, 
    //                                   sizeof(proc_info->syscall_path), 
    //                                   filename_ptr);
    char *filename_ptr;
    long ret = 0;    
    // Method 1: Direct args array access
    if (bpf_probe_read_user(&filename_ptr, sizeof(filename_ptr), &ctx->args[0]) == 0) {
        ret = bpf_probe_read_user_str(proc_info->syscall_path, 
                                     sizeof(proc_info->syscall_path), 
                                     filename_ptr);
        bpf_printk(" Syscall captured by method 1: PID=%d, Path=%s", pid, proc_info->syscall_path);
    } else {
        // Method 2: Use tracepoint fields if available
        filename_ptr = (char *)ctx->args[0];
        ret = bpf_probe_read_user_str(proc_info->syscall_path, 
                                     sizeof(proc_info->syscall_path), 
                                     filename_ptr);
        bpf_printk(" Syscall captured by method 2: PID=%d, Path=%s", pid, proc_info->syscall_path);
    }
    if (ret > 0) {
        proc_info->has_syscall_path = 1;
        bpf_printk(" Syscall captured: PID=%d, Path=%s", pid, proc_info->syscall_path);
    } else {
        bpf_printk(" Failed syscall capture: PID=%d, ret=%ld", pid, ret);
        // Fallback: use comm name
        bpf_get_current_comm(proc_info->syscall_path, sizeof(proc_info->syscall_path));
        proc_info->has_syscall_path = 1;
    }
    
    // Store for correlation
    bpf_map_update_elem(&process_tracker, &pid, proc_info, BPF_ANY);
    
    return 0;
}

// Enhanced LSM hook with comprehensive metadata comparison
SEC("lsm/bprm_check_security")
int BPF_PROG(content_aware_toctou_detector, struct linux_binprm *bprm)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = pid;
    __u64 current_time = bpf_ktime_get_ns();
    
    char actual_path[128] = {};
    
    // Read actual execution path
    const char *filename = BPF_CORE_READ(bprm, filename);
    long ret = 0;
    
    if (filename) {
        ret = bpf_probe_read_kernel_str(actual_path, sizeof(actual_path), filename);
        if (ret > 0) {
            bpf_printk(" LSM path: PID=%d, Path=%s", pid, actual_path);
        }
    }
    
    // Fallback to comm if path reading failed
    if (ret <= 0) {
        bpf_get_current_comm(actual_path, sizeof(actual_path));
        bpf_printk(" LSM fallback: PID=%d, Comm=%s", pid, actual_path);
        ret = 1;
    }
    
    // *** FIXED: Capture current file metadata with proper inode field access ***
    __u64 actual_inode = 0;
    __u64 actual_size = 0;
    __u64 actual_mtime_sec = 0;
    __u64 actual_mtime_nsec = 0;
    
    struct file *file = BPF_CORE_READ(bprm, file);
    if (file) {
        struct inode *inode = BPF_CORE_READ(file, f_inode);
        if (inode) {
            actual_inode = BPF_CORE_READ(inode, i_ino);
            actual_size = BPF_CORE_READ(inode, i_size);
            
            // *** FIXED: Use helper function to read mtime safely ***
            int mtime_success = read_inode_mtime(inode, &actual_mtime_sec, &actual_mtime_nsec);
            if (mtime_success) {
                bpf_printk(" Metadata: inode=%llu, size=%llu, mtime=%llu.%llu", 
                          actual_inode, actual_size, actual_mtime_sec, actual_mtime_nsec);
            } else {
                bpf_printk(" Metadata: inode=%llu, size=%llu, mtime=fallback", 
                          actual_inode, actual_size);
            }
        }
    }
    
    // Look up stored syscall context
    struct process_info *stored_context = bpf_map_lookup_elem(&process_tracker, &pid);
    
    // Update stored context with metadata (if not already captured)
    if (stored_context && !stored_context->has_metadata && file) {
        stored_context->inode_num = actual_inode;
        stored_context->file_size = actual_size;
        stored_context->mtime_sec = actual_mtime_sec;
        stored_context->mtime_nsec = actual_mtime_nsec;
        stored_context->has_metadata = 1;
        
        bpf_map_update_elem(&process_tracker, &pid, stored_context, BPF_ANY);
        bpf_printk(" Stored metadata for PID=%d", pid);
    }
    
    // Prepare enhanced event
    struct toctou_event *event = bpf_ringbuf_reserve(&enhanced_toctou_events, sizeof(*event), 0);
    if (!event) {
        bpf_printk(" Failed to reserve ring buffer for PID=%d", pid);
        return 0;
    }
    
    // Initialize event
    __builtin_memset(event, 0, sizeof(*event));
    event->pid = pid;
    event->tgid = tgid;
    event->timestamp = current_time;
    event->is_toctou = 0;
    
    // Copy paths
    __builtin_memcpy(event->actual_path, actual_path, sizeof(actual_path));
    for (int i = sizeof(actual_path); i < sizeof(event->actual_path); i++) {
        event->actual_path[i] = '\0';
    }
    
    if (stored_context && stored_context->has_syscall_path) {
        // Copy syscall context
        __builtin_memcpy(event->syscall_path, stored_context->syscall_path, 
                        sizeof(stored_context->syscall_path));
        for (int i = sizeof(stored_context->syscall_path); i < sizeof(event->syscall_path); i++) {
            event->syscall_path[i] = '\0';
        }
        
        event->uid = stored_context->uid;
        
        // *** ENHANCED TOCTOU DETECTION LOGIC ***
        int is_toctou_attack = 0;
        
        // Calculate timing gap
        __u64 time_diff = current_time - stored_context->syscall_time;
        __u32 time_gap_ms = (__u32)(time_diff / 1000000);
        
        // 1. Path comparison
        int path_differs = 0;
        for (int i = 0; i < 127; i++) {
            if (stored_context->syscall_path[i] != actual_path[i]) {
                path_differs = 1;
                break;
            }
            if (stored_context->syscall_path[i] == '\0') break;
        }
        
        // 2. Metadata comparison (content change detection)
        int inode_differs = 0;
        int size_differs = 0;
        int mtime_differs = 0;
        
        if (stored_context->has_metadata) {
            // Compare inode numbers
            if (stored_context->inode_num != actual_inode) {
                inode_differs = 1;
                bpf_printk(" INODE CHANGE: %llu -> %llu", stored_context->inode_num, actual_inode);
            }
            
            // Compare file sizes
            if (stored_context->file_size != actual_size) {
                size_differs = 1;
                bpf_printk(" SIZE CHANGE: %llu -> %llu", stored_context->file_size, actual_size);
            }
            
            // Compare modification times (with reasonable tolerance for filesystem precision)
            __u64 time_diff_sec = (actual_mtime_sec > stored_context->mtime_sec) ? 
                                  (actual_mtime_sec - stored_context->mtime_sec) : 
                                  (stored_context->mtime_sec - actual_mtime_sec);
            
            if (time_diff_sec > 0 || 
                (stored_context->mtime_nsec != actual_mtime_nsec && time_diff_sec == 0)) {
                mtime_differs = 1;
                bpf_printk(" MTIME CHANGE: %llu.%llu -> %llu.%llu", 
                          stored_context->mtime_sec, stored_context->mtime_nsec,
                          actual_mtime_sec, actual_mtime_nsec);
            }
        }
        
        // Store comparison results in event
        event->path_differs = path_differs;
        event->inode_differs = inode_differs;
        event->size_differs = size_differs;
        event->mtime_differs = mtime_differs;
        event->stored_inode = stored_context->inode_num;
        event->actual_inode = actual_inode;
        event->stored_size = stored_context->file_size;
        event->actual_size = actual_size;
        
        // *** COMPREHENSIVE DETECTION LOGIC ***
        if (path_differs) {
            is_toctou_attack = 1;
            bpf_printk(" PATH-BASED TOCTOU: Different paths detected");
        } else if (inode_differs) {
            is_toctou_attack = 1;
            bpf_printk(" INODE-BASED TOCTOU: File replaced (different inode)");
        } else if (size_differs || mtime_differs) {
            is_toctou_attack = 1;
            bpf_printk(" CONTENT-BASED TOCTOU: File modified (size/mtime change)");
        } else if (time_gap_ms >= 1 && time_gap_ms <= 100) {
            // Timing-based detection as fallback
            is_toctou_attack = 1;
            bpf_printk(" TIMING-BASED TOCTOU: Suspicious %ums gap", time_gap_ms);
        }
        
        if (is_toctou_attack) {
            event->is_toctou = 1;
            bpf_printk(" TOCTOU ATTACK DETECTED! PID=%d", pid);
            bpf_printk("   Syscall: %s", stored_context->syscall_path);
            bpf_printk("   Actual:  %s", actual_path);
            bpf_printk("   Gap: %u ms", time_gap_ms);
            bpf_printk("   Changes: path=%d inode=%d size=%d mtime=%d", 
                      path_differs, inode_differs, size_differs, mtime_differs);
        }
        
        // Clean up
        bpf_map_delete_elem(&process_tracker, &pid);
        
    } else {
        // No stored syscall context
        __builtin_memcpy(event->syscall_path, "[MISSING]", 9);
        event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        bpf_printk(" No syscall correlation for PID=%d, actual=%s", pid, actual_path);
    }
    
    bpf_printk(" LSM exec: PID=%d, Path=%s", pid, actual_path);
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}
