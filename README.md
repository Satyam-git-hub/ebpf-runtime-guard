# ebpf-runtime-guard
# eBPF LSM Security Monitor

A comprehensive eBPF-based security monitoring system that detects **TOCTOU (Time-of-Check-to-Time-of-Use) attacks** and **LD_PRELOAD library injection** attempts using Linux Security Module (LSM) hooks.

## 🛡️ Features

- **TOCTOU Attack Detection**: Monitors file modifications between security checks and execution
- **LD_PRELOAD Injection Detection**: Detects malicious library preloading attempts
- **Real-time Monitoring**: Uses eBPF LSM hooks for kernel-level visibility
- **Risk Assessment**: Confidence scoring and threat classification
- **Comprehensive Testing**: Automated test suites for validation

## 📁 Project Structure

```
.
├── LD_PRELOAD/                          # LD_PRELOAD detection module
│   ├── Makefile                         # Build configuration for LD_PRELOAD
│   ├── bpf_ldpreload_detector.bpf.c     # eBPF program for injection detection
│   ├── security_monitor.c               # User-space loader for LD_PRELOAD detection
│   ├── malicious_preload.c              # Test malicious library
│   └── vmlinux.h                        # Kernel headers
├── Makefile                             # Main build configuration
├── bpf_toctou_detector.bpf.c            # eBPF program for TOCTOU detection
├── toctou_loader.c                      # User-space loader for TOCTOU detection
├── enhanced_toctou_test.c               # TOCTOU attack test suite
├── test_framework.c                     # Comprehensive test framework
├── monitoring_toctou.sh                 # Monitoring automation script
└── run_toctou_tests.sh                  # Test runner script
```

## 🔧 System Requirements

### Kernel Requirements
- **Linux Kernel**: 5.7+ (for BPF LSM support)
- **eBPF Support**: Enabled in kernel configuration
- **BPF LSM**: Compiled and activated

### Required Packages
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-common \
    linux-tools-generic \
    build-essential \
    linux-headers-$(uname -r)

# RHEL/Fedora
sudo dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel \
    bpftool
```

## ⚙️ Kernel Configuration

### Step 1: Check Current LSM Status

```bash
# Check if BPF LSM is compiled
cat /boot/config-$(uname -r) | grep BPF_LSM
# Expected: CONFIG_BPF_LSM=y

# Check active LSMs
cat /sys/kernel/security/lsm
# Should include 'bpf' in the list
```

### Step 2: Enable BPF LSM (If Not Active)

If BPF LSM is compiled but not active, add it to kernel boot parameters:

#### Option A: Permanent GRUB Configuration

1. **Edit GRUB configuration:**
   ```bash
   sudo nano /etc/default/grub
   ```

2. **Modify the LSM parameter:**
   ```bash
   # Find this line:
   GRUB_CMDLINE_LINUX=""
   
   # Change to (add bpf to existing LSMs):
   GRUB_CMDLINE_LINUX="lsm=lockdown,yama,integrity,apparmor,bpf"
   
   # Or if no existing lsm parameter:
   GRUB_CMDLINE_LINUX="lsm=capability,lockdown,yama,integrity,apparmor,bpf"
   ```

3. **Update GRUB and reboot:**
   ```bash
   # Ubuntu/Debian
   sudo update-grub
   
   # RHEL/Fedora/CentOS
   sudo grub2-mkconfig -o /boot/grub2/grub.cfg
   
   # Reboot system
   sudo reboot
   ```

#### Option B: One-Time Boot Test

1. **At GRUB boot menu**, press `e` to edit
2. **Add to kernel line**: `lsm=capability,lockdown,yama,integrity,apparmor,bpf`
3. **Press Ctrl+X** to boot with these parameters

### Step 3: Verify BPF LSM is Active

After reboot:
```bash
cat /sys/kernel/security/lsm
# Should output something like: lockdown,capability,yama,apparmor,bpf
```

## 🏗️ Compilation Instructions

### TOCTOU Detection System (Root Directory)

```bash
# Navigate to project root
cd ~/TOCTOU-lsm

# Generate kernel headers
make clean

# Build TOCTOU detection system
make

# This creates:
# - bpf_toctou_detector.o (eBPF object)
# - toctou_loader (user-space loader)
# - enhanced_toctou_test (test program)
# - test_framework (comprehensive test suite)
```

#### Manual Compilation (if needed):
```bash
# Generate vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile eBPF program
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -I/usr/include \
    -c bpf_toctou_detector.bpf.c -o bpf_toctou_detector.o

# Compile user-space loader
gcc -Wall -O2 -o toctou_loader toctou_loader.c -lbpf

# Compile test programs
gcc -pthread -Wall -O2 -o enhanced_toctou_test enhanced_toctou_test.c
gcc -pthread -Wall -O2 -o test_framework test_framework.c
```

### LD_PRELOAD Detection System

```bash
# Navigate to LD_PRELOAD directory
cd ~/TOCTOU-lsm/LD_PRELOAD

# Build LD_PRELOAD detection system
make clean && make

# This creates:
# - bpf_ldpreload_detector.o (eBPF object)
# - security_monitor (user-space loader)
# - /tmp/malicious.so (test malicious library)
```

#### Manual Compilation:
```bash
# Generate vmlinux.h (if not present)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile eBPF program
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -I/usr/include \
    -c bpf_ldpreload_detector.bpf.c -o bpf_ldpreload_detector.o

# Compile security monitor
gcc -Wall -O2 -o security_monitor security_monitor.c -lbpf

# Compile malicious test library
gcc -shared -fPIC -o /tmp/malicious.so malicious_preload.c -ldl
```

## 🚀 Usage Instructions

### TOCTOU Detection

#### Basic Usage:
```bash
# Terminal 1: Start TOCTOU detector
sudo ./toctou_loader

# Terminal 2: Run TOCTOU attack tests
./enhanced_toctou_test
```

#### Automated Testing:
```bash
# Run comprehensive test suite
sudo ./run_toctou_tests.sh

# Or run individual test framework
./test_framework
```

#### Real-time Monitoring:
```bash
# Start monitoring with enhanced logging
sudo ./monitoring_toctou.sh
```

### LD_PRELOAD Detection

#### Basic Usage:
```bash
# Terminal 1: Start LD_PRELOAD detector
cd LD_PRELOAD
sudo ./security_monitor

# Terminal 2: Test LD_PRELOAD injection
LD_PRELOAD=/tmp/malicious.so /bin/ls
LD_PRELOAD=/tmp/malicious.so /usr/bin/whoami
```

#### Testing Different Attack Scenarios:
```bash
# Test with suspicious library paths
LD_PRELOAD=/tmp/evil.so /bin/cat /etc/passwd
LD_PRELOAD=/dev/shm/rootkit.so /usr/bin/id

# Test LD_LIBRARY_PATH manipulation
LD_LIBRARY_PATH=/tmp:/dev/shm /bin/bash
```

## 📊 Monitoring Output

### TOCTOU Detection Events:
```bash
[12:30:15] 🔍 Detection Event #1:
  PID: 12345 | UID: 1000 | TGID: 12345
  Syscall Path: /tmp/test_binary
  Actual Path: /tmp/test_binary
  🚨 *** TOCTOU ATTACK DETECTED *** 🚨
  🔥 Attack #1 - File was modified between check and use!
```

### LD_PRELOAD Detection Events:
```bash
[12:30:20] 🔍 Security Event #1:
  Attack Type: LD_PRELOAD INJECTION
  PID: 12346 | UID: 1000
  Binary: /bin/ls
  Risk Level: CRITICAL (9/10)
  🔍 LD_PRELOAD Library: /tmp/malicious.so
  🚨 SHARED LIBRARY INJECTION DETECTED
  ⚠️ SUSPICIOUS PATH: Library in temporary directory!
```

## 🧪 Testing and Validation

### Automated Test Execution:
```bash
# Test TOCTOU detection
sudo ./run_toctou_tests.sh

# Expected output: Multiple attack scenarios with detection alerts
```

### Manual Attack Simulation:
```bash
# Create test environment
mkdir -p /tmp/test_attacks

# Simulate TOCTOU attack
echo '#!/bin/bash\necho "Original"' > /tmp/test_attacks/victim &
sleep 0.1
echo '#!/bin/bash\necho "COMPROMISED!"' > /tmp/test_attacks/victim &
chmod +x /tmp/test_attacks/victim
/tmp/test_attacks/victim
```

### Kernel Log Monitoring:
```bash
# Monitor eBPF kernel logs
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep -E "(TOCTOU|LD_PRELOAD)"

# Check kernel messages
sudo dmesg | tail -20 | grep -E "(TOCTOU|LSM)"
```

## 🔍 Troubleshooting

### Common Issues:

1. **BPF LSM Not Active:**
   ```bash
   # Check current LSMs
   cat /sys/kernel/security/lsm
   # If 'bpf' missing, update GRUB configuration
   ```

2. **Permission Denied:**
   ```bash
   # Ensure running as root
   sudo ./toctou_loader
   sudo ./security_monitor
   ```

3. **Compilation Errors:**
   ```bash
   # Update packages
   sudo apt update && sudo apt upgrade
   
   # Reinstall libbpf-dev
   sudo apt install --reinstall libbpf-dev
   ```

4. **Verifier Errors:**
   ```bash
   # Check eBPF program with verbose output
   sudo bpftool prog load bpf_toctou_detector.o /sys/fs/bpf/toctou_prog
   ```

### Debug Commands:
```bash
# List loaded BPF programs
sudo bpftool prog list

# Check BPF maps
sudo bpftool map list

# Monitor BPF events
sudo bpftrace -e 'tracepoint:bpf:*'
```

## 📈 Performance Considerations

- **Minimal Overhead**: eBPF programs optimized for low performance impact
- **Memory Efficient**: Stack-optimized to respect eBPF 512-byte limit
- **Scalable**: Handles high-frequency execve() syscalls efficiently

## 🛡️ Security Features

### Detection Capabilities:
- ✅ **File Content Modification** during execution window
- ✅ **Path Resolution Attacks** (symlink manipulation)
- ✅ **Library Injection** via LD_PRELOAD
- ✅ **Suspicious Library Paths** (/tmp, /dev/shm)
- ✅ **Risk Assessment** with confidence scoring

### False Positive Mitigation:
- **Path Resolution Logic** - Distinguishes legitimate vs malicious path changes
- **Timing Analysis** - Identifies suspicious execution windows
- **Confidence Scoring** - Reduces false alarms with risk assessment

## 📝 License

This project is released under the MIT License. See LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-detection`)
3. Commit changes (`git commit -am 'Add new detection capability'`)
4. Push to branch (`git push origin feature/new-detection`)
5. Create Pull Request

## 📚 References

- [eBPF Documentation](https://ebpf.io/)
- [Linux Security Modules](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html)
- [BPF LSM Documentation](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)
- [libbpf Library](https://github.com/libbpf/libbpf)

**⚠️ Warning**: This tool is designed for security research and legitimate system monitoring. Use responsibly and in accordance with applicable laws and policies.
