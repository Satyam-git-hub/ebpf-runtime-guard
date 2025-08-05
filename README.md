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
├── TOCTOU-lsm/                          # TOCTOU detection module
│   ├── Makefile                         # Build configuration for TOCTOU
│   ├── bpf_toctou_detector.bpf.c        # eBPF program for TOCTOU detection
│   ├── bpf_toctou_detector.o            # Compiled eBPF object
│   ├── toctou_loader                    # User-space loader executable
│   ├── toctou_loader.c                  # User-space loader source
│   ├── enhanced_toctou_test             # Enhanced test executable
│   ├── enhanced_toctou_test.c           # Enhanced TOCTOU attack test suite
│   ├── test_framework                   # Test framework executable
│   ├── test_framework.c                 # Comprehensive test framework
│   ├── monitoring_toctou.sh             # Monitoring automation script
│   ├── run_toctou_tests.sh              # Test runner script
│   └── vmlinux.h                        # Kernel headers
├── LD_PRELOAD/                          # LD_PRELOAD detection module
│   ├── Makefile                         # Build configuration for LD_PRELOAD
│   ├── bpf_ldpreload_detector.bpf.c     # eBPF program for injection detection
│   ├── bpf_ldpreload_detector.o         # Compiled eBPF object
│   ├── security_monitor                 # Security monitor executable
│   ├── security_monitor.c               # User-space loader for LD_PRELOAD detection
│   ├── malicious_preload.c              # Test malicious library source
│   ├── malicious_preload.so             # Compiled test malicious library
│   └── vmlinux.h                        # Kernel headers
├── Makefile                             # Main build configuration
├── vmlinux.h                            # Shared kernel headers
└── README.md                            # This documentation
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

### Build All Modules

```bash
# Navigate to project root
cd ebpf-runtime-guard

# Build both modules
make all

# This creates executables in respective directories:
# TOCTOU-lsm/toctou_loader, enhanced_toctou_test, test_framework
# LD_PRELOAD/security_monitor, malicious_preload.so
```

### Build Individual Modules

```bash
# Build only TOCTOU detection
make toctou

# Build only LD_PRELOAD detection  
make ldpreload

# Generate kernel headers if needed
make vmlinux
```

## 🚀 Usage Instructions

### TOCTOU Detection

Use the automated test target:
```bash
make test-toctou
```

This displays instructions to:
1. **Terminal 1**: Start the detector
   ```bash
   sudo ./TOCTOU-lsm/toctou_loader
   ```

2. **Terminal 2**: Run attack tests
   ```bash
   ./TOCTOU-lsm/test_framework
   ```

3. **Alternative tests**:
   ```bash
   ./TOCTOU-lsm/enhanced_toctou_test
   ```

### LD_PRELOAD Detection

Use the automated test target:
```bash
make test-ldpreload
```

This displays instructions to:
1. **Terminal 1**: Start the monitor
   ```bash
   sudo ./LD_PRELOAD/security_monitor
   ```

2. **Terminal 2**: Run injection tests
   ```bash
   LD_PRELOAD=./LD_PRELOAD/malicious_preload.so /bin/ls
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
  🔍 LD_PRELOAD Library: ./LD_PRELOAD/malicious_preload.so
  🚨 SHARED LIBRARY INJECTION DETECTED
  ⚠️ SUSPICIOUS PATH: Library in temporary directory!
```

## 🧪 Testing and Validation

### Available Makefile Targets

| Target              | Description                                 |
|---------------------|---------------------------------------------|
| `all`               | Build both TOCTOU and LD_PRELOAD modules   |
| `toctou`            | Build TOCTOU detection module              |
| `ldpreload`         | Build LD_PRELOAD detection module          |
| `vmlinux`           | Generate kernel header file                 |
| `test-toctou`       | Show TOCTOU attack test instructions       |
| `test-ldpreload`    | Show LD_PRELOAD injection test instructions|
| `install-toctou`    | Run TOCTOU detector                         |
| `install-ldpreload` | Run LD_PRELOAD monitor                      |
| `clean`             | Clean all build artifacts                   |
| `help`              | Show all available targets                  |

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
   sudo ./TOCTOU-lsm/toctou_loader
   sudo ./LD_PRELOAD/security_monitor
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
   sudo bpftool prog load TOCTOU-lsm/bpf_toctou_detector.o /sys/fs/bpf/toctou_prog
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

This project is released under the Apache License 2.0. See LICENSE file for details.

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