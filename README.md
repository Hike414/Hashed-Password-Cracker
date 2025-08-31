# 🔓 Advanced Hash-Based Password Cracker
```
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ██╗  ██╗ █████╗ ███████╗██╗  ██╗██████╗ ██████╗ ███████╗    ║
    ║   ██║  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗██╔══██╗██╔════╝    ║
    ║   ███████║███████║███████╗███████║██████╔╝██████╔╝██          ║
    ║   ██╔══██║██╔══██║╚════██║██╔══██║██╔═══╝ ██╔══██╗██╔════╗    ║
    ║   ██║  ██║██║  ██║███████║██║  ██║██║     ██████╔╝███████╗    ║
    ║   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═════╝ ╚══════╝    ║
    ║                                                               ║
    ║              [ ADVANCED PASSWORD CRACKING SUITE ]             ║
    ║                     [ FOR PENTESTERS ONLY ]                   ║
    ╚═══════════════════════════════════════════════════════════════╝
```

## 💀 OVERVIEW

Welcome to the underground, fellow h4x0r. This ain't your script kiddie tool - it's a military-grade password cracking arsenal designed for serious penetration testing and educational warfare. Born from the necessity to break through digital fortresses, this beast implements multiple attack vectors against the most common hash algorithms you'll encounter in the wild.

**WARNING**: This tool is designed for WHITE HAT operations only. Use responsibly or face the consequences.

---

## ⚡ WEAPONIZED FEATURES

### 🎯 SUPPORTED HASH TARGETS
```
[+] MD5        → Legacy target, trivial to crack
[+] SHA-256    → More robust, but not unbreakable  
[+] Bcrypt     → Adaptive beast, slow but steady
[+] Scrypt     → Memory-hungry algorithm
[+] Argon2     → The new sheriff in town
```

### 🔥 ATTACK VECTORS
```
┌─────────────────────────────────────────────────────┐
│ [DICT]  Dictionary Attack  → Wordlist bombardment   │
│ [BRUTE] Brute Force       → Raw computational power │
│ [MULTI] Multi-threading   → Parallel assault        │
└─────────────────────────────────────────────────────┘
```

### 🚀 OPTIMIZATION ARSENAL
- **Session Management** → Never lose progress in long campaigns
- **Multi-threading** → Harness the full power of your rig
- **Memory Efficient** → Handle massive wordlists without breaking a sweat  
- **Progress Tracking** → Monitor your digital siege in real-time

### 🖥️ DUAL INTERFACE MODES
- **CLI Mode** → For the terminal warriors
- **GUI Mode** → For those who prefer point-and-click warfare

---

## 🛠️ INSTALLATION & DEPLOYMENT

### ⚙️ PREREQUISITES
```bash
# Minimum system requirements
Python 3.11+     # The snake that bites
Node.js 20.x     # For the web interface
```

### 📦 PYTHON ARSENAL
```bash
# Deploy the core dependencies
pip install bcrypt scrypt argon2-cffi psutil
```

### 🌐 GUI DEPLOYMENT
Built with cutting-edge tech stack:
```
React + Tailwind CSS + shadcn/ui + Lucide + Vite
```

---

## 🎮 OPERATIONAL MANUAL

### 💻 COMMAND LINE WARFARE

#### 📖 Dictionary Assault
```bash
# Basic dictionary bombardment
python3.11 cli.py <target_hash> --type <hash_algo> --attack dictionary --wordlist <wordlist_path>

# Example: Crack MD5 with rockyou.txt
python3.11 cli.py 5f4dcc3b5aa765d61d8327deb882cf99 --type md5 --attack dictionary --wordlist rockyou.txt
```

#### 💥 Brute Force Annihilation
```bash
# Raw computational assault
python3.11 cli.py <target_hash> --type <hash_algo> --attack brute-force --charset <char_set> --min-length <min> --max-length <max>

# Example: Crack 3-char lowercase MD5
python3.11 cli.py 900150983cd24fb0d6963f7d28e17f72 --type md5 --attack brute-force --charset abcdefghijklmnopqrstuvwxyz --min-length 1 --max-length 3
```

#### 🔧 ADVANCED TACTICAL OPTIONS
```bash
--threads <n>         # Unleash parallel processing power
--salt <hex>          # Handle salted targets (scrypt)
--session <file>      # Save/resume your campaigns
```

### 🌐 WEB INTERFACE DEPLOYMENT

```bash
# Enter the GUI battleground
cd password-cracker-gui

# Launch the interface
pnpm run dev --host

# Access via browser: http://localhost:5174
```

### 🐍 PYTHON API INTEGRATION

```python
from main import calculate_hash, dictionary_attack, brute_force_attack

# Calculate target hash
target = calculate_hash("password", "md5")

# Launch dictionary strike
result = dictionary_attack(target, "md5", "wordlist.txt")

# Initiate brute force campaign  
result = brute_force_attack(target, "md5", "abcdefghijklmnopqrstuvwxyz", 1, 8)
```

---

## ⚡ PERFORMANCE METRICS

### 🔥 HASH COMPUTATION SPEEDS
```
┌─────────────┬─────────────────────┐
│ Algorithm   │ Speed (hashes/sec)  │
├─────────────┼─────────────────────┤
│ MD5         │ ~1,400,000          │
│ SHA-256     │ ~1,200,000          │
│ Bcrypt      │ ~3.6 (by design)    │
└─────────────┴─────────────────────┘
```

### 🚀 MULTI-THREADING DOMINANCE
```
Threads    │ Execution Time    │ Performance Gain
───────────┼──────────────────┼─────────────────
1 thread   │ 0.314 seconds    │ Baseline
4 threads  │ 0.175 seconds    │ 79% faster
8 threads  │ 0.101 seconds    │ 211% faster
```

### 💾 MEMORY WARFARE
```
Base footprint:           ~37 MB
100K wordlist loaded:     ~110 MB
Memory overhead:          ~73 MB
```

---

## ⚠️ SECURITY & ETHICS

### 🎯 AUTHORIZED TARGETS ONLY
```
[✓] Educational environments
[✓] Authorized pen-testing
[✓] Security research
[✓] Your own systems
[✗] Unauthorized access
[✗] Illegal activities
```

### ⚖️ LEGAL DISCLAIMER
```
╔══════════════════════════════════════════════════════╗
║  WARNING: Unauthorized access is ILLEGAL             ║
║  This tool is for AUTHORIZED testing ONLY            ║
║  Use at your own risk and responsibility             ║
╚══════════════════════════════════════════════════════╝
```

### 🛡️ OPERATIONAL SECURITY
- Only engage targets you own or have explicit written permission to test
- Deploy strong, unique passwords for your own digital assets
- Implement proper access controls and real-time monitoring
- Consider using password managers for secure credential generation

---

## 📁 PROJECT ARCHITECTURE

```
password_cracker/
├── 🐍 main.py                 # Core cracking engine
├── 💻 cli.py                  # Terminal interface
├── 🧪 test_scenarios.py       # Battle-tested scenarios
├── 📊 performance_test.py     # Benchmarking suite
├── 💾 session.json           # Campaign persistence
├── 📝 dummy_wordlist.txt     # Training ammunition
├── 🌐 password-cracker-gui/  # Web-based command center
│   ├── src/
│   │   ├── App.jsx        # Main control panel
│   │   └── ...
│   ├── package.json
│   └── ...
└── 📖 README.md              # This war manual
```

---

## 🧪 TESTING & VALIDATION

### 🎯 UNIT TEST BATTERY
```bash
# Deploy full test suite
python -m unittest password_cracker/test_scenarios.py -v
```

#### 🔬 TEST MATRIX
```
[+] Hash Calculation Verification
    ├── MD5/SHA-1/SHA-256 accuracy
    ├── Bcrypt implementation validation  
    └── Error handling for invalid algorithms

[+] Dictionary Attack Validation
    ├── Successful password recovery scenarios
    ├── Handling of failed attempts
    ├── Multi-threaded performance validation
    └── Large wordlist stress testing

[+] Brute Force Attack Testing
    ├── Short password recovery validation
    ├── Configurable character set testing
    └── Length-based generation verification

[+] Session Management Testing
    ├── Save/load functionality
    ├── Progress tracking accuracy
    └── Result persistence validation

[+] Error Handling Matrix
    ├── Invalid algorithm detection
    ├── Missing file handling
    └── Input validation testing
```

### 📈 PERFORMANCE BENCHMARKING

```bash
# Launch comprehensive performance analysis
python -m password_cracker.performance_test
```

#### 📊 BENCHMARK CATEGORIES
```
⚡ Hash Calculation Metrics
├── Operations/second per algorithm
├── Memory consumption analysis
└── Multi-threading scaling impact

🎯 Dictionary Attack Analysis  
├── Passwords processed/second
├── Wordlist size scaling (100-100K entries)
└── Thread efficiency measurement (1-8 cores)

💥 Brute Force Performance
├── Attempts/second measurement
├── Password length impact analysis
└── Character set complexity effects
```

#### 📋 SAMPLE BENCHMARK OUTPUT
```
╔═════════════════════════════════════════════════════════════╗
║                    SYSTEM RECONNAISSANCE                    ║
╠═════════════════════════════════════════════════════════════╣
║ OS:        Windows                                          ║
║ CPU:       Intel(R) Core(TM) i7-10750H @ 2.60GHz            ║
║ Python:    3.11.4                                           ║
║ Cores:     6                                                ║
║ RAM:       16.0 GB                                          ║
╚═════════════════════════════════════════════════════════════╝

╔═════════════════════════════════════════════════════════════╗
║                    HASH PERFORMANCE METRICS                 ║
╠═════════════════════════════════════════════════════════════╣
║ MD5:           1,450,000 hashes/sec                         ║
║ SHA-256:       1,210,000 hashes/sec                         ║
║ Bcrypt:             320 hashes/sec                          ║
╚═════════════════════════════════════════════════════════════╝

╔═════════════════════════════════════════════════════════════╗
║           DICTIONARY ATTACK (10,000 TARGETS)                ║
╠═════════════════════════════════════════════════════════════╣
║ MD5 (1 thread):      25,000 pwd/sec                         ║
║ MD5 (4 threads):     92,000 pwd/sec                         ║
║ SHA-256 (4 threads): 88,000 pwd/sec                         ║
╚═════════════════════════════════════════════════════════════╝

╔═════════════════════════════════════════════════════════════╗
║        BRUTE FORCE (lowercase, 3-char targets)              ║
╠═════════════════════════════════════════════════════════════╣
║ MD5: 15,000 attempts/sec                                    ║
╚═════════════════════════════════════════════════════════════╝
```

### 💾 MEMORY PROFILING
```
Memory footprint analysis:
├── Base operation:        ~35 MB
├── 100K wordlist load:    ~75 MB additional
└── Memory cleanup:        Verified ✓
```

### 🔄 CONTINUOUS INTEGRATION PIPELINE
```yaml
# .github/workflows/tests.yml
name: 🧪 Automated Testing Pipeline

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - name: 📥 Clone Repository
      uses: actions/checkout@v3
    - name: 🐍 Deploy Python 3.11
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    - name: 📦 Install Dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements-dev.txt
    - name: 🚀 Execute Test Battery
      run: |
        python -m unittest discover -s tests -v
        python -m password_cracker.performance_test --output test-results/performance.txt
    - name: 📊 Upload Battle Results
      uses: actions/upload-artifact@v3
      with:
        name: test-results
        path: test-results/
```

### 📊 TEST COVERAGE ANALYSIS
```bash
# Deploy coverage analysis
pip install coverage
coverage run -m unittest discover -s tests
coverage report -m
```

### 🔍 ADVANCED PROFILING
```bash
# Profile dictionary assault performance
python -m cProfile -o dict_attack.prof -m password_cracker.test_scenarios TestPasswordCracker.test_dictionary_attack

# Generate visual analysis
snakeviz dict_attack.prof
```

---

## 🏗️ TECHNICAL ARCHITECTURE

### 🧠 CORE SYSTEM DESIGN
```
┌─────────────────────────────────────────────────────────┐
│                    MODULAR ARCHITECTURE                 │
├─────────────────────────────────────────────────────────┤
│ [HASH ENGINE]     → Multi-algorithm hash processing     │
│ [ATTACK CORES]    → Dictionary & brute force engines    │
│ [SESSION MGR]     → Campaign persistence & recovery     │
│ [THREAD POOL]     → Parallel processing framework       │ 
│ [UI LAYERS]       → CLI & GUI interface systems         │
└─────────────────────────────────────────────────────────┘
```

### ⚙️ MULTI-THREADING IMPLEMENTATION
Powered by Python's `concurrent.futures.ThreadPoolExecutor` for maximum CPU core utilization during assault operations.

### 💾 SESSION PERSISTENCE
JSON-based session storage enables campaign interruption and resumption without losing progress.

---

## 🔧 TROUBLESHOOTING & FIXES

### ❌ COMMON BATTLEFIELD ISSUES

#### Module Import Failures
```bash
# Deploy missing dependencies
pip install bcrypt scrypt argon2-cffi psutil
```

#### GUI Deployment Failures
```bash
# 1. Verify Node.js installation
# 2. Navigate to GUI directory
cd password-cracker-gui

# 3. Install dependencies
pnpm install

# 4. Launch interface
pnpm run dev --host
```

#### Performance Degradation
```
[!] Increase thread count: --threads <number>
[!] Use smaller wordlists for testing
[!] Remember: Bcrypt is DESIGNED to be slow
```

### 🚀 PERFORMANCE OPTIMIZATION
```
Hardware Recommendations:
├── SSD storage for wordlist I/O
├── Maximum available RAM
└── Multi-core CPU for threading
```

---

## 🔮 FUTURE WEAPONIZATION

### 🎯 PLANNED UPGRADES
```
[COMING SOON]
├── 🎮 GPU acceleration support
├── 🌈 Rainbow table attacks  
├── 🔄 Hybrid attack methodologies
├── 🌐 Distributed cracking networks
├── 📚 Extended hash algorithm support
└── 🧠 AI-powered rule-based attacks
```

### 🤝 CONTRIBUTION GUIDELINES
Join the resistance! Focus contributions on:
- Performance enhancements
- New hash algorithm implementations
- Enhanced UI/UX features
- Documentation improvements

---

## ⚖️ LEGAL & DISCLAIMER

```
╔═══════════════════════════════════════════════════════════════╗
║                         ⚠️  NOTICE  ⚠️                       ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  This software is provided for EDUCATIONAL and AUTHORIZED     ║
║  security testing purposes ONLY. Users bear FULL              ║
║  responsibility for legal compliance. Authors assume NO       ║
║  liability for misuse. Use wisely, hack responsibly.          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## 📋 SYSTEM METADATA

```
┌─────────────────────────────────────────────────────────┐
│ Version:      1.0.0                                     │
│ Author:                                                 │
│                ![](seal.png)                            │
│ Last Update:  August 31, 2025                           │
│ Python Req:   3.11+                                     │
│ Node.js Req:  20.x+                                     │
│ License:      Educational/Authorized Testing Only       │
└─────────────────────────────────────────────────────────┘
```

---

```
    ╔════════════════════════════════════════════════════════╗
    ║  "The best way to secure a system is to think like     ║
    ║   an attacker. Know your enemy, know their tools."     ║
    ║                                         - Anonymous    ║
    ╚════════════════════════════════════════════════════════╝
```

**Remember**: With great power comes great responsibility. Happy hacking, but keep it legal! 🔒
