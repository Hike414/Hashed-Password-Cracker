# Advanced Hash-Based Password Cracker

## Overview

The Advanced Hash-Based Password Cracker is a comprehensive security testing tool designed for educational purposes and authorized penetration testing. This tool implements multiple password cracking techniques and supports various hash algorithms commonly encountered in security assessments.

## Features

### Supported Hash Algorithms
- **MD5**: Fast but cryptographically broken hash function
- **SHA-256**: Secure Hash Algorithm with 256-bit output
- **Bcrypt**: Adaptive hash function designed for password hashing
- **Scrypt**: Memory-hard key derivation function
- **Argon2**: Winner of the Password Hashing Competition

### Attack Methods
- **Dictionary Attack**: Uses predefined wordlists to guess passwords
- **Brute Force Attack**: Systematically tries all possible character combinations
- **Multi-threaded Processing**: Utilizes multiple CPU cores for improved performance

### Optimization Features
- **Session Management**: Save and resume cracking sessions
- **Multi-threading**: Parallel processing for faster results
- **Memory Efficient**: Optimized for handling large wordlists
- **Progress Tracking**: Monitor cracking progress and performance

### User Interfaces
- **Command Line Interface (CLI)**: Full-featured command-line tool
- **Graphical User Interface (GUI)**: Modern React-based web interface

## Installation

### Prerequisites
- Python 3.11 or higher
- Node.js 20.x (for GUI)
- Required Python packages (see requirements below)

### Python Dependencies
```bash
pip install bcrypt scrypt argon2-cffi psutil
```

### GUI Dependencies
The GUI is built with React and includes:
- Tailwind CSS for styling
- shadcn/ui components
- Lucide icons
- Vite for development

## Usage

### Command Line Interface

#### Basic Dictionary Attack
```bash
python3.11 cli.py <hash> --type <hash_type> --attack dictionary --wordlist <wordlist_file>
```

#### Example: MD5 Dictionary Attack
```bash
python3.11 cli.py 5f4dcc3b5aa765d61d8327deb882cf99 --type md5 --attack dictionary --wordlist wordlist.txt
```

#### Brute Force Attack
```bash
python3.11 cli.py <hash> --type <hash_type> --attack brute-force --charset <characters> --min-length <min> --max-length <max>
```

#### Example: MD5 Brute Force Attack
```bash
python3.11 cli.py 900150983cd24fb0d6963f7d28e17f72 --type md5 --attack brute-force --charset abcdefghijklmnopqrstuvwxyz --min-length 1 --max-length 3
```

#### Advanced Options
- `--threads <number>`: Specify number of threads (default: 4)
- `--salt <hex_string>`: Provide salt for scrypt hashes
- `--session <file>`: Specify session file for progress saving

### Graphical User Interface

1. Navigate to the GUI directory:
```bash
cd password-cracker-gui
```

2. Start the development server:
```bash
pnpm run dev --host
```

3. Open your browser and navigate to the provided URL (typically http://localhost:5174)

### Python API

You can also use the password cracker as a Python library:

```python
from main import calculate_hash, dictionary_attack, brute_force_attack

# Calculate hash
hash_value = calculate_hash("password", "md5")

# Dictionary attack
result = dictionary_attack(hash_value, "md5", "wordlist.txt")

# Brute force attack
result = brute_force_attack(hash_value, "md5", "abcdefghijklmnopqrstuvwxyz", 1, 8)
```

## Performance Benchmarks

Based on testing on a modern system, the password cracker achieves the following performance:

### Hash Calculation Speed
- **MD5**: ~1,400,000 hashes/second
- **SHA-256**: ~1,200,000 hashes/second
- **Bcrypt**: ~3.6 hashes/second (intentionally slow for security)

### Multi-threading Performance
Dictionary attacks show significant improvement with multiple threads:
- 1 thread: 0.314 seconds
- 4 threads: 0.175 seconds
- 8 threads: 0.101 seconds

### Memory Usage
- Base memory usage: ~37 MB
- With 100,000 word dictionary: ~110 MB
- Memory increase: ~73 MB for large wordlists

## Security Considerations

### Ethical Use
This tool is designed for:
- Educational purposes
- Authorized penetration testing
- Security research
- Password strength assessment

### Legal Disclaimer
Users are responsible for ensuring they have proper authorization before using this tool. Unauthorized access to computer systems is illegal in most jurisdictions.

### Best Practices
- Only test on systems you own or have explicit permission to test
- Use strong, unique passwords for your own accounts
- Implement proper access controls and monitoring
- Consider using password managers for secure password generation

## File Structure

```
password_cracker/
├── main.py                 # Core password cracking functionality
├── cli.py                  # Command-line interface
├── test_scenarios.py       # Comprehensive test suite
├── performance_test.py     # Performance benchmarking
├── session.json           # Session data (created during use)
├── dummy_wordlist.txt     # Sample wordlist for testing
├── password-cracker-gui/  # React GUI application
│   ├── src/
│   │   ├── App.jsx        # Main GUI component
│   │   └── ...
│   ├── package.json
│   └── ...
└── README.md              # This documentation
```

## Testing

### Unit Tests
Run the comprehensive test suite:
```bash
python3.11 test_scenarios.py
```

The test suite includes:
- Hash calculation verification
- Dictionary attack testing
- Brute force attack testing
- Multi-threading validation
- Session management testing
- Error handling verification

### Performance Testing
Run performance benchmarks:
```bash
python3.11 performance_test.py
```

## Technical Implementation

### Core Architecture
The password cracker is built with a modular architecture:

1. **Hash Calculation Module**: Handles various hash algorithms
2. **Attack Engines**: Implements dictionary and brute force attacks
3. **Session Manager**: Provides persistence and resume functionality
4. **Threading Framework**: Enables parallel processing
5. **User Interfaces**: CLI and GUI for different use cases

### Multi-threading Implementation
The tool uses Python's `concurrent.futures.ThreadPoolExecutor` for parallel processing, allowing efficient utilization of multiple CPU cores during password cracking operations.

### Session Management
Session data is stored in JSON format, allowing users to save progress and resume interrupted cracking sessions.

## Troubleshooting

### Common Issues

#### "Module not found" errors
Ensure all required packages are installed:
```bash
pip install bcrypt scrypt argon2-cffi psutil
```

#### GUI not loading
1. Ensure Node.js is installed
2. Navigate to the GUI directory
3. Install dependencies: `pnpm install`
4. Start the development server: `pnpm run dev --host`

#### Slow performance
- Increase thread count with `--threads` parameter
- Use smaller wordlists for testing
- Consider the computational cost of secure hash functions like Bcrypt

### Performance Optimization
- Use SSD storage for large wordlists
- Increase available RAM for better performance
- Consider GPU acceleration for future versions

## Future Enhancements

### Planned Features
- GPU acceleration support
- Rainbow table attacks
- Hybrid attack methods
- Distributed cracking across multiple machines
- Additional hash algorithm support
- Advanced rule-based attacks

### Contributing
This project is designed for educational purposes. Contributions should focus on:
- Performance improvements
- Additional hash algorithm support
- Enhanced user interface features
- Better documentation and examples

## License and Disclaimer

This software is provided for educational and authorized security testing purposes only. Users are solely responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse of this software.

## Version Information

- **Version**: 1.0.0
- **Author**: 
  
  ![](seal.png)
  
- **Last Updated**: August 31, 2025
- **Python Version**: 3.11+
- **Node.js Version**: 20.x+
