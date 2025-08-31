#!/usr/bin/env python3
"""
Performance Testing Module for Advanced Hash-Based Password Cracker

This module provides performance testing and benchmarking for the password cracker.
It measures the performance of different hash algorithms and attack methods.
"""

import time
import statistics
import argparse
import os
import sys
import psutil
import platform
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

# Add parent directory to path to import the main module
sys.path.insert(0, str(Path(__file__).parent.parent))

from password_cracker.main import (
    calculate_hash,
    dictionary_attack,
    brute_force_attack,
    HashAlgorithm
)

class PerformanceTester:
    """Class for running performance tests on the password cracker."""
    
    def __init__(self, output_file: str = "performance_results.txt"):
        """Initialize the performance tester.
        
        Args:
            output_file: Path to save the performance results
        """
        self.output_file = output_file
        self.results: List[Dict[str, Any]] = []
        self.wordlist_sizes = [100, 1000, 10000, 50000]
        self.test_passwords = {
            "short": "pass",
            "medium": "password123",
            "long": "ThisIsAVeryLongPassword123!@#"
        }
        self.system_info = self._get_system_info()
    
    def _get_system_info(self) -> Dict[str, str]:
        """Get information about the system running the tests."""
        return {
            "system": platform.system(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "cpu_cores": psutil.cpu_count(logical=False) or 0,
            "total_ram_gb": round(psutil.virtual_memory().total / (1024 ** 3), 1)
        }
    
    def _time_function(self, func, *args, **kwargs) -> Tuple[float, Any]:
        """Time a function's execution and return the time taken and result."""
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        return (end_time - start_time), result
    
    def _generate_wordlist(self, size: int) -> str:
        """Generate a wordlist of the specified size."""
        wordlist_path = f"wordlist_{size}.txt"
        with open(wordlist_path, 'w', encoding='utf-8') as f:
            # Add some common passwords at the beginning
            common = [
                "password", "123456", "qwerty", "letmein", "welcome",
                "monkey", "dragon", "test", "secret", "admin"
            ]
            for word in common:
                f.write(f"{word}\n")
            
            # Generate the rest of the words
            for i in range(len(common), size):
                f.write(f"password{i}\n")
        
        return wordlist_path
    
    def _cleanup_wordlists(self):
        """Remove generated wordlist files."""
        for size in self.wordlist_sizes:
            path = f"wordlist_{size}.txt"
            if os.path.exists(path):
                os.remove(path)
    
    def test_hash_speed(self, algo: str, password: str, iterations: int = 1000) -> Dict[str, Any]:
        """Test the speed of a hash function."""
        print(f"Testing {algo} hashing speed with {iterations} iterations...")
        
        # Warm-up
        for _ in range(10):
            calculate_hash(password, algo)
        
        # Run the test
        times = []
        for _ in range(iterations):
            time_taken, _ = self._time_function(calculate_hash, password, algo)
            times.append(time_taken)
        
        avg_time = statistics.mean(times)
        hashes_per_second = 1 / avg_time if avg_time > 0 else float('inf')
        
        result = {
            "test_type": "hash_speed",
            "algorithm": algo,
            "password_length": len(password),
            "iterations": iterations,
            "avg_time_seconds": avg_time,
            "hashes_per_second": hashes_per_second,
            "total_time_seconds": sum(times)
        }
        
        self.results.append(result)
        self._print_result(result)
        return result
    
    def test_dictionary_attack(self, algo: str, wordlist_size: int, num_threads: int = 4) -> Dict[str, Any]:
        """Test the speed of a dictionary attack."""
        print(f"Testing {algo} dictionary attack with {wordlist_size} words and {num_threads} threads...")
        
        # Generate a wordlist
        wordlist_path = self._generate_wordlist(wordlist_size)
        
        try:
            # Create a test hash (using the last password in the wordlist)
            test_password = f"password{wordlist_size-1}"
            target_hash = calculate_hash(test_password, algo)
            
            # Time the attack
            time_taken, result = self._time_function(
                dictionary_attack,
                target_hash,
                algo,
                wordlist_path,
                num_threads=num_threads
            )
            
            # Verify the result
            success = result == test_password
            
            result_data = {
                "test_type": "dictionary_attack",
                "algorithm": algo,
                "wordlist_size": wordlist_size,
                "num_threads": num_threads,
                "time_seconds": time_taken,
                "success": success,
                "passwords_per_second": wordlist_size / time_taken if time_taken > 0 else float('inf')
            }
            
            self.results.append(result_data)
            self._print_result(result_data)
            return result_data
            
        finally:
            # Clean up the wordlist
            if os.path.exists(wordlist_path):
                os.remove(wordlist_path)
    
    def _print_result(self, result: Dict[str, Any]):
        """Print a test result in a human-readable format."""
        if result["test_type"] == "hash_speed":
            print((
                f"{result['algorithm'].upper():<8} | "
                f"Length: {result['password_length']:<2} | "
                f"{result['hashes_per_second']:,.0f} hashes/sec | "
                f"{result['avg_time_seconds']*1e6:,.2f} μs/op"
            ))
        elif result["test_type"] == "dictionary_attack":
            status = "✓" if result["success"] else "✗"
            print((
                f"Dict {result['algorithm'].upper():<6} | "
                f"Words: {result['wordlist_size']:<6} | "
                f"Threads: {result['num_threads']:<2} | "
                f"{result['passwords_per_second']:,.0f} pwd/sec | "
                f"{result['time_seconds']:.3f}s {status}"
            ))
    
    def run_all_tests(self):
        """Run all performance tests."""
        print("\n" + "="*50)
        print("Password Cracker Performance Tests")
        print("="*50)
        
        # Print system information
        print("\n=== System Information ===")
        for key, value in self.system_info.items():
            print(f"{key.replace('_', ' ').title()}: {value}")
        
        # Test hash speeds
        print("\n=== Hash Performance ===")
        for algo in ["md5", "sha1", "sha256", "bcrypt"]:
            for pwd_name, password in self.test_passwords.items():
                self.test_hash_speed(algo, password)
        
        # Test dictionary attacks
        print("\n=== Dictionary Attack Performance ===")
        for algo in ["md5", "sha256"]:
            for size in self.wordlist_sizes:
                for threads in [1, 2, 4]:
                    self.test_dictionary_attack(algo, size, threads)
        
        print("\nTests completed!")
        
        # Save results
        self._save_results()
    
    def _save_results(self):
        """Save test results to a file."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "system_info": self.system_info,
            "results": self.results
        }
        
        os.makedirs(os.path.dirname(self.output_file) or ".", exist_ok=True)
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            import json
            json.dump(results, f, indent=2)
        
        print(f"\nResults saved to: {os.path.abspath(self.output_file)}")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run performance tests for the password cracker.')
    parser.add_argument('--output', '-o', default='performance_results.json',
                      help='Output file for test results (default: performance_results.json)')
    return parser.parse_args()


def main():
    """Main function to run performance tests."""
    args = parse_args()
    tester = PerformanceTester(args.output)
    
    try:
        tester.run_all_tests()
    except KeyboardInterrupt:
        print("\nTest interrupted by user.")
        tester._save_results()
        sys.exit(1)
    except Exception as e:
        print(f"\nError during testing: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
