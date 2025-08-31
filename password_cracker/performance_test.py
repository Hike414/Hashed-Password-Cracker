import time
import hashlib
from main import calculate_hash, dictionary_attack, brute_force_attack

def benchmark_hash_calculation():
    """Benchmark hash calculation performance."""
    print("=== Hash Calculation Performance ===")
    
    password = "testpassword123"
    iterations = 1000
    
    # MD5 benchmark
    start_time = time.time()
    for _ in range(iterations):
        calculate_hash(password, "md5")
    md5_time = time.time() - start_time
    print(f"MD5: {iterations} hashes in {md5_time:.4f}s ({iterations/md5_time:.0f} hashes/sec)")
    
    # SHA-256 benchmark
    start_time = time.time()
    for _ in range(iterations):
        calculate_hash(password, "sha256")
    sha256_time = time.time() - start_time
    print(f"SHA-256: {iterations} hashes in {sha256_time:.4f}s ({iterations/sha256_time:.0f} hashes/sec)")
    
    # Bcrypt benchmark (fewer iterations due to computational cost)
    bcrypt_iterations = 10
    start_time = time.time()
    for _ in range(bcrypt_iterations):
        calculate_hash(password, "bcrypt")
    bcrypt_time = time.time() - start_time
    print(f"Bcrypt: {bcrypt_iterations} hashes in {bcrypt_time:.4f}s ({bcrypt_iterations/bcrypt_time:.2f} hashes/sec)")

def benchmark_dictionary_attack():
    """Benchmark dictionary attack performance."""
    print("\n=== Dictionary Attack Performance ===")
    
    # Create a larger wordlist for testing
    wordlist_file = "performance_wordlist.txt"
    with open(wordlist_file, "w") as f:
        for i in range(10000):
            f.write(f"password{i}\n")
        f.write("targetpassword\n")  # Target password at the end
    
    target_hash = calculate_hash("targetpassword", "md5")
    
    # Test with different thread counts
    for threads in [1, 2, 4, 8]:
        start_time = time.time()
        result = dictionary_attack(target_hash, "md5", wordlist_file, num_threads=threads)
        attack_time = time.time() - start_time
        print(f"Dictionary attack (MD5, {threads} threads): {attack_time:.4f}s - Result: {result}")
    
    # Clean up
    import os
    os.remove(wordlist_file)

def benchmark_brute_force_attack():
    """Benchmark brute-force attack performance."""
    print("\n=== Brute Force Attack Performance ===")
    
    # Test short passwords for reasonable execution time
    target_hash = calculate_hash("ab", "md5")
    charset = "abcdefghijklmnopqrstuvwxyz"
    
    # Test with different thread counts
    for threads in [1, 2, 4, 8]:
        start_time = time.time()
        result = brute_force_attack(target_hash, "md5", charset, 1, 2, num_threads=threads)
        attack_time = time.time() - start_time
        print(f"Brute force attack (MD5, {threads} threads): {attack_time:.4f}s - Result: {result}")

def memory_usage_test():
    """Test memory usage with large wordlists."""
    print("\n=== Memory Usage Test ===")
    
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    # Create a large wordlist
    wordlist_file = "large_wordlist.txt"
    with open(wordlist_file, "w") as f:
        for i in range(100000):
            f.write(f"password{i}\n")
    
    print(f"Initial memory usage: {initial_memory:.2f} MB")
    
    # Load wordlist and perform attack
    target_hash = calculate_hash("password50000", "md5")
    start_time = time.time()
    result = dictionary_attack(target_hash, "md5", wordlist_file, num_threads=4)
    attack_time = time.time() - start_time
    
    peak_memory = process.memory_info().rss / 1024 / 1024  # MB
    print(f"Peak memory usage: {peak_memory:.2f} MB")
    print(f"Memory increase: {peak_memory - initial_memory:.2f} MB")
    print(f"Attack time: {attack_time:.4f}s - Result: {result}")
    
    # Clean up
    os.remove(wordlist_file)

if __name__ == "__main__":
    print("Password Cracker Performance Benchmarks")
    print("=" * 50)
    
    benchmark_hash_calculation()
    benchmark_dictionary_attack()
    benchmark_brute_force_attack()
    memory_usage_test()
    
    print("\n=== Benchmark Complete ===")

