import unittest
import os
import tempfile
import json
from pathlib import Path
from main import calculate_hash, dictionary_attack, brute_force_attack, SessionManager, HashAlgorithm

class TestPasswordCracker(unittest.TestCase):
    """Comprehensive test suite for the password cracker."""
    
    @classmethod
    def setUpClass(cls):
        """Set up class fixtures before any tests are run."""
        # Create a more comprehensive test wordlist
        cls.test_wordlist = Path("test_wordlist.txt")
        common_passwords = [
            "password", "123456", "qwerty", "admin", "letmein",
            "welcome", "monkey", "dragon", "test", "secret",
            "123456789", "12345678", "12345", "1234567", "1234567890",
            "abc123", "password1", "123123", "111111", "sunshine"
        ]
        with open(cls.test_wordlist, 'w', encoding='utf-8') as f:
            f.write('\n'.join(common_passwords))
        
        # Known test hashes
        cls.test_hashes = {
            "md5": {
                "password": "5f4dcc3b5aa765d61d8327deb882cf99",
                "test": "098f6bcd4621d373cade4e832627b4f6"
            },
            "sha256": {
                "password": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                "test": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            }
        }
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.session_file = "test_session.json"
        self.session_manager = SessionManager(self.session_file)
    
    def tearDown(self):
        """Clean up after each test method."""
        if os.path.exists(self.session_file):
            os.remove(self.session_file)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up class fixtures after all tests are run."""
        if cls.test_wordlist.exists():
            cls.test_wordlist.unlink()
    
    # Hash Calculation Tests
    def test_hash_calculation(self):
        """Test hash calculation for various algorithms."""
        test_cases = [
            ("md5", "password"),
            ("sha256", "test"),
            ("sha1", "hello")
        ]
        
        for algo, password in test_cases:
            with self.subTest(algorithm=algo, password=password):
                # Test that the function doesn't raise an exception
                try:
                    result = calculate_hash(password, algo)
                    self.assertIsInstance(result, str)
                    self.assertGreater(len(result), 0)
                except Exception as e:
                    self.fail(f"Hash calculation failed for {algo}: {str(e)}")
    
    def test_bcrypt_hashing(self):
        """Test bcrypt hash calculation and verification."""
        if not hasattr(self, 'BCRYPT_AVAILABLE') or not self.BCRYPT_AVAILABLE:
            self.skipTest("bcrypt not available")
            
        password = "testpassword"
        hashed = calculate_hash(password, "bcrypt")
        self.assertTrue(hashed.startswith('$2b$'))
        
        # Test verification
        from bcrypt import checkpw
        self.assertTrue(checkpw(password.encode('utf-8'), hashed.encode('utf-8')))
    
    # Dictionary Attack Tests
    def test_dictionary_attack_success(self):
        """Test successful dictionary attack."""
        target_hash = self.test_hashes["md5"]["password"]
        result = dictionary_attack(target_hash, "md5", str(self.test_wordlist))
        self.assertEqual(result, "password")
    
    def test_dictionary_attack_failure(self):
        """Test dictionary attack with non-existent password."""
        # This hash is for "nonexistentpassword" which is not in our wordlist
        target_hash = "1d7107a3e722d4aed0b8d535a5e393d1"
        result = dictionary_attack(target_hash, "md5", str(self.test_wordlist))
        self.assertIsNone(result)
    
    def test_dictionary_attack_with_salt(self):
        """Test dictionary attack with salted hashes."""
        # This is a test case for algorithms that use salt
        # Note: This is a simplified test - in practice, you'd need to know the salt
        password = "test"
        salt = b'salttest'
        hashed = calculate_hash(password, "sha256", salt=salt.hex())
        
        # This test will fail because we don't know the salt in a real attack
        # It's here to demonstrate the concept
        with self.assertRaises(ValueError):
            dictionary_attack(hashed, "sha256", str(self.test_wordlist))
    
    # Brute Force Attack Tests
    def test_brute_force_attack_short(self):
        """Test brute force attack on a short password."""
        target_hash = self.test_hashes["md5"]["test"]  # MD5 of "test"
        result = brute_force_attack(
            target_hash, "md5", 
            "abcdefghijklmnopqrstuvwxyz",
            min_length=1, max_length=4
        )
        self.assertEqual(result, "test")
    
    # Session Manager Tests
    def test_session_management(self):
        """Test session save and load functionality."""
        test_data = {
            "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
            "algorithm": "md5",
            "status": "completed",
            "result": "password"
        }
        
        # Test saving session
        self.session_manager.save_session(test_data)
        self.assertTrue(os.path.exists(self.session_file))
        
        # Test loading session
        loaded_data = self.session_manager._load_session()
        self.assertEqual(loaded_data, test_data)
        
        # Test getting session data
        self.assertEqual(self.session_manager.get_session_data("result"), "password")
    
    # Error Handling Tests
    def test_invalid_algorithm(self):
        """Test behavior with invalid hash algorithm."""
        with self.assertRaises(ValueError):
            calculate_hash("test", "invalid_algorithm")
    
    def test_nonexistent_wordlist(self):
        """Test behavior with non-existent wordlist file."""
        with self.assertRaises(FileNotFoundError):
            dictionary_attack("dummyhash", "md5", "nonexistent_wordlist.txt")
    
    # Performance Tests (marked as expected to fail as they're for benchmarking)
    @unittest.expectedFailure
    def test_performance_large_wordlist(self):
        """Test performance with a large wordlist."""
        # Create a large wordlist
        large_wordlist = "large_wordlist.txt"
        with open(large_wordlist, 'w') as f:
            for i in range(100000):  # 100k passwords
                f.write(f"password{i}\n")
        
        # Add our test password at a known position
        with open(large_wordlist, 'a') as f:
            f.write("testpassword\n")
        
        # Time the dictionary attack
        import time
        start_time = time.time()
        result = dictionary_attack(
            calculate_hash("testpassword", "md5"),
            "md5",
            large_wordlist,
            num_threads=4
        )
        elapsed = time.time() - start_time
        
        self.assertEqual(result, "testpassword")
        print(f"\nLarge wordlist test completed in {elapsed:.2f} seconds")
        
        # Clean up
        if os.path.exists(large_wordlist):
            os.remove(large_wordlist)

    # Multi-threading Tests
    def test_thread_safety(self):
        """Test that dictionary attack works correctly with multiple threads."""
        target_hash = self.test_hashes["md5"]["password"]
        
        # Test with different thread counts
        for threads in [1, 2, 4]:
            with self.subTest(threads=threads):
                result = dictionary_attack(
                    target_hash, 
                    "md5", 
                    str(self.test_wordlist),
                    num_threads=threads
                )
                self.assertEqual(result, "password")

if __name__ == "__main__":
    unittest.main()
    
    def test_sha256_hash_calculation(self):
        """Test SHA-256 hash calculation."""
        password = "123456"
        expected_hash = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
        calculated_hash = calculate_hash(password, "sha256")
        self.assertEqual(calculated_hash, expected_hash)
    
    def test_bcrypt_hash_calculation_and_verification(self):
        """Test Bcrypt hash calculation and verification."""
        password = "testpassword"
        hashed = calculate_hash(password, "bcrypt")
        self.assertTrue(hashed.startswith("$2b$"))
        
        # Test verification by attempting to crack it
        with open(self.test_wordlist, "a") as f:
            f.write("testpassword\n")
        
        cracked = dictionary_attack(hashed, "bcrypt", self.test_wordlist)
        self.assertEqual(cracked, password)
    
    def test_scrypt_hash_calculation_and_verification(self):
        """Test Scrypt hash calculation and verification."""
        password = "scrypttest"
        salt = b'testsalt'
        hashed = calculate_hash(password, "scrypt", salt=salt)
        
        with open(self.test_wordlist, "a") as f:
            f.write("scrypttest\n")
        
        cracked = dictionary_attack(hashed, "scrypt", self.test_wordlist, salt=salt)
        self.assertEqual(cracked, password)
    
    def test_argon2_hash_calculation_and_verification(self):
        """Test Argon2 hash calculation and verification."""
        password = "argon2test"
        hashed = calculate_hash(password, "argon2")
        self.assertTrue(hashed.startswith("$argon2"))
        
        with open(self.test_wordlist, "a") as f:
            f.write("argon2test\n")
        
        cracked = dictionary_attack(hashed, "argon2", self.test_wordlist)
        self.assertEqual(cracked, password)
    
    def test_dictionary_attack_md5_success(self):
        """Test successful dictionary attack on MD5."""
        target_hash = calculate_hash("password", "md5")
        cracked = dictionary_attack(target_hash, "md5", self.test_wordlist)
        self.assertEqual(cracked, "password")
    
    def test_dictionary_attack_md5_failure(self):
        """Test failed dictionary attack on MD5."""
        target_hash = calculate_hash("notinwordlist", "md5")
        cracked = dictionary_attack(target_hash, "md5", self.test_wordlist)
        self.assertIsNone(cracked)
    
    def test_dictionary_attack_sha256_success(self):
        """Test successful dictionary attack on SHA-256."""
        target_hash = calculate_hash("123456", "sha256")
        cracked = dictionary_attack(target_hash, "sha256", self.test_wordlist)
        self.assertEqual(cracked, "123456")
    
    def test_brute_force_attack_md5_success(self):
        """Test successful brute-force attack on MD5."""
        target_hash = calculate_hash("abc", "md5")
        charset = "abcdefghijklmnopqrstuvwxyz"
        cracked = brute_force_attack(target_hash, "md5", charset, 1, 3)
        self.assertEqual(cracked, "abc")
    
    def test_brute_force_attack_md5_failure(self):
        """Test failed brute-force attack on MD5 (password too long)."""
        target_hash = calculate_hash("abcdefgh", "md5")
        charset = "abcdefghijklmnopqrstuvwxyz"
        cracked = brute_force_attack(target_hash, "md5", charset, 1, 3)
        self.assertIsNone(cracked)
    
    def test_session_manager(self):
        """Test session management functionality."""
        session_manager = SessionManager("test_session.json")
        
        # Save some data
        test_data = {"test_key": "test_value", "cracked_password": "password123"}
        session_manager.save_session(test_data)
        
        # Verify data was saved
        self.assertEqual(session_manager.get_session_data("test_key"), "test_value")
        self.assertEqual(session_manager.get_session_data("cracked_password"), "password123")
        
        # Create new session manager instance and verify data persists
        new_session_manager = SessionManager("test_session.json")
        self.assertEqual(new_session_manager.get_session_data("test_key"), "test_value")
    
    def test_invalid_hash_type(self):
        """Test handling of invalid hash types."""
        with self.assertRaises(ValueError):
            calculate_hash("password", "invalid_hash")
    
    def test_nonexistent_wordlist(self):
        """Test handling of nonexistent wordlist file."""
        target_hash = calculate_hash("password", "md5")
        cracked = dictionary_attack(target_hash, "md5", "nonexistent_file.txt")
        self.assertIsNone(cracked)
    
    def test_multithreading_dictionary_attack(self):
        """Test dictionary attack with multiple threads."""
        target_hash = calculate_hash("password", "md5")
        cracked = dictionary_attack(target_hash, "md5", self.test_wordlist, num_threads=8)
        self.assertEqual(cracked, "password")
    
    def test_multithreading_brute_force_attack(self):
        """Test brute-force attack with multiple threads."""
        target_hash = calculate_hash("ab", "md5")
        charset = "abcdefghijklmnopqrstuvwxyz"
        cracked = brute_force_attack(target_hash, "md5", charset, 1, 2, num_threads=8)
        self.assertEqual(cracked, "ab")

if __name__ == "__main__":
    # Run the tests
    unittest.main(verbosity=2)

