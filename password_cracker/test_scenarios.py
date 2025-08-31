import unittest
import os
from main import calculate_hash, dictionary_attack, brute_force_attack, SessionManager

class TestPasswordCracker(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create a test wordlist
        self.test_wordlist = "test_wordlist.txt"
        with open(self.test_wordlist, "w") as f:
            f.write("password\n")
            f.write("123456\n")
            f.write("qwerty\n")
            f.write("admin\n")
            f.write("letmein\n")
            f.write("welcome\n")
            f.write("monkey\n")
            f.write("dragon\n")
            f.write("test\n")
            f.write("secret\n")
    
    def tearDown(self):
        """Clean up after each test method."""
        if os.path.exists(self.test_wordlist):
            os.remove(self.test_wordlist)
        if os.path.exists("test_session.json"):
            os.remove("test_session.json")
    
    def test_md5_hash_calculation(self):
        """Test MD5 hash calculation."""
        password = "password"
        expected_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        calculated_hash = calculate_hash(password, "md5")
        self.assertEqual(calculated_hash, expected_hash)
    
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

