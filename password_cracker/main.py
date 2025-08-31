
import hashlib
import bcrypt
import scrypt
from argon2 import PasswordHasher
import itertools
from concurrent.futures import ThreadPoolExecutor
import json
import os

class SessionManager:
    def __init__(self, session_file="session.json"):
        self.session_file = session_file
        self.session_data = self._load_session()

    def _load_session(self):
        if os.path.exists(self.session_file):
            with open(self.session_file, "r") as f:
                return json.load(f)
        return {}

    def save_session(self, data):
        self.session_data.update(data)
        with open(self.session_file, "w") as f:
            json.dump(self.session_data, f, indent=4)

    def get_session_data(self, key):
        return self.session_data.get(key)


def calculate_hash(password, hash_type, salt=None):
    """
    Calculates the hash of a given password using the specified hash type.
    Salt is required for bcrypt, scrypt, and argon2.
    """
    if hash_type == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif hash_type == "bcrypt":
        if salt is None:
            salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt).decode("utf-8")
    elif hash_type == "scrypt":
        if salt is None:
            salt = b'randomsalt'
        return scrypt.hash(password.encode(), salt, N=16384, r=8, p=1, buflen=32).hex()
    elif hash_type == "argon2":
        ph = PasswordHasher()
        return ph.hash(password.encode())
    else:
        raise ValueError("Unsupported hash type")

def _check_password(word, hash_to_crack, hash_type, salt):
    """
    Helper function to check a single password against a hash.
    """
    if hash_type == "bcrypt":
        try:
            if bcrypt.checkpw(word.encode(), hash_to_crack.encode()):
                return word
        except ValueError:
            pass
    elif hash_type == "scrypt":
        try:
            calculated_hash = calculate_hash(word, hash_type, salt=salt)
            if calculated_hash == hash_to_crack:
                return word
        except Exception:
            pass
    elif hash_type == "argon2":
        ph = PasswordHasher()
        try:
            ph.verify(hash_to_crack, word.encode())
            return word
        except Exception:
            pass
    else:
        calculated_hash = calculate_hash(word, hash_type)
        if calculated_hash == hash_to_crack:
            return word
    return None

def dictionary_attack(hash_to_crack, hash_type, wordlist_path, salt=None, num_threads=4):
    """
    Performs a dictionary attack to crack a given hash using multi-threading.
    """
    try:
        with open(wordlist_path, 'r') as f:
            words = [line.strip() for line in f]

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(_check_password, word, hash_to_crack, hash_type, salt) for word in words]
            for future in futures:
                result = future.result()
                if result:
                    return result
        return None
    except FileNotFoundError:
        print(f"Error: Wordlist file not found at {wordlist_path}")
        return None

def brute_force_attack(hash_to_crack, hash_type, charset, min_length, max_length, salt=None, num_threads=4):
    """
    Performs a brute-force attack to crack a given hash using multi-threading.
    """
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        for length in range(min_length, max_length + 1):
            for attempt_tuple in itertools.product(charset, repeat=length):
                password_attempt = "".join(attempt_tuple)
                result = executor.submit(_check_password, password_attempt, hash_to_crack, hash_type, salt).result()
                if result:
                    return result
    return None

if __name__ == "__main__":
    session_manager = SessionManager()

    # Example Usage:
    # Create a dummy wordlist for testing
    with open("dummy_wordlist.txt", "w") as f:
        f.write("password\n")
        f.write("123456\n")
        f.write("qwerty\n")
        f.write("test\n")
        f.write("mysecretpassword\n") # Added for bcrypt test
        f.write("anothersecret\n") # Added for scrypt test
        f.write("argon2password\n") # Added for argon2 test

    # MD5 example
    target_hash_md5 = calculate_hash("password", "md5")
    print(f"MD5 hash of 'password': {target_hash_md5}")
    cracked_password_md5 = dictionary_attack(target_hash_md5, "md5", "dummy_wordlist.txt")
    if cracked_password_md5:
        print(f"Cracked MD5 password: {cracked_password_md5}")
        session_manager.save_session({"md5_cracked": cracked_password_md5})
    else:
        print("MD5 password not found in wordlist.")

    # SHA256 example
    target_hash_sha256 = calculate_hash("123456", "sha256")
    print(f"SHA256 hash of '123456': {target_hash_sha256}")
    cracked_password_sha256 = dictionary_attack(target_hash_sha256, "sha256", "dummy_wordlist.txt")
    if cracked_password_sha256:
        print(f"Cracked SHA256 password: {cracked_password_sha256}")
        session_manager.save_session({"sha256_cracked": cracked_password_sha256})
    else:
        print("SHA256 password not found in wordlist.")

    # Bcrypt example
    password_bcrypt = "mysecretpassword"
    hashed_bcrypt = calculate_hash(password_bcrypt, "bcrypt")
    print(f"Bcrypt hash of '{password_bcrypt}': {hashed_bcrypt}")
    cracked_bcrypt = dictionary_attack(hashed_bcrypt, "bcrypt", "dummy_wordlist.txt")
    if cracked_bcrypt:
        print(f"Cracked Bcrypt password: {cracked_bcrypt}")
        session_manager.save_session({"bcrypt_cracked": cracked_bcrypt})
    else:
        print("Bcrypt password not found in wordlist.")

    # Scrypt example
    password_scrypt = "anothersecret"
    scrypt_salt = b'randomsalt'
    hashed_scrypt = calculate_hash(password_scrypt, "scrypt", salt=scrypt_salt)
    print(f"Scrypt hash of '{password_scrypt}': {hashed_scrypt}")
    cracked_scrypt = dictionary_attack(hashed_scrypt, "scrypt", "dummy_wordlist.txt", salt=scrypt_salt)
    if cracked_scrypt:
        print(f"Cracked Scrypt password: {cracked_scrypt}")
        session_manager.save_session({"scrypt_cracked": cracked_scrypt})
    else:
        print("Scrypt password not found in wordlist.")

    # Argon2 example
    password_argon2 = "argon2password"
    ph = PasswordHasher()
    hashed_argon2 = ph.hash(password_argon2.encode())
    print(f"Argon2 hash of '{password_argon2}': {hashed_argon2}")
    cracked_argon2 = dictionary_attack(hashed_argon2, "argon2", "dummy_wordlist.txt")
    if cracked_argon2:
        print(f"Cracked Argon2 password: {cracked_argon2}")
        session_manager.save_session({"argon2_cracked": cracked_argon2})
    else:
        print("Argon2 password not found in wordlist.")

    # Brute-force example
    target_hash_brute = calculate_hash("abc", "md5")
    print(f"MD5 hash of 'abc': {target_hash_brute}")
    charset_brute = "abcdefghijklmnopqrstuvwxyz"
    cracked_brute = brute_force_attack(target_hash_brute, "md5", charset_brute, 1, 3)
    if cracked_brute:
        print(f"Cracked brute-force password: {cracked_brute}")
        session_manager.save_session({"brute_force_cracked": cracked_brute})
    else:
        print("Brute-force password not found.")

    print("\nSession Data:")
    print(session_manager.session_data)


