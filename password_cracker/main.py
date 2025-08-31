import hashlib
import hmac
import binascii
import time
import itertools
import concurrent.futures
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Union, Tuple, Callable

# Optional imports for advanced hashing
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    import argon2
    from argon2 import PasswordHasher
    import argon2.exceptions as argon2_exceptions
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

# Constants
DEFAULT_SALT = b'saltymcsaltface'  # Default salt for algorithms that require it
DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
MAX_WORD_LENGTH = 128  # Maximum password length to prevent memory issues

class HashAlgorithm(Enum):
    """Supported hash algorithms"""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA224 = "sha224"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    BCRYPT = "bcrypt"
    SCRYPT = "scrypt"
    ARGON2 = "argon2"
    HMAC_MD5 = "hmac_md5"
    HMAC_SHA1 = "hmac_sha1"
    HMAC_SHA256 = "hmac_sha256"
    HMAC_SHA512 = "hmac_sha512"

@dataclass
class HashConfig:
    """Configuration for hashing operations"""
    algorithm: HashAlgorithm
    salt: Optional[bytes] = None
    scrypt_n: int = 16384  # CPU/memory cost parameter
    scrypt_r: int = 8      # Block size parameter
    scrypt_p: int = 1      # Parallelization parameter
    scrypt_buflen: int = 32  # Length of the derived key
    
    # Argon2 parameters
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536  # 64MB
    argon2_parallelism: int = 4
    
    # HMAC key (for HMAC variants)
    hmac_key: Optional[bytes] = None

class SessionManager:
    """Manages session data for the password cracker"""
    def __init__(self, session_file="session.json"):
        self.session_file = session_file
        self.session_data = self._load_session()
    
    def _load_session(self) -> Dict[str, Any]:
        """Load session data from file"""
        if os.path.exists(self.session_file):
            try:
                import json
                with open(self.session_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Could not load session data: {e}")
        return {}
    
    def save_session(self, data: Dict[str, Any]) -> None:
        """Save data to session"""
        import json
        self.session_data.update(data)
        try:
            with open(self.session_file, 'w') as f:
                json.dump(self.session_data, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save session data: {e}")
    
    def get_session_data(self, key: str) -> Any:
        """Get data from session by key"""
        return self.session_data.get(key)

def calculate_hash(password: str, algorithm: Union[str, HashAlgorithm], 
                  config: Optional[HashConfig] = None) -> str:
    """
    Calculate the hash of a password using the specified algorithm and configuration.
    
    Args:
        password: The password to hash
        algorithm: The hashing algorithm to use
        config: Optional configuration for the hashing algorithm
        
    Returns:
        The hashed password as a string
    """
    if isinstance(algorithm, str):
        try:
            algorithm = HashAlgorithm(algorithm.lower())
        except ValueError:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    if config is None:
        config = HashConfig(algorithm=algorithm)
    
    password_bytes = password.encode('utf-8')
    
    try:
        if algorithm == HashAlgorithm.MD5:
            return hashlib.md5(password_bytes).hexdigest()
            
        elif algorithm == HashAlgorithm.SHA1:
            return hashlib.sha1(password_bytes).hexdigest()
            
        elif algorithm == HashAlgorithm.SHA224:
            return hashlib.sha224(password_bytes).hexdigest()
            
        elif algorithm == HashAlgorithm.SHA256:
            return hashlib.sha256(password_bytes).hexdigest()
            
        elif algorithm == HashAlgorithm.SHA384:
            return hashlib.sha384(password_bytes).hexdigest()
            
        elif algorithm == HashAlgorithm.SHA512:
            return hashlib.sha512(password_bytes).hexdigest()
            
        elif algorithm == HashAlgorithm.BCRYPT:
            if not BCRYPT_AVAILABLE:
                raise ImportError("bcrypt package is required for bcrypt hashing")
            # bcrypt has its own salt handling
            salt = config.salt or bcrypt.gensalt()
            if isinstance(salt, str):
                salt = salt.encode('utf-8')
            return bcrypt.hashpw(password_bytes, salt).decode('utf-8')
            
        elif algorithm == HashAlgorithm.SCRYPT:
            salt = config.salt or os.urandom(16)
            return hashlib.scrypt(
                password=password_bytes,
                salt=salt,
                n=config.scrypt_n,
                r=config.scrypt_r,
                p=config.scrypt_p,
                dklen=config.scrypt_buflen
            ).hex()
            
        elif algorithm == HashAlgorithm.ARGON2:
            if not ARGON2_AVAILABLE:
                raise ImportError("argon2-cffi package is required for Argon2 hashing")
            ph = PasswordHasher(
                time_cost=config.argon2_time_cost,
                memory_cost=config.argon2_memory_cost,
                parallelism=config.argon2_parallelism
            )
            return ph.hash(password_bytes)
            
        elif algorithm in [HashAlgorithm.HMAC_MD5, HashAlgorithm.HMAC_SHA1, 
                          HashAlgorithm.HMAC_SHA256, HashAlgorithm.HMAC_SHA512]:
            if not config.hmac_key:
                raise ValueError("HMAC key is required for HMAC hashing")
                
            hmac_algo = algorithm.value.split('_')[1]  # Extract algo part from 'hmac_sha256'
            h = hmac.new(config.hmac_key, password_bytes, getattr(hashlib, hmac_algo))
            return h.hexdigest()
            
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
    except Exception as e:
        raise ValueError(f"Error calculating {algorithm.value} hash: {str(e)}")

def _check_password(word: str, hash_to_crack: str, algorithm: Union[str, HashAlgorithm], 
                   config: Optional[HashConfig] = None) -> Optional[str]:
    """
    Check if a password matches the given hash using the specified algorithm.
    
    Args:
        word: The password candidate to check
        hash_to_crack: The target hash to match against
        algorithm: The hashing algorithm to use
        config: Optional configuration for the hashing algorithm
        
    Returns:
        The password if it matches, None otherwise
    """
    if not word or len(word) > MAX_WORD_LENGTH:
        return None
        
    if isinstance(algorithm, str):
        try:
            algorithm = HashAlgorithm(algorithm.lower())
        except ValueError:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    if config is None:
        config = HashConfig(algorithm=algorithm)
    
    try:
        if algorithm == HashAlgorithm.BCRYPT:
            try:
                if bcrypt.checkpw(word.encode('utf-8'), hash_to_crack.encode('utf-8')):
                    return word
            except (ValueError, UnicodeEncodeError):
                pass
                
        elif algorithm == HashAlgorithm.ARGON2:
            if not ARGON2_AVAILABLE:
                raise ImportError("argon2-cffi package is required for Argon2 verification")
            ph = PasswordHasher()
            try:
                ph.verify(hash_to_crack, word.encode('utf-8'))
                return word
            except (argon2_exceptions.VerifyMismatchError, 
                   argon2_exceptions.VerificationError,
                   argon2_exceptions.InvalidHash):
                pass
                
        else:
            # For other algorithms, calculate the hash and compare
            try:
                calculated_hash = calculate_hash(word, algorithm, config)
                
                # Special handling for bcrypt hashes in the database
                if algorithm == HashAlgorithm.BCRYPT and calculated_hash.startswith('$2'):
                    try:
                        if bcrypt.checkpw(word.encode('utf-8'), calculated_hash.encode('utf-8')):
                            return word
                    except (ValueError, UnicodeEncodeError):
                        pass
                # Direct comparison for other hash types
                elif calculated_hash == hash_to_crack:
                    return word
                    
            except (ValueError, UnicodeEncodeError) as e:
                # Skip invalid passwords (e.g., invalid UTF-8)
                pass
                
    except Exception as e:
        # Log unexpected errors but don't crash
        print(f"Error checking password: {str(e)}")
        
    return None

def dictionary_attack(hash_to_crack: str, algorithm: Union[str, HashAlgorithm], 
                     wordlist_path: Union[str, Path], 
                     config: Optional[HashConfig] = None,
                     num_threads: int = 4,
                     progress_callback: Optional[Callable[[int, int], None]] = None) -> Optional[str]:
    """
    Perform a dictionary attack to crack a hash using a wordlist.
    
    Args:
        hash_to_crack: The target hash to crack
        algorithm: The hashing algorithm to use
        wordlist_path: Path to the wordlist file
        config: Optional configuration for the hashing algorithm
        num_threads: Number of threads to use for parallel processing
        progress_callback: Optional callback function for progress updates (current, total)
        
    Returns:
        The cracked password if found, None otherwise
    """
    if not os.path.isfile(wordlist_path):
        raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")
    
    if isinstance(algorithm, str):
        try:
            algorithm = HashAlgorithm(algorithm.lower())
        except ValueError:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    if config is None:
        config = HashConfig(algorithm=algorithm)
    
    # Count total lines in wordlist for progress tracking
    total_words = 0
    with open(wordlist_path, 'rb') as f:
        total_words = sum(1 for _ in f)
    
    if total_words == 0:
        print("Warning: Wordlist is empty")
        return None
    
    # Process words in chunks to balance memory usage and performance
    CHUNK_SIZE = 1000
    
    def process_chunk(chunk):
        for word in chunk:
            word = word.strip()
            if not word:
                continue
            result = _check_password(word, hash_to_crack, algorithm, config)
            if result:
                return result
        return None
    
    try:
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                chunk = []
                for i, line in enumerate(f, 1):
                    chunk.append(line)
                    if len(chunk) >= CHUNK_SIZE:
                        future = executor.submit(process_chunk, chunk)
                        result = future.result()
                        if result:
                            return result
                        chunk = []
                    
                    # Update progress
                    if progress_callback and i % 1000 == 0:
                        progress_callback(i, total_words)
                
                # Process remaining words
                if chunk:
                    future = executor.submit(process_chunk, chunk)
                    result = future.result()
                    if result:
                        return result
    
    except KeyboardInterrupt:
        print("\nAttack interrupted by user")
    except Exception as e:
        print(f"Error during dictionary attack: {str(e)}")
    
    return None

def brute_force_attack(hash_to_crack: str, algorithm: Union[str, HashAlgorithm],
                      charset: str = DEFAULT_CHARSET,
                      min_length: int = 1, 
                      max_length: int = 8,
                      config: Optional[HashConfig] = None,
                      num_threads: int = 4,
                      progress_callback: Optional[Callable[[int, int, str], None]] = None) -> Optional[str]:
    """
    Perform a brute-force attack to crack a hash by trying all possible combinations.
    
    Args:
        hash_to_crack: The target hash to crack
        algorithm: The hashing algorithm to use
        charset: String containing all possible characters to try
        min_length: Minimum password length to try
        max_length: Maximum password length to try
        config: Optional configuration for the hashing algorithm
        num_threads: Number of threads to use for parallel processing
        progress_callback: Optional callback for progress updates (current, total, current_attempt)
        
    Returns:
        The cracked password if found, None otherwise
    """
    if isinstance(algorithm, str):
        try:
            algorithm = HashAlgorithm(algorithm.lower())
        except ValueError:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    if config is None:
        config = HashConfig(algorithm=algorithm)
    
    if min_length < 1:
        min_length = 1
    if max_length < min_length:
        max_length = min_length + 1
    if max_length > 20:  # Prevent excessive memory usage
        print("Warning: Maximum length reduced to 20 for performance reasons")
        max_length = 20
    
    # Calculate total number of combinations for progress tracking
    total_combinations = sum(len(charset) ** length 
                           for length in range(min_length, max_length + 1))
    
    processed = 0
    result = None
    
    def process_chunk(chunk):
        nonlocal processed
        for attempt in chunk:
            word = ''.join(attempt)
            current = _check_password(word, hash_to_crack, algorithm, config)
            if current:
                return current
            
            # Update progress
            nonlocal processed
            processed += 1
            if progress_callback and processed % 1000 == 0:
                progress_callback(processed, total_combinations, word)
        return None
    
    try:
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for length in range(min_length, max_length + 1):
                if result is not None:
                    break
                    
                # Generate combinations in chunks to balance memory and performance
                chunk_size = 1000
                chunk = []
                
                for combo in itertools.product(charset, repeat=length):
                    chunk.append(combo)
                    if len(chunk) >= chunk_size:
                        future = executor.submit(process_chunk, chunk)
                        chunk_result = future.result()
                        if chunk_result:
                            result = chunk_result
                            break
                        chunk = []
                
                # Process remaining combinations
                if chunk and result is None:
                    future = executor.submit(process_chunk, chunk)
                    chunk_result = future.result()
                    if chunk_result:
                        result = chunk_result
    
    except KeyboardInterrupt:
        print("\nAttack interrupted by user")
    except Exception as e:
        print(f"Error during brute force attack: {str(e)}")
    
    return result

def print_usage():
    print("""
Password Cracker - Advanced Hash Cracking Tool

Usage:
  python main.py [options]

Options:
  --hash HASH           Hash to crack (required)
  --type TYPE           Hash type (md5, sha1, sha256, sha512, bcrypt, scrypt, argon2, etc.)
  --wordlist FILE       Path to wordlist file (for dictionary attack)
  --brute-force         Use brute-force attack
  --charset CHARS       Character set for brute-force (default: a-zA-Z0-9!@#$%^&*()_+-=[]{}|;:,.<>?)
  --min-length N        Minimum password length (default: 1)
  --max-length N        Maximum password length (default: 8)
  --threads N           Number of threads to use (default: 4)
  --salt SALT           Salt for hashing algorithms that require it (hex encoded)
  --hmac-key KEY        HMAC key (for HMAC hashes)
  --scrypt-n N          Scrypt N parameter (CPU/memory cost)
  --scrypt-r N          Scrypt r parameter (block size)
  --scrypt-p N          Scrypt p parameter (parallelization)
  --argon2-t N          Argon2 time cost parameter
  --argon2-m N          Argon2 memory cost parameter (in KB)
  --argon2-p N          Argon2 parallelism parameter
  --help                Show this help message

Examples:
  # Dictionary attack on MD5 hash
  python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5 --wordlist wordlist.txt

  # Brute force attack on SHA-256 hash
  python main.py --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
    --type sha256 --brute-force --min 1 --max 6

  # Crack bcrypt hash with custom parameters
  python main.py --hash '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW' \
    --type bcrypt --wordlist wordlist.txt
""")

def parse_arguments():
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Password Cracker', add_help=False)
    
    # Required arguments
    parser.add_argument('--hash', type=str, help='Hash to crack')
    parser.add_argument('--type', type=str.lower, help='Hash algorithm')
    
    # Attack type
    attack_group = parser.add_mutually_exclusive_group(required=True)
    attack_group.add_argument('--wordlist', type=str, help='Path to wordlist file')
    attack_group.add_argument('--brute-force', action='store_true', help='Use brute-force attack')
    
    # Brute-force options
    parser.add_argument('--charset', type=str, default=DEFAULT_CHARSET, 
                      help=f'Character set (default: {DEFAULT_CHARSET[:20]}...)')
    parser.add_argument('--min-length', type=int, default=1, help='Minimum password length')
    parser.add_argument('--max-length', type=int, default=8, help='Maximum password length')
    
    # Performance options
    parser.add_argument('--threads', type=int, default=4, help='Number of threads to use')
    
    # Algorithm-specific options
    parser.add_argument('--salt', type=str, help='Salt (hex encoded)')
    parser.add_argument('--hmac-key', type=str, help='HMAC key')
    
    # Scrypt parameters
    parser.add_argument('--scrypt-n', type=int, default=16384, help='Scrypt N parameter')
    parser.add_argument('--scrypt-r', type=int, default=8, help='Scrypt r parameter')
    parser.add_argument('--scrypt-p', type=int, default=1, help='Scrypt p parameter')
    
    # Argon2 parameters
    parser.add_argument('--argon2-t', type=int, default=3, dest='argon2_time', help='Argon2 time cost')
    parser.add_argument('--argon2-m', type=int, default=65536, dest='argon2_mem', help='Argon2 memory cost (KB)')
    parser.add_argument('--argon2-p', type=int, default=4, dest='argon2_parallel', help='Argon2 parallelism')
    
    # Help
    parser.add_argument('--help', action='store_true', help='Show help message')
    
    args = parser.parse_args()
    
    # Show help if no arguments or --help is specified
    if args.help or not any(vars(args).values()):
        print_usage()
        exit(0)
        
    # Validate required arguments
    if not args.hash:
        print("Error: --hash is required")
        exit(1)
    if not args.type:
        print("Error: --type is required")
        exit(1)
    
    return args

def main():
    try:
        args = parse_arguments()
        
        # Create hash config
        config = HashConfig(algorithm=args.type)
        
        # Set salt if provided
        if args.salt:
            try:
                config.salt = bytes.fromhex(args.salt)
            except ValueError:
                print("Error: Invalid salt format. Must be a hex string.")
                exit(1)
        
        # Set HMAC key if provided
        if args.hmac_key:
            try:
                config.hmac_key = args.hmac_key.encode('utf-8')
            except Exception as e:
                print(f"Error: Invalid HMAC key - {str(e)}")
                exit(1)
        
        # Set scrypt parameters
        config.scrypt_n = args.scrypt_n
        config.scrypt_r = args.scrypt_r
        config.scrypt_p = args.scrypt_p
        
        # Set Argon2 parameters
        config.argon2_time_cost = args.argon2_time
        config.argon2_memory_cost = args.argon2_mem
        config.argon2_parallelism = args.argon2_parallel
        
        # Progress callback
        def progress_callback(current, total, current_attempt=None):
            percent = (current / total) * 100
            if current_attempt:
                print(f"\rProgress: {percent:.2f}% | Current: {current_attempt}", end='')
            else:
                print(f"\rProgress: {percent:.2f}% | Checked {current}/{total} passwords", end='')
        
        print(f"[+] Starting attack on {args.type.upper()} hash: {args.hash}")
        print(f"[+] Using {args.threads} threads")
        
        start_time = time.time()
        
        if args.wordlist:
            print(f"[+] Using wordlist: {args.wordlist}")
            result = dictionary_attack(
                hash_to_crack=args.hash,
                algorithm=args.type,
                wordlist_path=args.wordlist,
                config=config,
                num_threads=args.threads,
                progress_callback=progress_callback
            )
        elif args.brute_force:
            print(f"[+] Starting brute-force attack (lengths {args.min_length}-{args.max_length})")
            print(f"[+] Character set: {args.charset}")
            result = brute_force_attack(
                hash_to_crack=args.hash,
                algorithm=args.type,
                charset=args.charset,
                min_length=args.min_length,
                max_length=args.max_length,
                config=config,
                num_threads=args.threads,
                progress_callback=progress_callback
            )
        
        print("\n" + "="*50)
        if result:
            print(f"[+] Password found: {result}")
        else:
            print("[-] Password not found")
        
        elapsed = time.time() - start_time
        print(f"[+] Time elapsed: {elapsed:.2f} seconds")
        
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        if "argon2" in str(e).lower() and not ARGON2_AVAILABLE:
            print("Note: argon2-cffi package is required for Argon2 hashing. Install with: pip install argon2-cffi")
        sys.exit(1)

if __name__ == "__main__":
    main()
