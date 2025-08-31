import argparse
import sys
from main import calculate_hash, dictionary_attack, brute_force_attack, SessionManager

def main():
    parser = argparse.ArgumentParser(description="Advanced Hash-Based Password Cracker")
    parser.add_argument("hash", help="Hash to crack")
    parser.add_argument("--type", "-t", required=True, choices=["md5", "sha256", "bcrypt", "scrypt", "argon2"], help="Hash type")
    parser.add_argument("--attack", "-a", required=True, choices=["dictionary", "brute-force"], help="Attack method")
    parser.add_argument("--wordlist", "-w", help="Path to wordlist file (required for dictionary attack)")
    parser.add_argument("--charset", "-c", default="abcdefghijklmnopqrstuvwxyz0123456789", help="Character set for brute-force attack")
    parser.add_argument("--min-length", "-min", type=int, default=1, help="Minimum password length for brute-force attack")
    parser.add_argument("--max-length", "-max", type=int, default=4, help="Maximum password length for brute-force attack")
    parser.add_argument("--threads", "-th", type=int, default=4, help="Number of threads to use")
    parser.add_argument("--salt", "-s", help="Salt for scrypt (hex string)")
    parser.add_argument("--session", "-sess", default="session.json", help="Session file for saving progress")

    args = parser.parse_args()

    # Validate arguments
    if args.attack == "dictionary" and not args.wordlist:
        print("Error: Wordlist file is required for dictionary attack.")
        sys.exit(1)

    if args.type == "scrypt" and not args.salt:
        print("Error: Salt is required for scrypt hash type.")
        sys.exit(1)

    # Convert salt from hex string to bytes if provided
    salt = None
    if args.salt:
        try:
            salt = bytes.fromhex(args.salt)
        except ValueError:
            print("Error: Invalid salt format. Please provide a hex string.")
            sys.exit(1)

    session_manager = SessionManager(args.session)

    print(f"Starting {args.attack} attack on {args.type} hash: {args.hash}")
    print(f"Using {args.threads} threads")

    if args.attack == "dictionary":
        result = dictionary_attack(args.hash, args.type, args.wordlist, salt=salt, num_threads=args.threads)
    elif args.attack == "brute-force":
        result = brute_force_attack(args.hash, args.type, args.charset, args.min_length, args.max_length, salt=salt, num_threads=args.threads)

    if result:
        print(f"Password cracked: {result}")
        session_manager.save_session({f"{args.type}_{args.attack}_cracked": result})
    else:
        print("Password not found.")

if __name__ == "__main__":
    main()

