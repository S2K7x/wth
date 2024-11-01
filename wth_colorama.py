import re
import logging
import argparse
from difflib import SequenceMatcher
from colorama import Fore, Style, init
import hashlib
from concurrent.futures import ThreadPoolExecutor
from hash_signatures import hash_signatures  # Import hash signatures from the new file

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Configure logging
logging.basicConfig(filename='hash_identification.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to perform reverse lookup on MD5 and SHA-1 hashes using a small dictionary
def reverse_lookup(hash_string):
    known_hashes = {
        "5d41402abc4b2a76b9719d911017c592": "hello",
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12": "example",
        # Add more known hashes as needed
    }
    return known_hashes.get(hash_string, None)

# Function to identify hash type by matching length and pattern
def identify_hash(hash_string):
    # Validate input to contain only alphanumeric characters
    if not re.match(r"^[a-fA-F0-9]+$", hash_string):
        print(Fore.RED + f"Invalid hash: {hash_string}. Hashes should contain only hex characters.")
        return None

    # Attempt direct matching with hash signatures
    for hash_type, signature in hash_signatures.items():
        if len(hash_string) == signature["length"] and re.match(signature["characters"], hash_string):
            log_identification_attempt(hash_string, hash_type)
            print(Fore.GREEN + f"Exact match found: {hash_type}")
            return hash_type
    
    # If no exact match found, use fuzzy matching to suggest closest type
    closest_type, confidence = closest_hash_type(hash_string)
    if confidence >= 0.75:  # Show closest match only if confidence is high
        print(Fore.YELLOW + f"Closest match: {closest_type} (Confidence: {confidence:.2f})")
        log_identification_attempt(hash_string, f"{closest_type} (Confidence: {confidence:.2f})")
        return closest_type
    else:
        print(Fore.RED + f"Unknown hash type for: {hash_string}")
        return "Unknown"

# Fuzzy matching to find the closest hash type if no exact match
def closest_hash_type(hash_string):
    best_match = "Unknown"
    highest_ratio = 0
    for hash_type, signature in hash_signatures.items():
        match_ratio = SequenceMatcher(None, hash_string, signature["example"]).ratio()
        if match_ratio > highest_ratio:
            best_match = hash_type
            highest_ratio = match_ratio
    return best_match, highest_ratio

# Logging function to record identification attempts
def log_identification_attempt(hash_string, identified_type):
    logging.info(f"Identified Hash: {hash_string} as {identified_type}")

# Function to compare two hashes for equality and identify their types
def compare_hashes(hash1, hash2):
    if hash1 == hash2:
        print(Fore.GREEN + "The hashes are identical.")
    else:
        print(Fore.RED + "The hashes are different.")
    
    print(Fore.CYAN + "Hash 1 Type:")
    identify_hash(hash1)
    print(Fore.CYAN + "Hash 2 Type:")
    identify_hash(hash2)

# Function to process a hash string or read hashes from a file with multithreading
def process_hashes(hashes):
    with ThreadPoolExecutor() as executor:
        executor.map(identify_and_lookup, hashes)

# Function to identify a hash and perform reverse lookup if applicable
def identify_and_lookup(hash_string):
    hash_string = hash_string.strip()  # Remove any trailing newline characters
    identified_type = identify_hash(hash_string)
    if identified_type:
        # Attempt reverse lookup if hash is MD5 or SHA-1
        if identified_type in ["md5", "sha1"]:
            original_value = reverse_lookup(hash_string)
            if original_value:
                print(Fore.CYAN + f"Original value found for {identified_type}: {original_value}")
            else:
                print(Fore.CYAN + f"No known plaintext value found for {identified_type}")

# Main function for argument parsing
def main():
    parser = argparse.ArgumentParser(description="Identify the type of a given hash.")
    parser.add_argument("-s", "--hash", type=str, help="The hash string to identify.")
    parser.add_argument("-f", "--file", type=str, help="Path to a file containing hashes to identify (one per line).")
    parser.add_argument("-c", "--compare", nargs=2, metavar=("HASH1", "HASH2"), help="Compare two hashes.")

    args = parser.parse_args()

    # Check for hash input in command-line, file, or compare mode
    if args.hash:
        # Single hash string provided
        process_hashes([args.hash])
    elif args.file:
        # Read hashes from a file with error handling
        try:
            with open(args.file, "r") as file:
                hashes = file.readlines()
            process_hashes(hashes)
        except FileNotFoundError:
            print(Fore.RED + f"Error: The file '{args.file}' was not found.")
        except IOError:
            print(Fore.RED + f"Error: Could not read the file '{args.file}'.")
    elif args.compare:
        # Compare two hashes
        compare_hashes(args.compare[0], args.compare[1])
    else:
        print(Fore.RED + "Error: Please provide a hash string with -s, a file with -f, or hashes to compare with -c.")
        parser.print_help()

if __name__ == "__main__":
    main()
