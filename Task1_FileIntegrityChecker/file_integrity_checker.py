import hashlib  # For computing hash values
import os       # For file and directory operations
import sys      # For command-line arguments

# Function to compute SHA-256 hash of a file
def compute_hash(file_path):
    sha256 = hashlib.sha256()  # Initialize SHA-256 hash object
    try:
        with open(file_path, 'rb') as f:  # Open file in binary read mode
            while chunk := f.read(4096):  # Read file in 4KB chunks to handle large files
                sha256.update(chunk)      # Update hash with each chunk
        return sha256.hexdigest()         # Return the hexadecimal hash
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

# Function to generate baseline hashes for all files in a directory
def generate_baseline(directory):
    hashes = {}  # Dictionary to store file paths and their hashes
    for root, _, files in os.walk(directory):  # Traverse the directory
        for file in files:
            file_path = os.path.join(root, file)  # Get full file path
            hash_value = compute_hash(file_path)  # Compute hash
            if hash_value:
                hashes[file_path] = hash_value    # Store if successful
    
    # Save hashes to baseline.txt
    with open('baseline.txt', 'w') as f:
        for path, h in hashes.items():
            f.write(f"{path}:{h}\n")  # Format: path:hash
    
    print("Baseline hashes generated and saved to baseline.txt")

# Function to check file integrity against baseline
def check_integrity(directory):
    if not os.path.exists('baseline.txt'):
        print("Baseline file not found! Run generate mode first.")
        return
    
    # Load baseline hashes from file
    baseline = {}
    with open('baseline.txt', 'r') as f:
        for line in f:
            if ':' in line:
                path, h = line.strip().split(':', 1)  # Split path and hash
                baseline[path] = h
    
    # Compute current hashes
    current = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            hash_value = compute_hash(file_path)
            if hash_value:
                current[file_path] = hash_value
    
    # Compare and report
    print("Integrity Check Results:")
    for path, old_hash in baseline.items():
        if path not in current:
            print(f"MISSING: {path}")
        elif current[path] != old_hash:
            print(f"CHANGED: {path}")
        else:
            print(f"OK: {path}")
    
    # Report new files not in baseline
    for path in current:
        if path not in baseline:
            print(f"NEW: {path}")

# Main entry point: Handle command-line arguments
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python file_integrity_checker.py [generate|check] [directory]")
        sys.exit(1)
    
    mode = sys.argv[1]      # First argument: generate or check
    directory = sys.argv[2] # Second argument: directory path
    
    if mode == "generate":
        generate_baseline(directory)
    elif mode == "check":
        check_integrity(directory)
    else:
        print("Invalid mode! Use 'generate' or 'check'.")