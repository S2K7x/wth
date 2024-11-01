Here’s a `README.md` for your tool **What the Hash? (wth.py)**.

---

# What the Hash? (wth.py)

**What the Hash?** is a Python tool designed to identify hash types based on common hash formats and characteristics. With `wth.py`, you can determine the hash type of a given hash string, compare two hashes, and even look up common plaintext values for MD5 and SHA-1 hashes.

## Features

- **Identify Hash Type**: Detects various types of hashes by length and format.
- **Compare Hashes**: Checks if two hashes are identical and identifies their types.
- **Reverse Lookup**: Performs reverse lookup on known MD5 and SHA-1 hashes.
- **Batch Processing**: Reads and processes multiple hashes from a file using multithreading for speed.

## Supported Hash Types

Currently, the tool supports detection of:
- MD5
- SHA-1
- SHA-256
- bcrypt

You can extend support by adding more hash types to the `hash_signatures.py` file.

## Installation

1. **Clone this repository**:
   ```bash
   git clone https://github.com/yourusername/wth.git
   ```
2. **Navigate to the directory**:
   ```bash
   cd wth
   ```
3. **Ensure Python 3 is installed** (Python 3.6+ recommended).

4. **Install any additional dependencies** (if needed):
   ```bash
   pip install -r requirements.txt
   ```

5. **Edit `hash_signatures.py`** to add or modify hash types if necessary.

## Usage

### Command Line Arguments
Run `wth.py` with different options:

```bash
python wth.py [options]
```

Options:
- `-s`, `--hash` **<hash_string>**: Identify the type of a single hash string.
- `-f`, `--file` **<file_path>**: Process multiple hashes from a file (one hash per line).
- `-c`, `--compare` **<hash1> <hash2>**: Compare two hashes to check if they are identical and identify their types.

### Examples

#### Identify a Single Hash Type
Identify the type of a specific hash:
```bash
python wth.py -s d2d2d2d2e957e65707e88f7eecb9bc91b138b4f6c793b79923c4b6df3b67f0d2
```

#### Identify Hash Types from a File
Identify multiple hashes from a file (one hash per line):
```bash
python wth.py -f hashes.txt
```

#### Compare Two Hashes
Compare two hashes to see if they are identical:
```bash
python wth.py -c 5d41402abc4b2a76b9719d911017c592 5d41402abc4b2a76b9719d911017c592
```

## File Structure

- **wth.py**: Main script that processes and identifies hashes.
- **hash_signatures.py**: Contains definitions for hash types, lengths, and patterns.
- **hash_identification.log**: Log file for hash identification attempts.

## Extending the Tool

To support additional hash types, simply add new entries to `hash_signatures.py`. Each entry should contain:
- `length`: Length of the hash.
- `characters`: Regular expression pattern to match the hash format.
- `example`: Example of the hash format.

Example for adding SHA-512:
```python
"sha512": {
    "length": 128,
    "characters": r"^[a-f0-9]{128}$",
    "example": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
}
```

## Logging

All hash identification attempts are logged in `hash_identification.log` for audit purposes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributions

Contributions are welcome! Feel free to open issues or submit pull requests to enhance functionality, add hash types, or improve performance.

---

Enjoy using **What the Hash?**