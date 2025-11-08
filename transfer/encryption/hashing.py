"""
SHA-256 Hashing and HMAC Module

This module implements:
1. SHA-256 (Secure Hash Algorithm 256-bit)
2. HMAC (Hash-based Message Authentication Code)

SHA-256:
- Cryptographic hash function
- Produces 256-bit (32-byte) hash
- One-way function (cannot be reversed)
- Deterministic (same input = same output)
- Collision-resistant

Common uses:
- Data integrity verification
- Password hashing (with salt)
- Digital signatures
- Blockchain

How SHA-256 Works:
1. Pad the message to a multiple of 512 bits
2. Break into 512-bit chunks
3. Process each chunk through 64 rounds of:
   - Bitwise operations (AND, OR, XOR, NOT)
   - Modular addition
   - Rotations and shifts
4. Combine results to produce 256-bit hash

HMAC (Hash-based Message Authentication Code):
- Combines hash function with secret key
- Provides message authentication and integrity
- Prevents tampering
- Uses key stretching for security

HMAC Formula:
HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
where:
- K = secret key
- m = message
- H = hash function (SHA-256)
- opad = outer padding (0x5c repeated)
- ipad = inner padding (0x36 repeated)
- || = concatenation
- ⊕ = XOR
"""

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import os


class SHA256Hash:
    """
    SHA-256 Hashing Handler

    Supports:
    - String hashing
    - File hashing
    - Hex and Base64 output formats
    - Salted hashing
    """

    @staticmethod
    def hash_string(data, output_format='hex'):
        """
        Hash a string using SHA-256

        Args:
            data (str or bytes): Data to hash
            output_format (str): 'hex' or 'base64'

        Returns:
            str: Hash in specified format
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Create hash object
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        hash_bytes = digest.finalize()

        if output_format == 'hex':
            return hash_bytes.hex()
        elif output_format == 'base64':
            return base64.b64encode(hash_bytes).decode('utf-8')
        else:
            return hash_bytes

    @staticmethod
    def hash_file(file_path, chunk_size=8192, output_format='hex'):
        """
        Hash a file using SHA-256

        Args:
            file_path (str): Path to file
            chunk_size (int): Size of chunks to read (for large files)
            output_format (str): 'hex' or 'base64'

        Returns:
            str: Hash of file contents
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

        # Read file in chunks to handle large files efficiently
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)

        hash_bytes = digest.finalize()

        if output_format == 'hex':
            return hash_bytes.hex()
        elif output_format == 'base64':
            return base64.b64encode(hash_bytes).decode('utf-8')
        else:
            return hash_bytes

    @staticmethod
    def hash_with_salt(data, salt=None, output_format='hex'):
        """
        Hash data with a salt (for password hashing)

        Args:
            data (str or bytes): Data to hash
            salt (bytes, optional): Salt to use (generates random if None)
            output_format (str): 'hex' or 'base64'

        Returns:
            tuple: (hash, salt) both in specified format
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        if salt is None:
            salt = os.urandom(32)  # 256-bit salt

        # Combine data and salt
        salted_data = salt + data

        # Hash
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(salted_data)
        hash_bytes = digest.finalize()

        if output_format == 'hex':
            return hash_bytes.hex(), salt.hex()
        elif output_format == 'base64':
            return (
                base64.b64encode(hash_bytes).decode('utf-8'),
                base64.b64encode(salt).decode('utf-8')
            )
        else:
            return hash_bytes, salt

    @staticmethod
    def verify_hash(data, expected_hash, salt=None, input_format='hex'):
        """
        Verify if data matches the expected hash

        Args:
            data (str or bytes): Data to verify
            expected_hash (str): Expected hash value
            salt (str or bytes, optional): Salt used in hashing
            input_format (str): Format of expected_hash ('hex' or 'base64')

        Returns:
            bool: True if hash matches, False otherwise
        """
        if salt:
            if isinstance(salt, str):
                if input_format == 'hex':
                    salt = bytes.fromhex(salt)
                else:
                    salt = base64.b64decode(salt)

            computed_hash, _ = SHA256Hash.hash_with_salt(
                data, salt, output_format=input_format
            )
        else:
            computed_hash = SHA256Hash.hash_string(data, output_format=input_format)

        return computed_hash == expected_hash

    @staticmethod
    def compare_files(file1_path, file2_path):
        """
        Compare two files by their SHA-256 hashes

        Args:
            file1_path (str): Path to first file
            file2_path (str): Path to second file

        Returns:
            bool: True if files are identical, False otherwise
        """
        hash1 = SHA256Hash.hash_file(file1_path)
        hash2 = SHA256Hash.hash_file(file2_path)

        return hash1 == hash2


class HMACGenerator:
    """
    HMAC (Hash-based Message Authentication Code) Handler

    HMAC provides:
    - Message authentication
    - Data integrity verification
    - Protection against tampering

    Uses SHA-256 as the hash function
    """

    def __init__(self, key=None):
        """
        Initialize HMAC generator

        Args:
            key (bytes, optional): Secret key (generates random if None)
        """
        if key is None:
            self.key = os.urandom(32)  # 256-bit key
        else:
            self.key = key if isinstance(key, bytes) else key.encode('utf-8')

    def generate(self, message, output_format='hex'):
        """
        Generate HMAC for a message

        Args:
            message (str or bytes): Message to authenticate
            output_format (str): 'hex' or 'base64'

        Returns:
            str: HMAC in specified format
        """
        if isinstance(message, str):
            message = message.encode('utf-8')

        # Create HMAC
        h = hmac.HMAC(self.key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        hmac_bytes = h.finalize()

        if output_format == 'hex':
            return hmac_bytes.hex()
        elif output_format == 'base64':
            return base64.b64encode(hmac_bytes).decode('utf-8')
        else:
            return hmac_bytes

    def verify(self, message, expected_hmac, input_format='hex'):
        """
        Verify HMAC of a message

        Args:
            message (str or bytes): Message to verify
            expected_hmac (str): Expected HMAC value
            input_format (str): Format of expected_hmac ('hex' or 'base64')

        Returns:
            bool: True if HMAC is valid, False otherwise
        """
        if isinstance(message, str):
            message = message.encode('utf-8')

        # Convert expected HMAC to bytes
        if input_format == 'hex':
            expected_hmac_bytes = bytes.fromhex(expected_hmac)
        else:
            expected_hmac_bytes = base64.b64decode(expected_hmac)

        # Create HMAC and verify
        h = hmac.HMAC(self.key, hashes.SHA256(), backend=default_backend())
        h.update(message)

        try:
            h.verify(expected_hmac_bytes)
            return True
        except Exception:
            return False

    def generate_for_file(self, file_path, chunk_size=8192, output_format='hex'):
        """
        Generate HMAC for a file

        Args:
            file_path (str): Path to file
            chunk_size (int): Size of chunks to read
            output_format (str): 'hex' or 'base64'

        Returns:
            str: HMAC in specified format
        """
        h = hmac.HMAC(self.key, hashes.SHA256(), backend=default_backend())

        # Read file in chunks
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)

        hmac_bytes = h.finalize()

        if output_format == 'hex':
            return hmac_bytes.hex()
        elif output_format == 'base64':
            return base64.b64encode(hmac_bytes).decode('utf-8')
        else:
            return hmac_bytes

    def export_key(self, output_format='base64'):
        """
        Export the HMAC key

        Args:
            output_format (str): 'hex' or 'base64'

        Returns:
            str: Key in specified format
        """
        if output_format == 'hex':
            return self.key.hex()
        elif output_format == 'base64':
            return base64.b64encode(self.key).decode('utf-8')
        else:
            return self.key

    @staticmethod
    def import_key(key_str, input_format='base64'):
        """
        Import a key from string

        Args:
            key_str (str): Key string
            input_format (str): 'hex' or 'base64'

        Returns:
            HMACGenerator: New instance with imported key
        """
        if input_format == 'hex':
            key = bytes.fromhex(key_str)
        else:
            key = base64.b64decode(key_str)

        return HMACGenerator(key=key)


# Example usage and demonstration
if __name__ == "__main__":
    print("=" * 60)
    print("SHA-256 and HMAC Demonstration")
    print("=" * 60)

    # SHA-256 Demo
    print("\n--- SHA-256 Hashing ---")

    message = "Hello, this is a test message for SHA-256!"
    print(f"\n1. Original Message: '{message}'")

    # Hash the message
    hash_hex = SHA256Hash.hash_string(message, output_format='hex')
    hash_b64 = SHA256Hash.hash_string(message, output_format='base64')

    print(f"\n2. SHA-256 Hash:")
    print(f"   - Hex: {hash_hex}")
    print(f"   - Base64: {hash_b64}")

    # Verify hash
    is_valid = SHA256Hash.verify_hash(message, hash_hex, input_format='hex')
    print(f"\n3. Hash Verification: {is_valid}")

    # Salted hash
    print("\n--- SHA-256 with Salt (for Passwords) ---")
    password = "MySecurePassword123!"
    print(f"\n1. Password: '{password}'")

    hashed_pw, salt = SHA256Hash.hash_with_salt(password)
    print(f"\n2. Hashed Password: {hashed_pw}")
    print(f"   Salt: {salt}")

    # Verify password
    is_correct = SHA256Hash.verify_hash(password, hashed_pw, salt=salt)
    print(f"\n3. Password Verification: {is_correct}")

    # HMAC Demo
    print("\n\n--- HMAC (Message Authentication) ---")

    hmac_gen = HMACGenerator()
    message = "This message needs authentication"
    print(f"\n1. Message: '{message}'")

    # Generate HMAC
    message_hmac = hmac_gen.generate(message)
    print(f"\n2. HMAC: {message_hmac}")

    # Verify HMAC
    is_authentic = hmac_gen.verify(message, message_hmac)
    print(f"\n3. HMAC Verification: {is_authentic}")

    # Try with tampered message
    tampered = "This message was tampered with"
    is_authentic_tampered = hmac_gen.verify(tampered, message_hmac)
    print(f"\n4. Tampered Message Verification: {is_authentic_tampered}")

    # Export key
    print("\n\n--- Key Management ---")
    key_exported = hmac_gen.export_key()
    print(f"Exported HMAC Key: {key_exported}")

    print("\n" + "=" * 60)
    print("SHA-256 and HMAC Demo Complete!")
    print("=" * 60)
