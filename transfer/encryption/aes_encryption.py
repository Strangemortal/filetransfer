"""
AES (Advanced Encryption Standard) Encryption Module

AES is a symmetric encryption algorithm - the same key is used for both
encryption and decryption. It's the most widely used encryption standard.

Key Features:
- Symmetric key encryption
- Block cipher (128-bit blocks)
- Key sizes: 128, 192, or 256 bits
- Fast and secure
- Suitable for large data encryption

How AES Works:
1. Data is divided into 128-bit blocks
2. Each block undergoes multiple rounds of:
   - SubBytes: Byte substitution using S-box
   - ShiftRows: Row-wise circular shift
   - MixColumns: Column-wise mixing
   - AddRoundKey: XOR with round key
3. Number of rounds depends on key size:
   - 128-bit key: 10 rounds
   - 192-bit key: 12 rounds
   - 256-bit key: 14 rounds

Modes of Operation:
- GCM (Galois/Counter Mode): Provides both encryption and authentication
- CBC (Cipher Block Chaining): Traditional mode with IV
- CTR (Counter): Converts block cipher to stream cipher
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import os
import base64


class AESEncryption:
    """
    AES Encryption and Decryption Handler

    Supports:
    - AES-256-GCM (recommended for new applications)
    - AES-256-CBC (traditional mode)
    - Random key generation
    - File encryption/decryption
    - Data encryption/decryption
    """

    def __init__(self, key=None, mode='GCM'):
        """
        Initialize AES encryption

        Args:
            key (bytes, optional): 256-bit (32 bytes) encryption key
            mode (str): Encryption mode - 'GCM' or 'CBC'
        """
        self.mode = mode.upper()
        if key is None:
            self.key = self.generate_key()
        else:
            if len(key) != 32:
                raise ValueError("Key must be 32 bytes (256 bits) for AES-256")
            self.key = key

    @staticmethod
    def generate_key():
        """
        Generate a random 256-bit AES key

        Returns:
            bytes: 32-byte random key
        """
        return os.urandom(32)

    def encrypt(self, plaintext):
        """
        Encrypt data using AES

        Args:
            plaintext (str or bytes): Data to encrypt

        Returns:
            dict: Contains 'ciphertext', 'iv', and 'tag' (for GCM mode)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        if self.mode == 'GCM':
            return self._encrypt_gcm(plaintext)
        elif self.mode == 'CBC':
            return self._encrypt_cbc(plaintext)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

    def decrypt(self, ciphertext, iv, tag=None):
        """
        Decrypt AES-encrypted data

        Args:
            ciphertext (bytes or str): Encrypted data (base64 if string)
            iv (bytes or str): Initialization vector (base64 if string)
            tag (bytes or str, optional): Authentication tag for GCM mode

        Returns:
            bytes: Decrypted data
        """
        # Convert base64 strings to bytes if necessary
        if isinstance(ciphertext, str):
            ciphertext = base64.b64decode(ciphertext)
        if isinstance(iv, str):
            iv = base64.b64decode(iv)
        if tag and isinstance(tag, str):
            tag = base64.b64decode(tag)

        if self.mode == 'GCM':
            return self._decrypt_gcm(ciphertext, iv, tag)
        elif self.mode == 'CBC':
            return self._decrypt_cbc(ciphertext, iv)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

    def _encrypt_gcm(self, plaintext):
        """
        Encrypt using AES-GCM mode (provides authentication)

        GCM (Galois/Counter Mode) advantages:
        - Authenticated encryption (detects tampering)
        - Parallelizable
        - No padding required
        - Produces authentication tag

        Args:
            plaintext (bytes): Data to encrypt

        Returns:
            dict: ciphertext, iv, and authentication tag (all base64-encoded)
        """
        # Generate random IV (12 bytes is standard for GCM)
        iv = os.urandom(12)

        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        )

        # Encrypt
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Get authentication tag
        tag = encryptor.tag

        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }

    def _decrypt_gcm(self, ciphertext, iv, tag):
        """
        Decrypt using AES-GCM mode

        Args:
            ciphertext (bytes): Encrypted data
            iv (bytes): Initialization vector
            tag (bytes): Authentication tag

        Returns:
            bytes: Decrypted data

        Raises:
            InvalidTag: If data has been tampered with
        """
        if tag is None:
            raise ValueError("Authentication tag required for GCM mode")

        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )

        # Decrypt and verify
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext

    def _encrypt_cbc(self, plaintext):
        """
        Encrypt using AES-CBC mode (traditional mode)

        CBC (Cipher Block Chaining) characteristics:
        - Each block depends on previous block
        - Requires padding for non-block-sized data
        - Needs unique IV for each encryption
        - No built-in authentication

        Args:
            plaintext (bytes): Data to encrypt

        Returns:
            dict: ciphertext and iv (both base64-encoded)
        """
        # Generate random IV (16 bytes for AES block size)
        iv = os.urandom(16)

        # Apply PKCS7 padding
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )

        # Encrypt
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }

    def _decrypt_cbc(self, ciphertext, iv):
        """
        Decrypt using AES-CBC mode

        Args:
            ciphertext (bytes): Encrypted data
            iv (bytes): Initialization vector

        Returns:
            bytes: Decrypted data
        """
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )

        # Decrypt
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext

    def encrypt_file(self, input_path, output_path):
        """
        Encrypt a file using AES

        Args:
            input_path (str): Path to file to encrypt
            output_path (str): Path to save encrypted file

        Returns:
            dict: Encryption metadata (iv, tag if GCM)
        """
        # Read file
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        # Encrypt
        result = self.encrypt(plaintext)

        # Write encrypted file
        with open(output_path, 'wb') as f:
            f.write(base64.b64decode(result['ciphertext']))

        # Return metadata (needed for decryption)
        metadata = {'iv': result['iv']}
        if 'tag' in result:
            metadata['tag'] = result['tag']

        return metadata

    def decrypt_file(self, input_path, output_path, iv, tag=None):
        """
        Decrypt a file using AES

        Args:
            input_path (str): Path to encrypted file
            output_path (str): Path to save decrypted file
            iv (str): Base64-encoded initialization vector
            tag (str, optional): Base64-encoded authentication tag (for GCM)

        Returns:
            bool: True if successful
        """
        # Read encrypted file
        with open(input_path, 'rb') as f:
            ciphertext = f.read()

        # Decrypt
        plaintext = self.decrypt(ciphertext, iv, tag)

        # Write decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        return True

    def export_key(self):
        """
        Export key as base64 string

        Returns:
            str: Base64-encoded key
        """
        return base64.b64encode(self.key).decode('utf-8')

    @staticmethod
    def import_key(key_b64):
        """
        Import key from base64 string

        Args:
            key_b64 (str): Base64-encoded key

        Returns:
            bytes: Key bytes
        """
        return base64.b64decode(key_b64)


# Example usage and demonstration
if __name__ == "__main__":
    print("=" * 60)
    print("AES Encryption Demonstration")
    print("=" * 60)

    # Test AES-GCM mode
    print("\n--- AES-256-GCM Mode ---")
    aes_gcm = AESEncryption(mode='GCM')

    message = "This is a secret message for AES-GCM encryption!"
    print(f"\n1. Original Message: '{message}'")

    # Encrypt
    encrypted = aes_gcm.encrypt(message)
    print(f"\n2. Encrypted Data:")
    print(f"   - Ciphertext: {encrypted['ciphertext'][:50]}...")
    print(f"   - IV: {encrypted['iv']}")
    print(f"   - Auth Tag: {encrypted['tag']}")

    # Decrypt
    decrypted = aes_gcm.decrypt(
        encrypted['ciphertext'],
        encrypted['iv'],
        encrypted['tag']
    )
    print(f"\n3. Decrypted Message: '{decrypted.decode('utf-8')}'")

    # Test AES-CBC mode
    print("\n\n--- AES-256-CBC Mode ---")
    aes_cbc = AESEncryption(mode='CBC')

    message2 = "This is a secret message for AES-CBC encryption!"
    print(f"\n1. Original Message: '{message2}'")

    # Encrypt
    encrypted2 = aes_cbc.encrypt(message2)
    print(f"\n2. Encrypted Data:")
    print(f"   - Ciphertext: {encrypted2['ciphertext'][:50]}...")
    print(f"   - IV: {encrypted2['iv']}")

    # Decrypt
    decrypted2 = aes_cbc.decrypt(
        encrypted2['ciphertext'],
        encrypted2['iv']
    )
    print(f"\n3. Decrypted Message: '{decrypted2.decode('utf-8')}'")

    # Export key
    print("\n\n--- Key Management ---")
    key_exported = aes_gcm.export_key()
    print(f"Exported Key (Base64): {key_exported}")

    print("\n" + "=" * 60)
    print("AES Encryption Demo Complete!")
    print("=" * 60)
