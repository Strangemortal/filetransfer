"""
RSA (Rivest-Shamir-Adleman) Encryption Module

RSA is an asymmetric encryption algorithm that uses a public-private key pair.
It's commonly used for:
- Encrypting small amounts of data
- Key exchange
- Digital signatures

How RSA Works:
1. Generate two large prime numbers (p and q)
2. Calculate n = p * q (modulus)
3. Calculate φ(n) = (p-1) * (q-1)
4. Choose public exponent e (commonly 65537)
5. Calculate private exponent d (modular multiplicative inverse of e mod φ(n))
6. Public key: (e, n)
7. Private key: (d, n)

Encryption: c = m^e mod n
Decryption: m = c^d mod n
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64


class RSAEncryption:
    """
    RSA Encryption and Decryption Handler

    Supports:
    - Key generation (2048-bit and 4096-bit)
    - Encryption/Decryption
    - Key serialization (PEM format)
    - Public/Private key export and import
    """

    def __init__(self, key_size=2048):
        """
        Initialize RSA with specified key size

        Args:
            key_size (int): Size of RSA key in bits (2048 or 4096 recommended)
        """
        self.key_size = key_size
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """
        Generate a new RSA key pair

        Returns:
            tuple: (private_key, public_key)
        """
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,  # Commonly used public exponent
            key_size=self.key_size,
            backend=default_backend()
        )

        # Derive public key from private key
        self.public_key = self.private_key.public_key()

        return self.private_key, self.public_key

    def encrypt(self, plaintext, public_key=None):
        """
        Encrypt data using RSA public key with OAEP padding

        Args:
            plaintext (str or bytes): Data to encrypt
            public_key: RSA public key (uses self.public_key if None)

        Returns:
            str: Base64-encoded encrypted data
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("No public key available. Generate keys first.")

        # Convert string to bytes if necessary
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Encrypt using OAEP padding (Optimal Asymmetric Encryption Padding)
        # OAEP provides semantic security and prevents certain attacks
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Return base64-encoded string for easy storage/transmission
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, ciphertext, private_key=None):
        """
        Decrypt RSA-encrypted data using private key

        Args:
            ciphertext (str): Base64-encoded encrypted data
            private_key: RSA private key (uses self.private_key if None)

        Returns:
            bytes: Decrypted data
        """
        if private_key is None:
            private_key = self.private_key

        if private_key is None:
            raise ValueError("No private key available. Generate keys first.")

        # Decode base64
        ciphertext_bytes = base64.b64decode(ciphertext)

        # Decrypt using OAEP padding
        plaintext = private_key.decrypt(
            ciphertext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return plaintext

    def export_private_key(self, password=None):
        """
        Export private key in PEM format

        Args:
            password (str, optional): Password to encrypt the private key

        Returns:
            str: PEM-formatted private key
        """
        if self.private_key is None:
            raise ValueError("No private key available. Generate keys first.")

        encryption_algorithm = serialization.NoEncryption()

        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(
                password.encode('utf-8')
            )

        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

        return pem.decode('utf-8')

    def export_public_key(self):
        """
        Export public key in PEM format

        Returns:
            str: PEM-formatted public key
        """
        if self.public_key is None:
            raise ValueError("No public key available. Generate keys first.")

        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return pem.decode('utf-8')

    def import_private_key(self, pem_data, password=None):
        """
        Import private key from PEM format

        Args:
            pem_data (str or bytes): PEM-formatted private key
            password (str, optional): Password if key is encrypted
        """
        if isinstance(pem_data, str):
            pem_data = pem_data.encode('utf-8')

        password_bytes = None
        if password:
            password_bytes = password.encode('utf-8')

        self.private_key = serialization.load_pem_private_key(
            pem_data,
            password=password_bytes,
            backend=default_backend()
        )

        self.public_key = self.private_key.public_key()

    def import_public_key(self, pem_data):
        """
        Import public key from PEM format

        Args:
            pem_data (str or bytes): PEM-formatted public key
        """
        if isinstance(pem_data, str):
            pem_data = pem_data.encode('utf-8')

        self.public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )

    def get_key_info(self):
        """
        Get information about current keys

        Returns:
            dict: Key information including key size and availability
        """
        return {
            'key_size': self.key_size,
            'has_private_key': self.private_key is not None,
            'has_public_key': self.public_key is not None,
            'max_encryption_size': (self.key_size // 8) - 42  # OAEP padding overhead
        }


# Example usage and demonstration
if __name__ == "__main__":
    print("=" * 60)
    print("RSA Encryption Demonstration")
    print("=" * 60)

    # Initialize RSA
    rsa_handler = RSAEncryption(key_size=2048)

    # Generate keys
    print("\n1. Generating RSA key pair (2048-bit)...")
    private_key, public_key = rsa_handler.generate_keys()
    print("   Keys generated successfully!")

    # Display key info
    info = rsa_handler.get_key_info()
    print(f"\n2. Key Information:")
    print(f"   - Key Size: {info['key_size']} bits")
    print(f"   - Max Encryption Size: {info['max_encryption_size']} bytes")

    # Encrypt a message
    message = "Hello, this is a secret message for RSA encryption!"
    print(f"\n3. Original Message: '{message}'")

    encrypted = rsa_handler.encrypt(message)
    print(f"\n4. Encrypted (Base64): {encrypted[:60]}...")

    # Decrypt the message
    decrypted = rsa_handler.decrypt(encrypted)
    print(f"\n5. Decrypted Message: '{decrypted.decode('utf-8')}'")

    # Export keys
    print("\n6. Exporting keys...")
    private_pem = rsa_handler.export_private_key()
    public_pem = rsa_handler.export_public_key()

    print("\n   Private Key (PEM format):")
    print("   " + private_pem.split('\n')[0])
    print("   [... key data ...]")
    print("   " + private_pem.split('\n')[-2])

    print("\n   Public Key (PEM format):")
    print("   " + public_pem.split('\n')[0])
    print("   [... key data ...]")
    print("   " + public_pem.split('\n')[-2])

    print("\n" + "=" * 60)
    print("RSA Encryption Demo Complete!")
    print("=" * 60)
