"""
Digital Signature Module (RSA-based)

Digital signatures provide:
1. Authentication - Verify the sender's identity
2. Non-repudiation - Sender cannot deny signing
3. Integrity - Detect if message was modified

How Digital Signatures Work:

Signing Process:
1. Hash the message using SHA-256
2. Encrypt the hash with sender's private key
3. Attach signature to message

Verification Process:
1. Hash the received message using SHA-256
2. Decrypt the signature using sender's public key
3. Compare decrypted hash with computed hash
4. If they match, signature is valid

Mathematical Foundation:
- Based on RSA asymmetric cryptography
- Uses modular exponentiation
- Sign: signature = hash^d mod n (using private key d)
- Verify: hash = signature^e mod n (using public key e)

Security Properties:
- Only private key holder can create valid signature
- Anyone with public key can verify signature
- Signature is unique to both message and signer
- Tampering invalidates signature

Padding Scheme:
- PSS (Probabilistic Signature Scheme)
- Provides additional security
- Prevents certain cryptographic attacks
- Adds randomness to signature process
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64


class DigitalSignature:
    """
    RSA-based Digital Signature Handler

    Supports:
    - Signature creation (signing)
    - Signature verification
    - Key pair generation
    - Multiple hash algorithms
    - PSS padding for enhanced security
    """

    def __init__(self, private_key=None, public_key=None, key_size=2048):
        """
        Initialize Digital Signature handler

        Args:
            private_key: RSA private key (for signing)
            public_key: RSA public key (for verification)
            key_size (int): Size of RSA key in bits (if generating new keys)
        """
        self.private_key = private_key
        self.public_key = public_key
        self.key_size = key_size

    def generate_keys(self):
        """
        Generate a new RSA key pair for signing

        Returns:
            tuple: (private_key, public_key)
        """
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )

        # Derive public key
        self.public_key = self.private_key.public_key()

        return self.private_key, self.public_key

    def sign(self, message, private_key=None):
        """
        Create a digital signature for a message

        Args:
            message (str or bytes): Message to sign
            private_key: RSA private key (uses self.private_key if None)

        Returns:
            str: Base64-encoded signature
        """
        if private_key is None:
            private_key = self.private_key

        if private_key is None:
            raise ValueError("No private key available. Generate keys first.")

        # Convert string to bytes
        if isinstance(message, str):
            message = message.encode('utf-8')

        # Sign using PSS padding
        # PSS (Probabilistic Signature Scheme) is more secure than PKCS1v15
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return base64.b64encode(signature).decode('utf-8')

    def verify(self, message, signature, public_key=None):
        """
        Verify a digital signature

        Args:
            message (str or bytes): Original message
            signature (str): Base64-encoded signature
            public_key: RSA public key (uses self.public_key if None)

        Returns:
            bool: True if signature is valid, False otherwise
        """
        if public_key is None:
            public_key = self.public_key

        if public_key is None:
            raise ValueError("No public key available. Load or generate keys first.")

        # Convert string to bytes
        if isinstance(message, str):
            message = message.encode('utf-8')

        # Decode signature
        signature_bytes = base64.b64decode(signature)

        try:
            # Verify signature
            public_key.verify(
                signature_bytes,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def sign_file(self, file_path, output_signature_path=None):
        """
        Create a digital signature for a file

        Args:
            file_path (str): Path to file to sign
            output_signature_path (str, optional): Path to save signature file

        Returns:
            str: Base64-encoded signature
        """
        if self.private_key is None:
            raise ValueError("No private key available. Generate keys first.")

        # Read file
        with open(file_path, 'rb') as f:
            file_content = f.read()

        # Sign file content
        signature = self.sign(file_content)

        # Save signature to file if path provided
        if output_signature_path:
            with open(output_signature_path, 'w') as f:
                f.write(signature)

        return signature

    def verify_file(self, file_path, signature, signature_path=None):
        """
        Verify a file's digital signature

        Args:
            file_path (str): Path to file to verify
            signature (str, optional): Base64-encoded signature
            signature_path (str, optional): Path to signature file

        Returns:
            bool: True if signature is valid, False otherwise
        """
        if self.public_key is None:
            raise ValueError("No public key available. Load or generate keys first.")

        # Read file
        with open(file_path, 'rb') as f:
            file_content = f.read()

        # Read signature from file if path provided
        if signature_path:
            with open(signature_path, 'r') as f:
                signature = f.read().strip()

        # Verify signature
        return self.verify(file_content, signature)

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

    def get_signature_info(self, signature):
        """
        Get information about a signature

        Args:
            signature (str): Base64-encoded signature

        Returns:
            dict: Signature information
        """
        signature_bytes = base64.b64decode(signature)

        return {
            'signature_length': len(signature_bytes),
            'signature_bits': len(signature_bytes) * 8,
            'encoding': 'base64',
            'algorithm': 'RSA-PSS with SHA-256'
        }


# Example usage and demonstration
if __name__ == "__main__":
    print("=" * 60)
    print("Digital Signature Demonstration")
    print("=" * 60)

    # Initialize
    ds = DigitalSignature(key_size=2048)

    # Generate keys
    print("\n1. Generating RSA key pair for digital signatures...")
    private_key, public_key = ds.generate_keys()
    print("   Keys generated successfully!")

    # Sign a message
    message = "This is an important message that needs to be signed."
    print(f"\n2. Original Message: '{message}'")

    signature = ds.sign(message)
    print(f"\n3. Digital Signature (Base64):")
    print(f"   {signature[:60]}...")

    # Get signature info
    sig_info = ds.get_signature_info(signature)
    print(f"\n4. Signature Information:")
    print(f"   - Signature Length: {sig_info['signature_length']} bytes")
    print(f"   - Signature Bits: {sig_info['signature_bits']} bits")
    print(f"   - Algorithm: {sig_info['algorithm']}")

    # Verify signature (correct message)
    is_valid = ds.verify(message, signature)
    print(f"\n5. Signature Verification (Original): {is_valid}")

    # Verify with tampered message
    tampered_message = "This message has been tampered with!"
    is_valid_tampered = ds.verify(tampered_message, signature)
    print(f"\n6. Signature Verification (Tampered): {is_valid_tampered}")

    # Demonstrate key exchange scenario
    print("\n\n--- Key Exchange Scenario ---")
    print("\nScenario: Alice signs a message and sends it to Bob")

    # Alice's side
    print("\n[Alice's Side]")
    alice = DigitalSignature()
    alice.generate_keys()
    alice_message = "Hello Bob, this is a secure message from Alice."
    alice_signature = alice.sign(alice_message)
    alice_public_key = alice.export_public_key()

    print(f"1. Alice creates message: '{alice_message}'")
    print(f"2. Alice signs the message")
    print(f"3. Alice sends: message + signature + public key")

    # Bob's side
    print("\n[Bob's Side]")
    bob = DigitalSignature()
    bob.import_public_key(alice_public_key)

    print(f"4. Bob receives message: '{alice_message}'")
    print("5. Bob receives Alice's public key")
    print("6. Bob verifies signature...")

    verification = bob.verify(alice_message, alice_signature)

    if verification:
        print("   ✓ Signature is VALID")
        print("   ✓ Message is from Alice")
        print("   ✓ Message has not been tampered with")
    else:
        print("   ✗ Signature is INVALID")
        print("   ✗ Message may be forged or tampered")

    print("\n" + "=" * 60)
    print("Digital Signature Demo Complete!")
    print("=" * 60)
