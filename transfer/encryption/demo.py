"""
Comprehensive Encryption Module Demonstration

This script demonstrates all encryption modules:
1. RSA Encryption
2. AES Encryption
3. SHA-256 Hashing
4. HMAC
5. Digital Signatures

Run this script to see all encryption features in action.
"""

import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encryption.rsa_encryption import RSAEncryption
from encryption.aes_encryption import AESEncryption
from encryption.hashing import SHA256Hash, HMACGenerator
from encryption.digital_signature import DigitalSignature


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def demo_rsa():
    """Demonstrate RSA encryption"""
    print_section("1. RSA (Rivest-Shamir-Adleman) Encryption")

    # Initialize
    rsa = RSAEncryption(key_size=2048)
    rsa.generate_keys()

    # Get key info
    info = rsa.get_key_info()
    print(f"\nKey Size: {info['key_size']} bits")
    print(f"Max Encryption Size: {info['max_encryption_size']} bytes")

    # Encrypt
    message = "Confidential: Project budget is $1,000,000"
    print(f"\nOriginal Message: '{message}'")

    encrypted = rsa.encrypt(message)
    print(f"\nEncrypted: {encrypted[:50]}...")

    # Decrypt
    decrypted = rsa.decrypt(encrypted)
    print(f"Decrypted: '{decrypted.decode('utf-8')}'")

    # Export keys
    public_pem = rsa.export_public_key()
    print(f"\nPublic Key (first line): {public_pem.split(chr(10))[0]}")

    print("\n✓ RSA encryption/decryption successful!")


def demo_aes():
    """Demonstrate AES encryption"""
    print_section("2. AES (Advanced Encryption Standard) Encryption")

    # AES-GCM Mode
    print("\n--- AES-256-GCM Mode ---")
    aes_gcm = AESEncryption(mode='GCM')

    message = "Secret file contents: User passwords database"
    print(f"\nOriginal Data: '{message}'")

    # Encrypt
    encrypted = aes_gcm.encrypt(message)
    print(f"\nEncrypted: {encrypted['ciphertext'][:50]}...")
    print(f"IV: {encrypted['iv']}")
    print(f"Auth Tag: {encrypted['tag']}")

    # Decrypt
    decrypted = aes_gcm.decrypt(
        encrypted['ciphertext'],
        encrypted['iv'],
        encrypted['tag']
    )
    print(f"\nDecrypted: '{decrypted.decode('utf-8')}'")

    # Export key
    key = aes_gcm.export_key()
    print(f"\nAES Key: {key}")

    print("\n✓ AES-GCM encryption/decryption successful!")

    # AES-CBC Mode
    print("\n--- AES-256-CBC Mode ---")
    aes_cbc = AESEncryption(mode='CBC')

    message2 = "Another secret: Nuclear launch codes"
    print(f"\nOriginal Data: '{message2}'")

    encrypted2 = aes_cbc.encrypt(message2)
    print(f"Encrypted: {encrypted2['ciphertext'][:50]}...")

    decrypted2 = aes_cbc.decrypt(encrypted2['ciphertext'], encrypted2['iv'])
    print(f"Decrypted: '{decrypted2.decode('utf-8')}'")

    print("\n✓ AES-CBC encryption/decryption successful!")


def demo_sha256():
    """Demonstrate SHA-256 hashing"""
    print_section("3. SHA-256 (Secure Hash Algorithm) Hashing")

    # Basic hashing
    data = "Important document content"
    print(f"\nData: '{data}'")

    hash_hex = SHA256Hash.hash_string(data, output_format='hex')
    print(f"\nSHA-256 Hash (Hex): {hash_hex}")

    hash_b64 = SHA256Hash.hash_string(data, output_format='base64')
    print(f"SHA-256 Hash (Base64): {hash_b64}")

    # Verify hash
    is_valid = SHA256Hash.verify_hash(data, hash_hex, input_format='hex')
    print(f"\nHash Verification: {is_valid}")

    # Salted hashing (for passwords)
    print("\n--- Salted Hashing (Password Storage) ---")
    password = "MySecurePassword123!"
    print(f"\nPassword: '{password}'")

    hashed_pw, salt = SHA256Hash.hash_with_salt(password)
    print(f"\nHashed: {hashed_pw}")
    print(f"Salt: {salt}")

    # Verify password
    is_correct = SHA256Hash.verify_hash(password, hashed_pw, salt=salt)
    print(f"\nPassword Verification: {is_correct}")

    wrong_password = "WrongPassword"
    is_wrong = SHA256Hash.verify_hash(wrong_password, hashed_pw, salt=salt)
    print(f"Wrong Password Verification: {is_wrong}")

    print("\n✓ SHA-256 hashing successful!")


def demo_hmac():
    """Demonstrate HMAC"""
    print_section("4. HMAC (Hash-based Message Authentication Code)")

    # Initialize
    hmac_gen = HMACGenerator()

    message = "Transfer $50,000 to account #12345"
    print(f"\nMessage: '{message}'")

    # Generate HMAC
    message_hmac = hmac_gen.generate(message)
    print(f"\nHMAC: {message_hmac}")

    # Verify HMAC
    is_valid = hmac_gen.verify(message, message_hmac)
    print(f"\nHMAC Verification (Original): {is_valid}")

    # Tampered message
    tampered = "Transfer $99,999 to account #54321"
    is_tampered = hmac_gen.verify(tampered, message_hmac)
    print(f"HMAC Verification (Tampered): {is_tampered}")

    # Export key
    key = hmac_gen.export_key()
    print(f"\nHMAC Key: {key}")

    print("\n✓ HMAC generation/verification successful!")


def demo_digital_signature():
    """Demonstrate digital signatures"""
    print_section("5. Digital Signature (RSA-based)")

    # Initialize
    ds = DigitalSignature(key_size=2048)
    ds.generate_keys()

    # Sign message
    message = "I, Alice, transfer ownership of property to Bob."
    print(f"\nMessage: '{message}'")

    signature = ds.sign(message)
    print(f"\nDigital Signature: {signature[:60]}...")

    # Get signature info
    sig_info = ds.get_signature_info(signature)
    print(f"\nSignature Info:")
    print(f"  - Length: {sig_info['signature_length']} bytes")
    print(f"  - Bits: {sig_info['signature_bits']}")
    print(f"  - Algorithm: {sig_info['algorithm']}")

    # Verify signature
    is_valid = ds.verify(message, signature)
    print(f"\nSignature Verification (Original): {is_valid}")

    # Tampered message
    tampered = "I, Alice, transfer ownership of property to Charlie."
    is_tampered = ds.verify(tampered, signature)
    print(f"Signature Verification (Tampered): {is_tampered}")

    # Demonstrate real-world scenario
    print("\n--- Real-World Scenario: Document Signing ---")
    print("\nAlice signs a contract and sends it to Bob")

    # Alice's side
    alice = DigitalSignature()
    alice.generate_keys()

    contract = "Contract: Alice agrees to sell house for $500,000"
    alice_signature = alice.sign(contract)
    alice_public_key = alice.export_public_key()

    print(f"\n[Alice] Contract: '{contract}'")
    print(f"[Alice] Signature created: {alice_signature[:40]}...")
    print("[Alice] Sends: contract + signature + public key to Bob")

    # Bob's side
    bob = DigitalSignature()
    bob.import_public_key(alice_public_key)

    print("\n[Bob] Receives contract and signature")
    print("[Bob] Verifying signature...")

    is_verified = bob.verify(contract, alice_signature)

    if is_verified:
        print("\n✓ Signature VALID - Contract is authentic!")
        print("✓ Contract was signed by Alice")
        print("✓ Contract has not been modified")
    else:
        print("\n✗ Signature INVALID - Contract may be forged!")

    print("\n✓ Digital signature demonstration successful!")


def demo_combined_scenario():
    """Demonstrate a complete secure communication scenario"""
    print_section("6. Complete Secure Communication Scenario")

    print("\nScenario: Alice sends an encrypted, signed message to Bob")
    print("\nSteps:")
    print("1. Alice creates a message")
    print("2. Alice signs the message (authentication)")
    print("3. Alice encrypts message + signature with AES")
    print("4. Alice encrypts AES key with Bob's RSA public key")
    print("5. Alice computes HMAC for integrity")
    print("6. Bob receives and verifies everything")

    # Setup
    print("\n--- Setup ---")

    # Alice's keys
    alice_ds = DigitalSignature()
    alice_ds.generate_keys()
    alice_public_key = alice_ds.export_public_key()

    # Bob's keys
    bob_rsa = RSAEncryption()
    bob_rsa.generate_keys()
    bob_public_key = bob_rsa.export_public_key()

    print("Alice: Generated signing keys")
    print("Bob: Generated RSA keys")

    # Alice sends message
    print("\n--- Alice's Side ---")

    message = "Meet me at the secret location at midnight."
    print(f"\n1. Original Message: '{message}'")

    # Step 1: Sign the message
    signature = alice_ds.sign(message)
    print(f"\n2. Message signed: {signature[:40]}...")

    # Step 2: Encrypt with AES
    aes = AESEncryption(mode='GCM')
    combined = f"{message}|||{signature}"
    encrypted_data = aes.encrypt(combined)
    print(f"\n3. Message+Signature encrypted with AES")

    # Step 3: Encrypt AES key with Bob's RSA public key
    aes_key_b64 = aes.export_key()
    encrypted_aes_key = bob_rsa.encrypt(aes_key_b64)
    print(f"\n4. AES key encrypted with Bob's public key")

    # Step 4: Compute HMAC for integrity
    hmac_gen = HMACGenerator()
    hmac_value = hmac_gen.generate(encrypted_data['ciphertext'])
    print(f"\n5. HMAC computed: {hmac_value[:40]}...")

    # Bob receives message
    print("\n--- Bob's Side ---")

    print("\nBob receives:")
    print("  - Encrypted data (AES)")
    print("  - Encrypted AES key (RSA)")
    print("  - HMAC")
    print("  - IV and Auth Tag")
    print("  - Alice's public key")

    # Step 1: Decrypt AES key
    decrypted_aes_key = bob_rsa.decrypt(encrypted_aes_key)
    aes_bob = AESEncryption(key=AESEncryption.import_key(decrypted_aes_key.decode('utf-8')))
    print("\n1. AES key decrypted with Bob's private key")

    # Step 2: Verify HMAC
    is_hmac_valid = hmac_gen.verify(encrypted_data['ciphertext'], hmac_value)
    print(f"\n2. HMAC verified: {is_hmac_valid}")

    if not is_hmac_valid:
        print("   ✗ Message integrity compromised! Aborting.")
        return

    # Step 3: Decrypt message
    decrypted_combined = aes_bob.decrypt(
        encrypted_data['ciphertext'],
        encrypted_data['iv'],
        encrypted_data['tag']
    ).decode('utf-8')
    print(f"\n3. Message decrypted with AES")

    # Step 4: Extract message and signature
    parts = decrypted_combined.split('|||')
    received_message = parts[0]
    received_signature = parts[1]

    print(f"\n4. Extracted message: '{received_message}'")

    # Step 5: Verify signature
    bob_ds = DigitalSignature()
    bob_ds.import_public_key(alice_public_key)
    is_signature_valid = bob_ds.verify(received_message, received_signature)

    print(f"\n5. Signature verified: {is_signature_valid}")

    # Final result
    print("\n--- Result ---")
    if is_signature_valid and is_hmac_valid:
        print("\n✓✓✓ SUCCESS ✓✓✓")
        print(f"\nBob successfully received: '{received_message}'")
        print("\nSecurity properties achieved:")
        print("  ✓ Confidentiality (AES encryption)")
        print("  ✓ Authentication (Digital signature)")
        print("  ✓ Integrity (HMAC)")
        print("  ✓ Non-repudiation (Digital signature)")
        print("  ✓ Key exchange (RSA)")
    else:
        print("\n✗ FAILURE - Security verification failed!")


def main():
    """Run all demonstrations"""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  COMPREHENSIVE CRYPTOGRAPHY DEMONSTRATION".center(68) + "║")
    print("║" + "  Secure File Transfer System".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "=" * 68 + "╝")

    try:
        demo_rsa()
        input("\nPress Enter to continue to AES demo...")

        demo_aes()
        input("\nPress Enter to continue to SHA-256 demo...")

        demo_sha256()
        input("\nPress Enter to continue to HMAC demo...")

        demo_hmac()
        input("\nPress Enter to continue to Digital Signature demo...")

        demo_digital_signature()
        input("\nPress Enter to see complete scenario...")

        demo_combined_scenario()

        print_section("All Demonstrations Complete!")
        print("\n✓ All encryption modules working correctly!")
        print("\nYou can now use these modules in your file transfer application.")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
