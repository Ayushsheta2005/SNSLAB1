"""
Cryptographic Utilities Module
Contains only cryptographic primitives: AES-CBC, PKCS#7 padding, and HMAC.
No protocol or networking logic is included here.
"""

import os
import hmac
import hashlib
from Crypto.Cipher import AES


class CryptoUtils:
    """Provides core cryptographic operations for the secure communication protocol."""
    
    BLOCK_SIZE = 16  # AES block size in bytes
    IV_SIZE = 16     # Initialization vector size
    HMAC_SIZE = 32   # HMAC-SHA256 output size
    
    @staticmethod
    def apply_pkcs7_padding(data: bytes) -> bytes:
        """
        Manually applies PKCS#7 padding to data.
        
        Args:
            data: Raw bytes to be padded
            
        Returns:
            Padded data according to PKCS#7 specification
        """
        padding_length = CryptoUtils.BLOCK_SIZE - (len(data) % CryptoUtils.BLOCK_SIZE)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def remove_pkcs7_padding(padded_data: bytes) -> bytes:
        """
        Manually removes PKCS#7 padding from data.
        
        Args:
            padded_data: Padded data to be unpadded
            
        Returns:
            Original unpadded data
            
        Raises:
            ValueError: If padding is invalid (indicating tampering)
        """
        if len(padded_data) == 0:
            raise ValueError("Cannot remove padding from empty data")
        
        padding_length = padded_data[-1]
        
        # Validate padding
        if padding_length == 0 or padding_length > CryptoUtils.BLOCK_SIZE:
            raise ValueError("Invalid padding length")
        
        # Check all padding bytes are correct
        for i in range(padding_length):
            if padded_data[-(i + 1)] != padding_length:
                raise ValueError("Invalid padding bytes - data tampering detected")
        
        return padded_data[:-padding_length]
    
    @staticmethod
    def generate_random_iv() -> bytes:
        """
        Generates a cryptographically secure random IV.
        
        Returns:
            16-byte random IV
        """
        return os.urandom(CryptoUtils.IV_SIZE)
    
    @staticmethod
    def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Encrypts plaintext using AES-128-CBC mode.
        
        Args:
            plaintext: Data to encrypt (must be already padded)
            key: 16-byte AES-128 key
            iv: 16-byte initialization vector
            
        Returns:
            Encrypted ciphertext
        """
        if len(key) != 16:
            raise ValueError("Key must be exactly 16 bytes for AES-128")
        if len(iv) != CryptoUtils.IV_SIZE:
            raise ValueError(f"IV must be exactly {CryptoUtils.IV_SIZE} bytes")
        if len(plaintext) % CryptoUtils.BLOCK_SIZE != 0:
            raise ValueError("Plaintext must be padded to block size")
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(plaintext)
    
    @staticmethod
    def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypts ciphertext using AES-128-CBC mode.
        
        Args:
            ciphertext: Encrypted data
            key: 16-byte AES-128 key
            iv: 16-byte initialization vector
            
        Returns:
            Decrypted plaintext (still padded)
        """
        if len(key) != 16:
            raise ValueError("Key must be exactly 16 bytes for AES-128")
        if len(iv) != CryptoUtils.IV_SIZE:
            raise ValueError(f"IV must be exactly {CryptoUtils.IV_SIZE} bytes")
        if len(ciphertext) % CryptoUtils.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be multiple of block size")
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(ciphertext)
    
    @staticmethod
    def compute_hmac(key: bytes, data: bytes) -> bytes:
        """
        Computes HMAC-SHA256 over data.
        
        Args:
            key: HMAC key
            data: Data to authenticate
            
        Returns:
            32-byte HMAC tag
        """
        return hmac.new(key, data, hashlib.sha256).digest()
    
    @staticmethod
    def verify_hmac(key: bytes, data: bytes, tag: bytes) -> bool:
        """
        Verifies HMAC-SHA256 tag in constant time.
        
        Args:
            key: HMAC key
            data: Data that was authenticated
            tag: HMAC tag to verify
            
        Returns:
            True if HMAC is valid, False otherwise
        """
        expected_tag = CryptoUtils.compute_hmac(key, data)
        return hmac.compare_digest(expected_tag, tag)
    
    @staticmethod
    def derive_key(master_key: bytes, label: str) -> bytes:
        """
        Derives a key from master key using SHA-256.
        
        Args:
            master_key: Master key material
            label: Label string for key derivation
            
        Returns:
            16-byte derived key (truncated from SHA-256)
        """
        derived = hashlib.sha256(master_key + label.encode()).digest()
        return derived[:16]  # Use first 16 bytes for AES-128
    
    @staticmethod
    def evolve_key(current_key: bytes, additional_data: bytes) -> bytes:
        """
        Evolves key using key ratcheting.
        
        Args:
            current_key: Current key
            additional_data: Additional data for key evolution
            
        Returns:
            16-byte evolved key
        """
        evolved = hashlib.sha256(current_key + additional_data).digest()
        return evolved[:16]  # Use first 16 bytes for AES-128
