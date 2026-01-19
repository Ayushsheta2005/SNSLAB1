"""
Protocol Finite State Machine Module
Implements protocol state management, round tracking, key evolution,
opcode validation, and session termination logic.
"""

import struct
from enum import IntEnum
from typing import Tuple, Optional
from crypto_utils import CryptoUtils


class Opcode(IntEnum):
    """Protocol operation codes"""
    CLIENT_HELLO = 10
    SERVER_CHALLENGE = 20
    CLIENT_DATA = 30
    SERVER_AGGR_RESPONSE = 40
    KEY_DESYNC_ERROR = 50
    TERMINATE = 60


class Direction(IntEnum):
    """Message direction indicators"""
    CLIENT_TO_SERVER = 1
    SERVER_TO_CLIENT = 2


class ProtocolPhase(IntEnum):
    """Protocol state phases"""
    INIT = 0
    ACTIVE = 1
    TERMINATED = 2


class SessionState:
    """Maintains state for a single client session"""
    
    def __init__(self, client_id: int, master_key: bytes):
        """
        Initialize session state.
        
        Args:
            client_id: Unique client identifier (0-255)
            master_key: Pre-shared master key
        """
        self.client_id = client_id
        self.master_key = master_key
        self.round_number = 0
        self.phase = ProtocolPhase.INIT
        
        # Derive initial keys
        self.c2s_enc_key = CryptoUtils.derive_key(master_key, "C2S-ENC")
        self.c2s_mac_key = CryptoUtils.derive_key(master_key, "C2S-MAC")
        self.s2c_enc_key = CryptoUtils.derive_key(master_key, "S2C-ENC")
        self.s2c_mac_key = CryptoUtils.derive_key(master_key, "S2C-MAC")
        
        # Store last processed data for key evolution
        self.last_c2s_ciphertext = b""
        self.last_c2s_nonce = b""
        self.last_s2c_aggregated_data = b""
        self.last_s2c_status_code = b""
    
    def evolve_c2s_keys(self, ciphertext: bytes, nonce: bytes):
        """
        Evolve client-to-server keys after successful message processing.
        
        Args:
            ciphertext: Ciphertext from the last message
            nonce: Nonce (IV) from the last message
        """
        self.c2s_enc_key = CryptoUtils.evolve_key(self.c2s_enc_key, ciphertext)
        self.c2s_mac_key = CryptoUtils.evolve_key(self.c2s_mac_key, nonce)
        self.last_c2s_ciphertext = ciphertext
        self.last_c2s_nonce = nonce
    
    def evolve_s2c_keys(self, aggregated_data: bytes, status_code: bytes):
        """
        Evolve server-to-client keys after successful message processing.
        
        Args:
            aggregated_data: Aggregated data from the last message
            status_code: Status code from the last message
        """
        self.s2c_enc_key = CryptoUtils.evolve_key(self.s2c_enc_key, aggregated_data)
        self.s2c_mac_key = CryptoUtils.evolve_key(self.s2c_mac_key, status_code)
        self.last_s2c_aggregated_data = aggregated_data
        self.last_s2c_status_code = status_code
    
    def advance_round(self):
        """Advance to the next round"""
        self.round_number += 1
    
    def terminate(self):
        """Terminate the session"""
        self.phase = ProtocolPhase.TERMINATED
    
    def is_terminated(self) -> bool:
        """Check if session is terminated"""
        return self.phase == ProtocolPhase.TERMINATED


class ProtocolMessage:
    """Represents a protocol message with encryption and authentication"""
    
    # Message format: | Opcode (1) | Client ID (1) | Round (4) | Direction (1) | IV (16) | Ciphertext (variable) | HMAC (32) |
    HEADER_SIZE = 1 + 1 + 4 + 1 + 16  # 23 bytes
    
    def __init__(self, opcode: Opcode, client_id: int, round_num: int, 
                 direction: Direction, plaintext: bytes = b""):
        """
        Initialize a protocol message.
        
        Args:
            opcode: Operation code
            client_id: Client identifier (0-255)
            round_num: Current round number
            direction: Message direction
            plaintext: Plaintext payload (will be encrypted)
        """
        self.opcode = opcode
        self.client_id = client_id
        self.round_number = round_num
        self.direction = direction
        self.plaintext = plaintext
        self.iv = None
        self.ciphertext = None
        self.hmac = None
    
    def encrypt_and_sign(self, enc_key: bytes, mac_key: bytes) -> bytes:
        """
        Encrypt plaintext and sign the message.
        
        Args:
            enc_key: Encryption key
            mac_key: MAC key
            
        Returns:
            Complete serialized message
        """
        # Generate random IV
        self.iv = CryptoUtils.generate_random_iv()
        
        # Apply PKCS#7 padding
        padded_plaintext = CryptoUtils.apply_pkcs7_padding(self.plaintext)
        
        # Encrypt
        self.ciphertext = CryptoUtils.aes_cbc_encrypt(padded_plaintext, enc_key, self.iv)
        
        # Build header
        header = struct.pack('!B B I B', self.opcode, self.client_id, 
                            self.round_number, self.direction)
        header += self.iv
        
        # Compute HMAC over header + ciphertext
        data_to_mac = header + self.ciphertext
        self.hmac = CryptoUtils.compute_hmac(mac_key, data_to_mac)
        
        # Return complete message
        return data_to_mac + self.hmac
    
    @staticmethod
    def parse_and_verify(message_bytes: bytes, enc_key: bytes, mac_key: bytes,
                         expected_round: int, expected_direction: Direction) -> 'ProtocolMessage':
        """
        Parse, verify, and decrypt a message.
        
        Args:
            message_bytes: Raw message bytes
            enc_key: Encryption key
            mac_key: MAC key
            expected_round: Expected round number
            expected_direction: Expected direction
            
        Returns:
            Decrypted ProtocolMessage object
            
        Raises:
            ValueError: If verification fails or message is invalid
        """
        if len(message_bytes) < ProtocolMessage.HEADER_SIZE + CryptoUtils.HMAC_SIZE:
            raise ValueError("Message too short")
        
        # Extract components
        hmac_start = len(message_bytes) - CryptoUtils.HMAC_SIZE
        data_to_verify = message_bytes[:hmac_start]
        received_hmac = message_bytes[hmac_start:]
        
        # CRITICAL: Verify HMAC before any other processing
        if not CryptoUtils.verify_hmac(mac_key, data_to_verify, received_hmac):
            raise ValueError("HMAC verification failed - message authentication error")
        
        # Parse header
        header = data_to_verify[:ProtocolMessage.HEADER_SIZE]
        opcode, client_id, round_num, direction = struct.unpack('!B B I B', header[:7])
        iv = header[7:23]
        ciphertext = data_to_verify[ProtocolMessage.HEADER_SIZE:]
        
        # Verify round number
        if round_num != expected_round:
            raise ValueError(f"Round number mismatch: expected {expected_round}, got {round_num}")
        
        # Verify direction
        if direction != expected_direction:
            raise ValueError(f"Direction mismatch: expected {expected_direction}, got {direction}")
        
        # Decrypt ciphertext
        padded_plaintext = CryptoUtils.aes_cbc_decrypt(ciphertext, enc_key, iv)
        
        # Remove padding
        try:
            plaintext = CryptoUtils.remove_pkcs7_padding(padded_plaintext)
        except ValueError as e:
            raise ValueError(f"Padding removal failed - possible tampering: {e}")
        
        # Create message object
        msg = ProtocolMessage(Opcode(opcode), client_id, round_num, 
                            Direction(direction), plaintext)
        msg.iv = iv
        msg.ciphertext = ciphertext
        msg.hmac = received_hmac
        
        return msg


class ProtocolFSM:
    """Finite State Machine for protocol validation"""
    
    # Valid opcode transitions: (current_phase, received_opcode) -> next_phase
    VALID_TRANSITIONS = {
        (ProtocolPhase.INIT, Opcode.CLIENT_HELLO): ProtocolPhase.INIT,
        (ProtocolPhase.INIT, Opcode.SERVER_CHALLENGE): ProtocolPhase.ACTIVE,
        (ProtocolPhase.ACTIVE, Opcode.CLIENT_DATA): ProtocolPhase.ACTIVE,
        (ProtocolPhase.ACTIVE, Opcode.SERVER_AGGR_RESPONSE): ProtocolPhase.ACTIVE,
    }
    
    @staticmethod
    def validate_opcode(current_phase: ProtocolPhase, opcode: Opcode) -> bool:
        """
        Validate if opcode is allowed in current phase.
        
        Args:
            current_phase: Current protocol phase
            opcode: Received opcode
            
        Returns:
            True if valid, False otherwise
        """
        # TERMINATE and KEY_DESYNC_ERROR can occur in any phase
        if opcode in [Opcode.TERMINATE, Opcode.KEY_DESYNC_ERROR]:
            return True
        
        return (current_phase, opcode) in ProtocolFSM.VALID_TRANSITIONS
    
    @staticmethod
    def get_next_phase(current_phase: ProtocolPhase, opcode: Opcode) -> ProtocolPhase:
        """
        Get next phase after processing opcode.
        
        Args:
            current_phase: Current protocol phase
            opcode: Processed opcode
            
        Returns:
            Next protocol phase
        """
        if opcode in [Opcode.TERMINATE, Opcode.KEY_DESYNC_ERROR]:
            return ProtocolPhase.TERMINATED
        
        return ProtocolFSM.VALID_TRANSITIONS.get((current_phase, opcode), current_phase)
