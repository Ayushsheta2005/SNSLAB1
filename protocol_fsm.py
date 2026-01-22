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
    
    # Enhanced Error Codes for Specific Attack Scenarios
    ERROR_INVALID_HMAC = 51          # HMAC verification failed (tampering detected)
    ERROR_REPLAY_DETECTED = 52       # Replay attack detected (old round number)
    ERROR_REORDERING_DETECTED = 53   # Message reordering detected (wrong round)
    ERROR_KEY_DESYNC = 54            # Key desynchronization detected
    ERROR_INVALID_DIRECTION = 55     # Wrong direction field (reflection attack)
    ERROR_INVALID_PHASE = 56         # Invalid opcode for current phase
    ERROR_INVALID_CLIENT = 57        # Unauthorized client
    ERROR_PADDING_ERROR = 58         # Padding validation failed
    ERROR_DECRYPTION_FAILED = 59     # Decryption error


class Direction(IntEnum):
    """Message direction indicators"""
    CLIENT_TO_SERVER = 1
    SERVER_TO_CLIENT = 2


class ProtocolPhase(IntEnum):
    """Protocol state phases"""
    INIT = 0
    ACTIVE = 1
    TERMINATED = 2


class SecurityError(Exception):
    """Base class for security-related errors with specific error codes"""
    def __init__(self, error_code: Opcode, message: str, details: dict = None):
        self.error_code = error_code
        self.message = message
        self.details = details or {}
        super().__init__(f"[{error_code.name}] {message}")


class InvalidHMACError(SecurityError):
    """HMAC verification failed - message tampering or key mismatch detected"""
    def __init__(self, expected_round: int, actual_round: int = None):
        super().__init__(
            Opcode.ERROR_INVALID_HMAC,
            "HMAC verification failed - message authentication error (tampering or key mismatch)",
            {"expected_round": expected_round, "actual_round": actual_round}
        )


class ReplayAttackError(SecurityError):
    """Replay attack detected - old message with past round number"""
    def __init__(self, expected_round: int, received_round: int):
        super().__init__(
            Opcode.ERROR_REPLAY_DETECTED,
            f"Replay attack detected - received old message from round {received_round}, expected {expected_round}",
            {"expected_round": expected_round, "received_round": received_round}
        )


class ReorderingAttackError(SecurityError):
    """Message reordering detected - future or out-of-sequence message"""
    def __init__(self, expected_round: int, received_round: int):
        super().__init__(
            Opcode.ERROR_REORDERING_DETECTED,
            f"Message reordering detected - expected round {expected_round}, got {received_round}",
            {"expected_round": expected_round, "received_round": received_round}
        )


class KeyDesyncError(SecurityError):
    """Key desynchronization detected - decryption failed"""
    def __init__(self, client_id: int, round_num: int):
        super().__init__(
            Opcode.ERROR_KEY_DESYNC,
            f"Key desynchronization detected for client {client_id} at round {round_num}",
            {"client_id": client_id, "round_num": round_num}
        )


class InvalidDirectionError(SecurityError):
    """Invalid direction field - possible reflection attack"""
    def __init__(self, expected: Direction, received: int):
        super().__init__(
            Opcode.ERROR_INVALID_DIRECTION,
            f"Invalid direction - expected {expected.name}, got {received} (possible reflection attack)",
            {"expected": expected.value, "received": received}
        )


class InvalidPhaseError(SecurityError):
    """Invalid opcode for current protocol phase"""
    def __init__(self, current_phase: ProtocolPhase, received_opcode: Opcode):
        super().__init__(
            Opcode.ERROR_INVALID_PHASE,
            f"Invalid opcode {received_opcode.name} for phase {current_phase.name}",
            {"current_phase": current_phase.value, "received_opcode": received_opcode.value}
        )


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
        Parse, verify, and decrypt a message with ENHANCED ERROR DETECTION.
        
        Raises specific exceptions for different attack scenarios:
        - InvalidHMACError: HMAC verification failed (tampering)
        - ReplayAttackError: Old round number (replay attack)
        - ReorderingAttackError: Future/wrong round number (reordering)
        - InvalidDirectionError: Wrong direction field (reflection attack)
        - KeyDesyncError: Decryption failed (key desynchronization)
        
        Args:
            message_bytes: Raw message bytes
            enc_key: Encryption key
            mac_key: MAC key
            expected_round: Expected round number
            expected_direction: Expected direction
            
        Returns:
            Decrypted ProtocolMessage object
            
        Raises:
            Various SecurityError subclasses for specific attacks
        """
        if len(message_bytes) < ProtocolMessage.HEADER_SIZE + CryptoUtils.HMAC_SIZE:
            raise ValueError("Message too short")
        
        # Extract components
        hmac_start = len(message_bytes) - CryptoUtils.HMAC_SIZE
        data_to_verify = message_bytes[:hmac_start]
        received_hmac = message_bytes[hmac_start:]
        
        # Parse header to extract metadata for error reporting
        header = data_to_verify[:ProtocolMessage.HEADER_SIZE]
        opcode, client_id, round_num, direction = struct.unpack('!B B I B', header[:7])
        iv = header[7:23]
        ciphertext = data_to_verify[ProtocolMessage.HEADER_SIZE:]
        
        # ===== STEP 1: CHECK ROUND NUMBER FIRST (Detect Replay/Reordering) =====
        if round_num < expected_round:
            # Old message - REPLAY ATTACK DETECTED
            raise ReplayAttackError(expected_round, round_num)
        elif round_num > expected_round:
            # Future message - REORDERING ATTACK DETECTED
            raise ReorderingAttackError(expected_round, round_num)
        
        # ===== STEP 2: CHECK DIRECTION FIELD (Detect Reflection) =====
        if direction != expected_direction:
            raise InvalidDirectionError(expected_direction, direction)
        
        # ===== STEP 3: VERIFY HMAC (Detect Tampering/Key Issues) =====
        # CRITICAL: HMAC verification happens BEFORE any decryption
        if not CryptoUtils.verify_hmac(mac_key, data_to_verify, received_hmac):
            # HMAC failed - could be:
            # 1. Message tampering (modified ciphertext/header)
            # 2. Key desynchronization (wrong MAC key)
            # 3. Corrupted data in transit
            raise InvalidHMACError(expected_round, round_num)
        
        # ===== STEP 4: DECRYPT (Only after all security checks pass) =====
        try:
            padded_plaintext = CryptoUtils.aes_cbc_decrypt(ciphertext, enc_key, iv)
        except Exception as e:
            # Decryption failed - likely key desynchronization
            raise KeyDesyncError(client_id, round_num)
        
        # ===== STEP 5: REMOVE PADDING =====
        try:
            plaintext = CryptoUtils.remove_pkcs7_padding(padded_plaintext)
        except ValueError as e:
            # Padding error - data corruption or tampering
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
