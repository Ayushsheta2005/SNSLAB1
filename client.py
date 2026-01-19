"""
Client Implementation for Secure Multi-Client Communication
Implements stateful symmetric key protocol with the server.
"""

import socket
import struct
import time
from protocol_fsm import (
    SessionState, ProtocolMessage, ProtocolFSM,
    Opcode, Direction, ProtocolPhase
)
from crypto_utils import CryptoUtils


class SecureClient:
    """Client for secure communication with server"""
    
    def __init__(self, client_id: int, master_key: bytes, 
                 host: str = '127.0.0.1', port: int = 9999):
        """
        Initialize the secure client.
        
        Args:
            client_id: Unique client identifier (1-255)
            master_key: Pre-shared master key (16 bytes)
            host: Server host address
            port: Server port number
        """
        self.host = host
        self.port = port
        self.socket = None
        self.session = SessionState(client_id, master_key)
        self.connected = False
    
    def connect(self):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            print(f"[CLIENT {self.session.client_id}] Connected to server at {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[CLIENT {self.session.client_id}] Connection failed: {e}")
            return False
    
    def send_hello(self) -> bool:
        """
        Send CLIENT_HELLO message to initiate protocol.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.session.is_terminated():
                print(f"[CLIENT {self.session.client_id}] Session is terminated")
                return False
            
            print(f"[CLIENT {self.session.client_id}] Sending CLIENT_HELLO")
            
            # Create CLIENT_HELLO message
            hello_payload = f"Hello from client {self.session.client_id}".encode()
            msg = ProtocolMessage(
                Opcode.CLIENT_HELLO,
                self.session.client_id,
                self.session.round_number,
                Direction.CLIENT_TO_SERVER,
                hello_payload
            )
            
            # Encrypt and sign
            msg_bytes = msg.encrypt_and_sign(
                self.session.c2s_enc_key,
                self.session.c2s_mac_key
            )
            
            # Send message
            self.send_message(msg_bytes)
            
            # Evolve C2S keys
            self.session.evolve_c2s_keys(msg.ciphertext, msg.iv)
            
            # Receive SERVER_CHALLENGE
            response = self.receive_message()
            if not response:
                print(f"[CLIENT {self.session.client_id}] No response to CLIENT_HELLO")
                self.session.terminate()
                return False
            
            # Parse and verify SERVER_CHALLENGE
            challenge_msg = ProtocolMessage.parse_and_verify(
                response,
                self.session.s2c_enc_key,
                self.session.s2c_mac_key,
                expected_round=self.session.round_number,
                expected_direction=Direction.SERVER_TO_CLIENT
            )
            
            if challenge_msg.opcode != Opcode.SERVER_CHALLENGE:
                print(f"[CLIENT {self.session.client_id}] Expected SERVER_CHALLENGE, got {challenge_msg.opcode}")
                self.session.terminate()
                return False
            
            print(f"[CLIENT {self.session.client_id}] Received SERVER_CHALLENGE: {challenge_msg.plaintext.decode()}")
            
            # Evolve S2C keys
            self.session.evolve_s2c_keys(challenge_msg.plaintext, b"OK")
            
            # Update phase and advance round
            self.session.phase = ProtocolFSM.get_next_phase(self.session.phase, Opcode.SERVER_CHALLENGE)
            self.session.advance_round()
            
            print(f"[CLIENT {self.session.client_id}] Handshake complete, advancing to round {self.session.round_number}")
            
            return True
            
        except ValueError as e:
            print(f"[CLIENT {self.session.client_id}] Handshake failed: {e}")
            self.session.terminate()
            return False
        except Exception as e:
            print(f"[CLIENT {self.session.client_id}] Error in handshake: {e}")
            self.session.terminate()
            return False
    
    def send_data(self, data: str) -> bool:
        """
        Send CLIENT_DATA message.
        
        Args:
            data: Data to send (comma-separated numbers)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.session.is_terminated():
                print(f"[CLIENT {self.session.client_id}] Session is terminated")
                return False
            
            if self.session.phase != ProtocolPhase.ACTIVE:
                print(f"[CLIENT {self.session.client_id}] Not in ACTIVE phase")
                return False
            
            print(f"[CLIENT {self.session.client_id}] Sending data: {data}")
            
            # Create CLIENT_DATA message
            msg = ProtocolMessage(
                Opcode.CLIENT_DATA,
                self.session.client_id,
                self.session.round_number,
                Direction.CLIENT_TO_SERVER,
                data.encode()
            )
            
            # Encrypt and sign
            msg_bytes = msg.encrypt_and_sign(
                self.session.c2s_enc_key,
                self.session.c2s_mac_key
            )
            
            # Send message
            self.send_message(msg_bytes)
            
            # Evolve C2S keys
            self.session.evolve_c2s_keys(msg.ciphertext, msg.iv)
            
            # Receive SERVER_AGGR_RESPONSE
            response = self.receive_message()
            if not response:
                print(f"[CLIENT {self.session.client_id}] No response to CLIENT_DATA")
                self.session.terminate()
                return False
            
            # Parse and verify response
            response_msg = ProtocolMessage.parse_and_verify(
                response,
                self.session.s2c_enc_key,
                self.session.s2c_mac_key,
                expected_round=self.session.round_number,
                expected_direction=Direction.SERVER_TO_CLIENT
            )
            
            # Check for error opcodes
            if response_msg.opcode == Opcode.KEY_DESYNC_ERROR:
                print(f"[CLIENT {self.session.client_id}] KEY_DESYNC_ERROR received")
                self.session.terminate()
                return False
            elif response_msg.opcode == Opcode.TERMINATE:
                print(f"[CLIENT {self.session.client_id}] TERMINATE received: {response_msg.plaintext.decode()}")
                self.session.terminate()
                return False
            elif response_msg.opcode != Opcode.SERVER_AGGR_RESPONSE:
                print(f"[CLIENT {self.session.client_id}] Unexpected opcode: {response_msg.opcode}")
                self.session.terminate()
                return False
            
            print(f"[CLIENT {self.session.client_id}] Received: {response_msg.plaintext.decode()}")
            
            # Evolve S2C keys
            self.session.evolve_s2c_keys(response_msg.plaintext, b"OK")
            
            # Advance round
            self.session.advance_round()
            
            print(f"[CLIENT {self.session.client_id}] Round complete, advancing to round {self.session.round_number}")
            
            return True
            
        except ValueError as e:
            print(f"[CLIENT {self.session.client_id}] Data exchange failed: {e}")
            self.session.terminate()
            return False
        except Exception as e:
            print(f"[CLIENT {self.session.client_id}] Error sending data: {e}")
            self.session.terminate()
            return False
    
    def send_message(self, msg_bytes: bytes):
        """
        Send a message to the server.
        
        Args:
            msg_bytes: Message bytes to send
        """
        # Send length prefix
        length = struct.pack('!I', len(msg_bytes))
        self.socket.sendall(length + msg_bytes)
    
    def receive_message(self) -> bytes:
        """
        Receive a message from the server.
        
        Returns:
            Message bytes or None
        """
        # Receive length prefix
        length_data = self.recv_exact(4)
        if not length_data:
            return None
        
        msg_length = struct.unpack('!I', length_data)[0]
        
        # Receive message
        return self.recv_exact(msg_length)
    
    def recv_exact(self, num_bytes: int) -> bytes:
        """
        Receive exact number of bytes from socket.
        
        Args:
            num_bytes: Number of bytes to receive
            
        Returns:
            Received bytes or None
        """
        data = b''
        while len(data) < num_bytes:
            chunk = self.socket.recv(num_bytes - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def disconnect(self):
        """Disconnect from server"""
        if self.socket:
            self.socket.close()
            self.connected = False
            print(f"[CLIENT {self.session.client_id}] Disconnected from server")
    
    def is_active(self) -> bool:
        """Check if session is active"""
        return self.connected and not self.session.is_terminated()


def main():
    """Main entry point for testing"""
    import sys
    
    # Get client ID from command line or use default
    client_id = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    
    # Use pre-shared master key (same as server)
    master_key = f'client{client_id}_master_k'.encode()[:16].ljust(16, b'\x00')
    
    client = SecureClient(client_id, master_key)
    
    try:
        # Connect to server
        if not client.connect():
            return
        
        # Send CLIENT_HELLO
        if not client.send_hello():
            return
        
        # Send some data
        for i in range(3):
            data = f"{10.5 + i}, {20.3 + i}, {30.1 + i}"
            if not client.send_data(data):
                break
            time.sleep(1)
        
        print(f"[CLIENT {client_id}] Communication complete")
        
    except KeyboardInterrupt:
        print(f"\n[CLIENT {client_id}] Interrupted by user")
    except Exception as e:
        print(f"[CLIENT {client_id}] Error: {e}")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
