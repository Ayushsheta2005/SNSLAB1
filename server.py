"""
Server Implementation for Secure Multi-Client Communication
Handles multiple clients with stateful symmetric key protocol.
"""

import socket
import struct
import threading
import time
from typing import Dict, List
from protocol_fsm import (
    SessionState, ProtocolMessage, ProtocolFSM,
    Opcode, Direction, ProtocolPhase
)
from crypto_utils import CryptoUtils



class SecureServer:
    """Server for secure multi-client communication"""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 9999):
        """
        Initialize the secure server.
        
        Args:
            host: Server host address
            port: Server port number
        """
        self.host = host
        self.port = port
        self.socket = None
        self.sessions: Dict[int, SessionState] = {}
        # Track data by round number: round_data[round_num][client_id] = [values]
        self.round_data: Dict[int, Dict[int, List[float]]] = {}
        # Track active clients (connected and not terminated)
        self.active_clients: set = set()
        self.lock = threading.Lock()
        self.running = False
        
        # Pre-configured master keys for clients (in production, load from secure storage)
        self.master_keys = {
            1: b'client1_master_k',  # 16 bytes
            2: b'client2_master_k',
            3: b'client3_master_k',
            4: b'client4_master_k',
            5: b'client5_master_k',
        }
    
    def start(self):
        """Start the server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self.running = True
        
        print(f"[SERVER] Listening on {self.host}:{self.port}")
        
        while self.running:
            try:
                client_sock, client_addr = self.socket.accept()
                print(f"[SERVER] New connection from {client_addr}")
                
                # Handle client in a new thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, client_addr),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.running:
                    print(f"[SERVER] Error accepting connection: {e}")
    
    def handle_client(self, client_sock: socket.socket, client_addr):
        """
        Handle communication with a single client.
        
        Args:
            client_sock: Client socket
            client_addr: Client address
        """
        session = None
        client_id = None
        
        try:
            while self.running:
                # Receive message length first (4 bytes)
                length_data = self.recv_exact(client_sock, 4)
                if not length_data:
                    break
                
                msg_length = struct.unpack('!I', length_data)[0]
                
                # Receive the actual message
                msg_data = self.recv_exact(client_sock, msg_length)
                if not msg_data:
                    break
                
                # Process the message
                response = self.process_message(msg_data, session)
                
                if response:
                    # Send response
                    response_length = struct.pack('!I', len(response))
                    client_sock.sendall(response_length + response)
                
                # Update session reference and extract client_id
                if response and not session:
                    # After first message, extract client_id from message
                    if len(msg_data) >= 2:
                        client_id = msg_data[1]
                        session = self.sessions.get(client_id)
                
                # Check if session terminated
                if session and session.is_terminated():
                    print(f"[SERVER] Session terminated for client {session.client_id}")
                    client_id = session.client_id
                    break
                    
        except Exception as e:
            print(f"[SERVER] Error handling client {client_addr}: {e}")
        finally:
            # Remove client from all aggregations when disconnected
            if client_id:
                self.remove_client_from_aggregations(client_id)
            client_sock.close()
            print(f"[SERVER] Connection closed for {client_addr}")
    
    def process_message(self, msg_data: bytes, session: SessionState = None) -> bytes:
        """
        Process an incoming message.
        
        Args:
            msg_data: Raw message data
            session: Current session state (None for first message)
            
        Returns:
            Response message bytes or None
        """
        try:
            # Parse header to get client ID and opcode
            if len(msg_data) < 7:
                print("[SERVER] Message too short")
                return None
            
            opcode, client_id, round_num, direction = struct.unpack('!B B I B', msg_data[:7])
            
            # Handle CLIENT_HELLO (session initialization)
            if opcode == Opcode.CLIENT_HELLO:
                return self.handle_client_hello(client_id, msg_data)
            
            # For other opcodes, we need an existing session
            with self.lock:
                session = self.sessions.get(client_id)
            
            if not session:
                print(f"[SERVER] No session found for client {client_id}")
                return None
            
            if session.is_terminated():
                print(f"[SERVER] Session already terminated for client {client_id}")
                return None
            
            # Route to appropriate handler
            if opcode == Opcode.CLIENT_DATA:
                return self.handle_client_data(session, msg_data)
            else:
                print(f"[SERVER] Unexpected opcode: {opcode}")
                return self.send_terminate(session, "Invalid opcode")
                
        except Exception as e:
            print(f"[SERVER] Error processing message: {e}")
            if session:
                session.terminate()
            return None
    
    def handle_client_hello(self, client_id: int, msg_data: bytes) -> bytes:
        """
        Handle CLIENT_HELLO message.
        
        Args:
            client_id: Client identifier
            msg_data: Raw message data
            
        Returns:
            SERVER_CHALLENGE response
        """
        try:
            print(f"[SERVER] Processing CLIENT_HELLO from client {client_id}")
            
            # Check if client is authorized
            if client_id not in self.master_keys:
                print(f"[SERVER] Unauthorized client {client_id}")
                return None
            
            # Create new session
            with self.lock:
                session = SessionState(client_id, self.master_keys[client_id])
                self.sessions[client_id] = session
                self.active_clients.add(client_id)
                print(f"[SERVER] Client {client_id} marked as active")
            
            # Parse and verify CLIENT_HELLO
            msg = ProtocolMessage.parse_and_verify(
                msg_data,
                session.c2s_enc_key,
                session.c2s_mac_key,
                expected_round=0,
                expected_direction=Direction.CLIENT_TO_SERVER
            )
            
            # Validate FSM
            if not ProtocolFSM.validate_opcode(session.phase, msg.opcode):
                print(f"[SERVER] Invalid opcode for phase {session.phase}")
                session.terminate()
                return None
            
            print(f"[SERVER] CLIENT_HELLO payload: {msg.plaintext.decode()}")
            
            # Evolve C2S keys
            session.evolve_c2s_keys(msg.ciphertext, msg.iv)
            
            # Send SERVER_CHALLENGE
            challenge_payload = b"ServerChallenge-" + str(time.time()).encode()
            response_msg = ProtocolMessage(
                Opcode.SERVER_CHALLENGE,
                client_id,
                session.round_number,
                Direction.SERVER_TO_CLIENT,
                challenge_payload
            )
            
            response_bytes = response_msg.encrypt_and_sign(
                session.s2c_enc_key,
                session.s2c_mac_key
            )
            
            # Evolve S2C keys
            session.evolve_s2c_keys(challenge_payload, b"OK")
            
            # Advance round and update phase
            session.phase = ProtocolFSM.get_next_phase(session.phase, Opcode.SERVER_CHALLENGE)
            session.advance_round()
            
            print(f"[SERVER] Sent SERVER_CHALLENGE to client {client_id}, advancing to round {session.round_number}")
            
            return response_bytes
            
        except ValueError as e:
            print(f"[SERVER] Verification failed for CLIENT_HELLO: {e}")
            if client_id in self.sessions:
                self.sessions[client_id].terminate()
            return None
    
    def handle_client_data(self, session: SessionState, msg_data: bytes) -> bytes:
        """
        Handle CLIENT_DATA message.
        
        Args:
            session: Session state
            msg_data: Raw message data
            
        Returns:
            SERVER_AGGR_RESPONSE message
        """
        try:
            print(f"[SERVER] Processing CLIENT_DATA from client {session.client_id}")
            
            # Parse and verify message
            msg = ProtocolMessage.parse_and_verify(
                msg_data,
                session.c2s_enc_key,
                session.c2s_mac_key,
                expected_round=session.round_number,
                expected_direction=Direction.CLIENT_TO_SERVER
            )
            
            # Validate FSM
            if not ProtocolFSM.validate_opcode(session.phase, msg.opcode):
                print(f"[SERVER] Invalid opcode for phase {session.phase}")
                return self.send_terminate(session, "Invalid protocol state")
            
            # Parse client data (expecting comma-separated numbers)
            data_str = msg.plaintext.decode()
            print(f"[SERVER] Received data from client {session.client_id}: {data_str}")
            
            numbers = [float(x.strip()) for x in data_str.split(',')]
            
            # Get current round number for this client
            current_round = session.round_number
            
            # Store data indexed by round number
            with self.lock:
                # Initialize round dictionary if it doesn't exist
                if current_round not in self.round_data:
                    self.round_data[current_round] = {}
                
                # Store this client's data for this specific round
                self.round_data[current_round][session.client_id] = numbers
                
                print(f"[SERVER] Client {session.client_id} completed round {current_round} with data: {numbers}")
            
            # Evolve C2S keys
            session.evolve_c2s_keys(msg.ciphertext, msg.iv)
            
            # Compute aggregation for this specific round number
            aggregated_result = self.compute_aggregation(current_round)
            
            # Send response
            response_payload = f"Aggregated: {aggregated_result:.2f}".encode()
            response_msg = ProtocolMessage(
                Opcode.SERVER_AGGR_RESPONSE,
                session.client_id,
                session.round_number,
                Direction.SERVER_TO_CLIENT,
                response_payload
            )
            
            response_bytes = response_msg.encrypt_and_sign(
                session.s2c_enc_key,
                session.s2c_mac_key
            )
            
            # Evolve S2C keys
            session.evolve_s2c_keys(response_payload, b"OK")
            
            # Advance round
            session.advance_round()
            
            print(f"[SERVER] Sent aggregation result to client {session.client_id}, advancing to round {session.round_number}")
            
            return response_bytes
            
        except ValueError as e:
            print(f"[SERVER] Verification/Processing failed: {e}")
            return self.send_key_desync_error(session)
        except Exception as e:
            print(f"[SERVER] Error handling CLIENT_DATA: {e}")
            return self.send_terminate(session, f"Error: {e}")
    
    def compute_aggregation(self, round_num: int) -> float:
        """
        Compute aggregation for a SPECIFIC round number.
        Aggregates data from ALL ACTIVE clients who have successfully completed that round.
        Excludes disconnected or terminated clients.
        
        Each round's aggregation is independent:
        - Round 1 aggregate = average of all data from all ACTIVE clients who completed round 1
        - Round 2 aggregate = average of all data from all ACTIVE clients who completed round 2
        - etc.
        
        Args:
            round_num: The specific round number to aggregate
            
        Returns:
            Average of all data points from all ACTIVE clients in that round
        """
        with self.lock:
            # Check if this round has any data
            if round_num not in self.round_data:
                print(f"[SERVER] No data for round {round_num} yet")
                return 0.0
            
            round_clients = self.round_data[round_num]
            if not round_clients:
                return 0.0
            
            # Collect data points ONLY from ACTIVE clients who completed this round
            all_values = []
            active_contributors = 0
            for client_id, numbers in round_clients.items():
                # Only include data from clients that are still active
                if client_id in self.active_clients and numbers:
                    all_values.extend(numbers)
                    active_contributors += 1
                    print(f"[SERVER] Round {round_num} - Client {client_id} contributed: {numbers}")
                elif client_id not in self.active_clients:
                    print(f"[SERVER] Round {round_num} - Client {client_id} excluded (disconnected/terminated)")
            
            if not all_values:
                return 0.0
            
            # Calculate average across all values from active clients
            result = sum(all_values) / len(all_values)
            print(f"[SERVER] Round {round_num} aggregate = {result:.2f} (from {len(all_values)} values across {active_contributors} active clients)")
            
            return result
    
    def remove_client_from_aggregations(self, client_id: int):
        """
        Remove a client from active set when they disconnect or session terminates.
        This excludes their data from future aggregation calculations.
        Historical data remains in round_data but is excluded via active_clients check.
        
        Args:
            client_id: Client identifier to remove
        """
        with self.lock:
            if client_id in self.active_clients:
                self.active_clients.remove(client_id)
                print(f"[SERVER] Client {client_id} removed from active clients (excluded from aggregations)")
            
            # Optionally remove session
            if client_id in self.sessions:
                del self.sessions[client_id]
                print(f"[SERVER] Session for client {client_id} removed")
    
    def send_key_desync_error(self, session: SessionState) -> bytes:
        """
        Send KEY_DESYNC_ERROR message.
        
        Args:
            session: Session state
            
        Returns:
            Error message bytes
        """
        try:
            error_msg = ProtocolMessage(
                Opcode.KEY_DESYNC_ERROR,
                session.client_id,
                session.round_number,
                Direction.SERVER_TO_CLIENT,
                b"Key desynchronization detected"
            )
            
            response = error_msg.encrypt_and_sign(
                session.s2c_enc_key,
                session.s2c_mac_key
            )
            
            session.terminate()
            return response
        except:
            session.terminate()
            return None
    
    def send_terminate(self, session: SessionState, reason: str) -> bytes:
        """
        Send TERMINATE message.
        
        Args:
            session: Session state
            reason: Termination reason
            
        Returns:
            Terminate message bytes
        """
        try:
            term_msg = ProtocolMessage(
                Opcode.TERMINATE,
                session.client_id,
                session.round_number,
                Direction.SERVER_TO_CLIENT,
                reason.encode()
            )
            
            response = term_msg.encrypt_and_sign(
                session.s2c_enc_key,
                session.s2c_mac_key
            )
            
            session.terminate()
            return response
        except:
            session.terminate()
            return None
    
    @staticmethod
    def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
        """
        Receive exact number of bytes from socket.
        
        Args:
            sock: Socket to receive from
            num_bytes: Number of bytes to receive
            
        Returns:
            Received bytes
        """
        data = b''
        while len(data) < num_bytes:
            chunk = sock.recv(num_bytes - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.socket:
            self.socket.close()


def main():
    """Main entry point"""
    server = SecureServer()
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
        server.stop()


if __name__ == "__main__":
    main()
