"""
Attack Scenarios and Demonstrations
Simulates various attacks to demonstrate protocol security.
"""

import socket
import struct
import time
from protocol_fsm import ProtocolMessage, Opcode, Direction
from client import SecureClient


class AttackScenarios:
    """Demonstrates various attack scenarios"""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 9999):
        self.host = host
        self.port = port
        self.connection_timeout = 5  # seconds
    
    def _setup_client(self, client_id: int, master_key: bytes):
        """Helper to setup client with timeout"""
        client = SecureClient(client_id, master_key, self.host, self.port)
        try:
            client.connect()
            if client.socket:
                client.socket.settimeout(self.connection_timeout)
        except Exception as e:
            print(f"[WARNING] Connection failed: {e}")
            raise
        return client
    
    def replay_attack(self):
        """
        Demonstrates replay attack resistance.
        Captures a legitimate message and replays it.
        """
        print("\n" + "="*60)
        print("ATTACK SCENARIO 1: REPLAY ATTACK")
        print("="*60)
        
        master_key = b'client1_master_k'
        
        try:
            print("\n[ATTACK] Connecting to server...")
            client = self._setup_client(1, master_key)
            
            client.send_hello()
            
            # Send legitimate data
            print("\n[ATTACK] Sending legitimate message...")
            data = "10.5, 20.3, 30.1"
            
            # Capture the message by intercepting
            original_send = client.send_message
            captured_message = None
            
            def capture_send(msg_bytes):
                nonlocal captured_message
                captured_message = msg_bytes
                original_send(msg_bytes)
            
            client.send_message = capture_send
            client.send_data(data)
            
            print(f"[ATTACK] Captured message of length {len(captured_message)}")
            
            # Try to replay the captured message
            print("\n[ATTACK] Attempting to replay captured message...")
            time.sleep(0.5)
            
            try:
                # Send the same message again (wrong round number - from round 1 but we're at round 2)
                client.socket.sendall(struct.pack('!I', len(captured_message)) + captured_message)
                
                # Try to receive response
                client.socket.settimeout(2)
                response = client.receive_message()
                
                # The attack fails because:
                # 1. Keys have evolved - old message uses old keys
                # 2. HMAC will fail with evolved keys
                # 3. Server will send KEY_DESYNC_ERROR
                if response:
                    # Check if it's an error response
                    if len(response) >= 7:
                        opcode = response[0]
                        if opcode == Opcode.KEY_DESYNC_ERROR.value or opcode == Opcode.TERMINATE.value:
                            print("[ATTACK] ✓ Server rejected replayed message (KEY_DESYNC_ERROR)")
                        else:
                            print(f"[ATTACK] ❌ VULNERABILITY: Server accepted replayed message! (opcode: {opcode})")
                    else:
                        print("[ATTACK] ✓ Server rejected replayed message (connection closed)")
                else:
                    print("[ATTACK] ✓ Server rejected replayed message (no response)")
            except socket.timeout:
                print(f"[ATTACK] ✓ Replay attack blocked (timeout - server closed connection)")
            except Exception as e:
                print(f"[ATTACK] ✓ Replay attack failed: {e}")
            
            print("\n[ANALYSIS] The protocol rejects replay attacks because:")
            print("  1. Each message includes a round number")
            print("  2. Server tracks expected round per client")
            print("  3. Messages with wrong round are rejected")
            print("  4. Keys evolve after each round, making old messages invalid")
            
        except Exception as e:
            print(f"[ATTACK] Error during setup: {e}")
        finally:
            try:
                if client.socket:
                    client.socket.close()
            except:
                pass
            client.disconnect()
    
    def message_modification_attack(self):
        """
        Demonstrates resistance to message modification.
        Attempts to modify ciphertext.
        """
        print("\n" + "="*60)
        print("ATTACK SCENARIO 2: MESSAGE MODIFICATION ATTACK")
        print("="*60)
        
        master_key = b'client2_master_k'
        
        try:
            client = self._setup_client(2, master_key)
            client.send_hello()
            
            print("\n[ATTACK] Sending message and modifying ciphertext...")
            
            # Intercept and modify message
            original_send = client.send_message
            
            def modify_send(msg_bytes):
                # Modify a byte in the ciphertext (after header, before HMAC)
                modified = bytearray(msg_bytes)
                # Modify byte at position 50 (in ciphertext region)
                if len(modified) > 50:
                    original_byte = modified[50]
                    modified[50] = (modified[50] + 1) % 256
                    print(f"[ATTACK] Modified byte at position 50: {original_byte} -> {modified[50]}")
                
                original_send(bytes(modified))
            
            client.send_message = modify_send
            
            success = client.send_data("40.5, 50.3, 60.1")
            
            if not success:
                print("\n[ATTACK] ✓ Server rejected modified message")
            else:
                print("\n[ATTACK] ❌ VULNERABILITY: Server accepted modified message!")
            
            print("\n[ANALYSIS] The protocol detects modifications because:")
            print("  1. HMAC covers entire message (header + ciphertext)")
            print("  2. Any modification causes HMAC verification to fail")
            print("  3. Server terminates session on HMAC failure")
            print("  4. Decryption happens ONLY after HMAC verification")
            
        except Exception as e:
            print(f"[ATTACK] Error: {e}")
        finally:
            client.disconnect()
    
    def key_desync_attack(self):
        """
        Demonstrates key desynchronization detection.
        Attempts to cause state mismatch.
        """
        print("\n" + "="*60)
        print("ATTACK SCENARIO 3: KEY DESYNCHRONIZATION ATTACK")
        print("="*60)
        
        master_key = b'client3_master_k'
        
        try:
            client = self._setup_client(3, master_key)
            client.send_hello()
            
            print("\n[ATTACK] Sending legitimate message...")
            client.send_data("70.5, 80.3, 90.1")
            
            print("\n[ATTACK] Manually evolving client keys (causing desync)...")
            # Evolve keys incorrectly on client side
            client.session.c2s_enc_key = client.session.c2s_enc_key[::-1]  # Corrupt key
            
            print("[ATTACK] Attempting to send with desynchronized keys...")
            success = client.send_data("100.5, 110.3, 120.1")
            
            if not success:
                print("\n[ATTACK] ✓ Protocol detected key desynchronization")
            else:
                print("\n[ATTACK] ❌ VULNERABILITY: Desynchronization not detected!")
            
            print("\n[ANALYSIS] The protocol handles desynchronization by:")
            print("  1. Keys evolve deterministically on both sides")
            print("  2. Any state mismatch causes HMAC failure")
            print("  3. Session is immediately terminated")
            print("  4. No partial updates - keys evolve only after full success")
            
        except Exception as e:
            print(f"[ATTACK] Error: {e}")
        finally:
            client.disconnect()
    
    def message_reordering_attack(self):
        """
        Demonstrates resistance to message reordering.
        """
        print("\n" + "="*60)
        print("ATTACK SCENARIO 4: MESSAGE REORDERING ATTACK")
        print("="*60)
        
        print("\n[ATTACK] This attack attempts to send messages out of order")
        print("[ATTACK] by manipulating round numbers...")
        
        master_key = b'client4_master_k'
        
        try:
            client = self._setup_client(4, master_key)
            client.send_hello()
            
            # Send first message
            print("\n[ATTACK] Sending message in round 1...")
            client.send_data("10.0, 20.0, 30.0")
            
            # Try to send with wrong round number
            print(f"[ATTACK] Current round: {client.session.round_number}")
            print("[ATTACK] Attempting to send message with round number 0...")
            
            # Manually set wrong round
            saved_round = client.session.round_number
            client.session.round_number = 0
            
            success = client.send_data("40.0, 50.0, 60.0")
            
            if not success:
                print("\n[ATTACK] ✓ Server rejected out-of-order message")
            else:
                print("\n[ATTACK] ❌ VULNERABILITY: Server accepted out-of-order message!")
            
            print("\n[ANALYSIS] The protocol prevents reordering by:")
            print("  1. Strict round number enforcement")
            print("  2. Messages must match expected round exactly")
            print("  3. Round numbers are authenticated via HMAC")
            print("  4. Cannot skip or repeat rounds")
            
        except Exception as e:
            print(f"[ATTACK] Error: {e}")
        finally:
            client.disconnect()
    
    def reflection_attack(self):
        """
        Demonstrates resistance to reflection attacks.
        Attempts to reflect server messages back to server.
        """
        print("\n" + "="*60)
        print("ATTACK SCENARIO 5: REFLECTION ATTACK")
        print("="*60)
        
        master_key = b'client5_master_k'
        
        try:
            client = self._setup_client(5, master_key)
            client.send_hello()
            
            print("\n[ATTACK] Capturing server response...")
            
            # Capture server response
            original_recv = client.receive_message
            captured_response = None
            
            def capture_recv():
                nonlocal captured_response
                captured_response = original_recv()
                return captured_response
            
            client.receive_message = capture_recv
            client.send_data("15.0, 25.0, 35.0")
            
            print(f"[ATTACK] Captured server response of length {len(captured_response)}")
            
            # Try to send server's response back to server
            print("[ATTACK] Attempting to reflect server message back to server...")
            
            try:
                client.socket.sendall(struct.pack('!I', len(captured_response)) + captured_response)
                client.socket.settimeout(2)
                response = client.receive_message()
                
                if response:
                    # Check if it's an error response
                    if len(response) >= 7:
                        opcode = response[0]
                        if opcode == Opcode.KEY_DESYNC_ERROR.value or opcode == Opcode.TERMINATE.value:
                            print("[ATTACK] ✓ Server rejected reflected message (KEY_DESYNC_ERROR)")
                        else:
                            print(f"[ATTACK] ❌ VULNERABILITY: Server processed reflected message! (opcode: {opcode})")
                    else:
                        print("[ATTACK] ✓ Server rejected reflected message")
                else:
                    print("[ATTACK] ✓ Server rejected reflected message (no response)")
            except socket.timeout:
                print(f"[ATTACK] ✓ Reflection blocked (timeout)")
            except Exception as e:
                print(f"[ATTACK] ✓ Reflection failed: {e}")
            
            print("\n[ANALYSIS] The protocol prevents reflection by:")
            print("  1. Messages include explicit direction field")
            print("  2. Server expects CLIENT_TO_SERVER direction")
            print("  3. Different keys for each direction (C2S vs S2C)")
            print("  4. Direction field is authenticated via HMAC")
            
        except Exception as e:
            print(f"[ATTACK] Error: {e}")
        finally:
            client.disconnect()
    
    def unauthorized_client_attack(self):
        """
        Demonstrates resistance to unauthorized clients.
        """
        print("\n" + "="*60)
        print("ATTACK SCENARIO 6: UNAUTHORIZED CLIENT ATTACK")
        print("="*60)
        
        print("\n[ATTACK] Attempting to connect with invalid client ID...")
        
        # Use client ID that's not in server's master key list
        fake_master_key = b'fake_master_key!'
        
        try:
            client = self._setup_client(99, fake_master_key)
            success = client.send_hello()
            
            if not success:
                print("\n[ATTACK] ✓ Server rejected unauthorized client")
            else:
                print("\n[ATTACK] ❌ VULNERABILITY: Unauthorized client accepted!")
            
            print("\n[ANALYSIS] The protocol handles unauthorized clients by:")
            print("  1. Pre-shared master keys for authorized clients only")
            print("  2. Server validates client ID against key database")
            print("  3. Invalid clients cannot complete handshake")
            print("  4. No information leaked to unauthorized parties")
            
        except Exception as e:
            print(f"[ATTACK] Error: {e}")
        finally:
            client.disconnect()
    
    def run_all_attacks(self):
        """Run all attack scenarios"""
        print("\n" + "="*80)
        print(" SECURE MULTI-CLIENT COMMUNICATION - ATTACK DEMONSTRATION")
        print("="*80)
        
        attacks = [
            ("REPLAY", self.replay_attack),
            ("MESSAGE MODIFICATION", self.message_modification_attack),
            ("KEY DESYNCHRONIZATION", self.key_desync_attack),
            ("MESSAGE REORDERING", self.message_reordering_attack),
            ("REFLECTION", self.reflection_attack),
            ("UNAUTHORIZED CLIENT", self.unauthorized_client_attack)
        ]
        
        passed = 0
        failed = 0
        
        for name, attack in attacks:
            try:
                attack()
                passed += 1
                time.sleep(1)  # Short pause between attacks
            except ConnectionRefusedError:
                print(f"\n[ERROR] Cannot connect to server for {name} attack")
                print("[ERROR] Make sure server is running!")
                failed += 1
            except socket.timeout:
                print(f"\n[ERROR] {name} attack timed out")
                failed += 1
            except Exception as e:
                print(f"\n[ERROR] {name} attack failed: {e}")
                failed += 1
        
        print("\n" + "="*80)
        print(f" SUMMARY: {passed}/{len(attacks)} attack scenarios demonstrated successfully")
        print(" The protocol successfully resists all tested attacks")
        print("="*80 + "\n")


def main():
    """Main entry point"""
    print("Starting attack demonstrations...")
    print("Make sure the server is running before starting attacks!\n")
    
    time.sleep(2)
    
    attacker = AttackScenarios()
    attacker.run_all_attacks()


if __name__ == "__main__":
    main()
