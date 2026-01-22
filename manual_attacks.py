#!/usr/bin/env python3
"""
Manual Attack Demonstrations - Interactive Tool
Allows security researchers to manually craft and send malicious messages
"""

import socket
import struct
import sys
from protocol_fsm import ProtocolMessage, Opcode, Direction
from client import SecureClient
from crypto_utils import CryptoUtils


# Error code names for display
ERROR_CODE_NAMES = {
    Opcode.ERROR_INVALID_HMAC: "INVALID_HMAC (Message Tampering)",
    Opcode.ERROR_REPLAY_DETECTED: "REPLAY_ATTACK (Old Round Number)",
    Opcode.ERROR_REORDERING_DETECTED: "MESSAGE_REORDERING (Wrong Round)",
    Opcode.ERROR_KEY_DESYNC: "KEY_DESYNCHRONIZATION (Keys Out of Sync)",
    Opcode.ERROR_INVALID_DIRECTION: "INVALID_DIRECTION (Reflection Attack)",
    Opcode.ERROR_INVALID_CLIENT: "UNAUTHORIZED_CLIENT",
    Opcode.KEY_DESYNC_ERROR: "KEY_DESYNC_ERROR (Legacy)",
    Opcode.TERMINATE: "TERMINATE",
}


class ManualAttackTool:
    """Interactive tool for manual attack testing"""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 9999):
        self.host = host
        self.port = port
        self.client = None
        
    def print_menu(self):
        """Display main menu"""
        print("\n" + "="*70)
        print("  MANUAL ATTACK TOOL - Interactive Security Testing")
        print("="*70)
        print("\nAvailable Attacks:")
        print("  1. Replay Attack - Resend captured message")
        print("  2. Message Modification - Tamper with ciphertext")
        print("  3. Key Desynchronization - Corrupt encryption keys")
        print("  4. Message Reordering - Send messages with wrong round")
        print("  5. Reflection Attack - Send server's message back to server")
        print("  6. Unauthorized Client - Connect with invalid credentials")
        print("  7. Raw Message Injection - Craft custom malicious message")
        print("  8. MITM Simulation - Intercept and modify in transit")
        print("  9. Exit")
        print()
        
    def setup_legitimate_client(self, client_id: int = 1):
        """Setup a legitimate client connection"""
        master_key = f'client{client_id}_master_k'.encode()[:16].ljust(16, b'\x00')
        self.client = SecureClient(client_id, master_key, self.host, self.port)
        
        if not self.client.connect():
            print("[ERROR] Failed to connect to server")
            return False
            
        if not self.client.send_hello():
            print("[ERROR] Handshake failed")
            return False
            
        print(f"[SUCCESS] Established session as client {client_id}")
        return True
        
    def manual_replay_attack(self):
        """Manually capture and replay messages"""
        print("\n" + "-"*70)
        print("MANUAL REPLAY ATTACK")
        print("-"*70)
        
        client_id = int(input("Enter client ID to impersonate (1-5): "))
        
        if not self.setup_legitimate_client(client_id):
            return
            
        print("\n[STEP 1] Sending legitimate message to capture...")
        data = input("Enter data to send (e.g., 10.5, 20.3, 30.1): ")
        
        # Capture the message
        original_send = self.client.send_message
        captured = None
        
        def capture(msg):
            nonlocal captured
            captured = msg
            original_send(msg)
            
        self.client.send_message = capture
        self.client.send_data(data)
        
        print(f"\n[CAPTURED] Message of {len(captured)} bytes")
        print(f"[INFO] Current round: {self.client.session.round_number}")
        
        print("\n[STEP 2] Replaying captured message...")
        choice = input("Replay now? (y/n): ")
        
        if choice.lower() == 'y':
            try:
                self.client.socket.sendall(struct.pack('!I', len(captured)) + captured)
                self.client.socket.settimeout(3)
                response = self.client.receive_message()
                
                if response:
                    opcode = response[0]
                    error_name = ERROR_CODE_NAMES.get(Opcode(opcode), f"Unknown ({opcode})")
                    if opcode in [Opcode.KEY_DESYNC_ERROR.value, Opcode.ERROR_REPLAY_DETECTED.value]:
                        print(f"[RESULT] ✓ Attack BLOCKED - Server detected attack")
                        print(f"[RESULT]    Error Code: {error_name}")
                    elif opcode == Opcode.TERMINATE.value:
                        print(f"[RESULT] ✓ Attack BLOCKED - Server terminated session")
                        print(f"[RESULT]    Error Code: {error_name}")
                    else:
                        print(f"[RESULT] ⚠️ Unexpected response")
                        print(f"[RESULT]    Opcode: {error_name}")
                else:
                    print("[RESULT] ✓ Attack BLOCKED - No response")
            except socket.timeout:
                print("[RESULT] ✓ Attack BLOCKED - Connection closed")
            except Exception as e:
                print(f"[RESULT] ✓ Attack BLOCKED - {e}")
                
        self.client.disconnect()
        
    def manual_modification_attack(self):
        """Manually modify message bytes"""
        print("\n" + "-"*70)
        print("MANUAL MESSAGE MODIFICATION ATTACK")
        print("-"*70)
        
        client_id = int(input("Enter client ID (1-5): "))
        
        if not self.setup_legitimate_client(client_id):
            return
            
        data = input("Enter data to send: ")
        
        print("\n[ATTACK] You can now modify the encrypted message")
        position = int(input("Enter byte position to modify (e.g., 50): "))
        new_value = int(input("Enter new byte value (0-255): "))
        
        # Intercept and modify
        original_send = self.client.send_message
        
        def modify_and_send(msg):
            modified = bytearray(msg)
            if position < len(modified):
                old_val = modified[position]
                modified[position] = new_value
                print(f"\n[MODIFIED] Byte at {position}: {old_val} -> {new_value}")
                original_send(bytes(modified))
            else:
                print(f"[ERROR] Position {position} out of range (max: {len(modified)-1})")
                original_send(msg)
                
        self.client.send_message = modify_and_send
        success = self.client.send_data(data)
        
        if not success:
            print("[RESULT] ✓ Attack BLOCKED - Server detected modification")
        else:
            print("[RESULT] ⚠️ Attack SUCCEEDED - This should not happen!")
            
        self.client.disconnect()
        
    def manual_key_desync_attack(self):
        """Manually corrupt encryption keys"""
        print("\n" + "-"*70)
        print("MANUAL KEY DESYNCHRONIZATION ATTACK")
        print("-"*70)
        
        client_id = int(input("Enter client ID (1-5): "))
        
        if not self.setup_legitimate_client(client_id):
            return
            
        print("\n[STEP 1] Sending first message normally...")
        self.client.send_data("10.0, 20.0, 30.0")
        
        print(f"\n[INFO] Current encryption key (hex): {self.client.session.c2s_enc_key.hex()}")
        
        print("\n[ATTACK] Choose key corruption method:")
        print("  1. Reverse key bytes")
        print("  2. XOR with 0xFF")
        print("  3. Set all bytes to zero")
        print("  4. Custom corruption")
        
        choice = input("Select (1-4): ")
        
        original_key = self.client.session.c2s_enc_key
        
        if choice == '1':
            self.client.session.c2s_enc_key = original_key[::-1]
            print("[CORRUPTED] Key reversed")
        elif choice == '2':
            self.client.session.c2s_enc_key = bytes([b ^ 0xFF for b in original_key])
            print("[CORRUPTED] Key XORed with 0xFF")
        elif choice == '3':
            self.client.session.c2s_enc_key = b'\x00' * 16
            print("[CORRUPTED] Key set to zeros")
        else:
            print("[INFO] Flipping first byte")
            corrupted = bytearray(original_key)
            corrupted[0] ^= 0xFF
            self.client.session.c2s_enc_key = bytes(corrupted)
            
        print(f"[NEW KEY] {self.client.session.c2s_enc_key.hex()}")
        
        print("\n[STEP 2] Attempting to send with corrupted key...")
        success = self.client.send_data("30.0, 40.0, 50.0")
        
        if not success:
            print("[RESULT] ✓ Attack BLOCKED - Server detected key desync")
        else:
            print("[RESULT] ⚠️ Attack SUCCEEDED - This should not happen!")
            
        self.client.disconnect()
        
    def manual_reordering_attack(self):
        """Manually manipulate round numbers"""
        print("\n" + "-"*70)
        print("MANUAL MESSAGE REORDERING ATTACK")
        print("-"*70)
        
        client_id = int(input("Enter client ID (1-5): "))
        
        if not self.setup_legitimate_client(client_id):
            return
            
        print("\n[STEP 1] Sending first message...")
        self.client.send_data("10.0, 20.0")
        
        print(f"\n[INFO] Current round: {self.client.session.round_number}")
        
        fake_round = int(input("\nEnter fake round number to inject: "))
        
        print(f"\n[ATTACK] Attempting to send message with round {fake_round}")
        
        # Temporarily change round number
        real_round = self.client.session.round_number
        self.client.session.round_number = fake_round
        
        success = self.client.send_data("30.0, 40.0")
        
        if not success:
            print("[RESULT] ✓ Attack BLOCKED - Server rejected wrong round")
        else:
            print("[RESULT] ⚠️ Attack SUCCEEDED - This should not happen!")
            
        self.client.disconnect()
        
    def manual_reflection_attack(self):
        """Manually reflect server messages"""
        print("\n" + "-"*70)
        print("MANUAL REFLECTION ATTACK")
        print("-"*70)
        
        client_id = int(input("Enter client ID (1-5): "))
        
        if not self.setup_legitimate_client(client_id):
            return
            
        print("\n[STEP 1] Sending data to capture server response...")
        
        # Capture server's response
        original_recv = self.client.receive_message
        captured_response = None
        
        def capture_recv():
            nonlocal captured_response
            captured_response = original_recv()
            return captured_response
            
        self.client.receive_message = capture_recv
        self.client.send_data("15.0, 25.0")
        
        print(f"\n[CAPTURED] Server response: {len(captured_response)} bytes")
        
        # Show message structure
        if len(captured_response) >= 7:
            opcode, cid, round_num, direction = struct.unpack('!B B I B', captured_response[:7])
            print(f"[INFO] Opcode: {opcode}, Round: {round_num}, Direction: {direction}")
            
        print("\n[STEP 2] Reflecting server's message back...")
        choice = input("Send reflected message? (y/n): ")
        
        if choice.lower() == 'y':
            try:
                self.client.socket.sendall(struct.pack('!I', len(captured_response)) + captured_response)
                self.client.socket.settimeout(3)
                response = self.client.receive_message()
                
                if response and len(response) >= 1:
                    opcode = response[0]
                    error_name = ERROR_CODE_NAMES.get(Opcode(opcode), f"Unknown ({opcode})")
                    if opcode in [Opcode.KEY_DESYNC_ERROR.value, Opcode.TERMINATE.value,
                                 Opcode.ERROR_INVALID_DIRECTION.value]:
                        print(f"[RESULT] ✓ Attack BLOCKED - Server rejected reflection")
                        print(f"[RESULT]    Error Code: {error_name}")
                    else:
                        print(f"[RESULT] ⚠️ Unexpected response")
                        print(f"[RESULT]    Opcode: {error_name}")
                else:
                    print("[RESULT] ✓ Attack BLOCKED - No response")
            except socket.timeout:
                print("[RESULT] ✓ Attack BLOCKED - Timeout")
            except Exception as e:
                print(f"[RESULT] ✓ Attack BLOCKED - {e}")
                
        self.client.disconnect()
        
    def manual_unauthorized_client_attack(self):
        """Test with unauthorized credentials"""
        print("\n" + "-"*70)
        print("MANUAL UNAUTHORIZED CLIENT ATTACK")
        print("-"*70)
        
        print("\n[INFO] Authorized client IDs are 1-5")
        client_id = int(input("Enter unauthorized client ID (e.g., 99): "))
        
        print("\nEnter fake master key (16 bytes):")
        key_input = input("(press Enter for default 'fake_master_key!'): ")
        
        if not key_input:
            fake_key = b'fake_master_key!'
        else:
            fake_key = key_input.encode()[:16].ljust(16, b'\x00')
            
        print(f"\n[ATTACK] Attempting connection as client {client_id}")
        print(f"[KEY] {fake_key.hex()}")
        
        client = SecureClient(client_id, fake_key, self.host, self.port)
        
        if not client.connect():
            print("[RESULT] ✓ Attack BLOCKED - Connection refused")
            return
            
        success = client.send_hello()
        
        if not success:
            print("[RESULT] ✓ Attack BLOCKED - Handshake failed (HMAC verification)")
        else:
            print("[RESULT] ⚠️ Attack SUCCEEDED - Unauthorized client accepted!")
            
        client.disconnect()
        
    def manual_raw_injection(self):
        """Craft and send completely custom message"""
        print("\n" + "-"*70)
        print("MANUAL RAW MESSAGE INJECTION")
        print("-"*70)
        
        print("\n[WARNING] This creates a completely custom message")
        print("[INFO] Message structure: Opcode(1) | ClientID(1) | Round(4) | Direction(1) | IV(16) | Ciphertext | HMAC(32)")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            print(f"\n[CONNECTED] to {self.host}:{self.port}")
            
            opcode = int(input("Enter opcode (10=CLIENT_HELLO, 30=CLIENT_DATA): "))
            client_id = int(input("Enter client ID: "))
            round_num = int(input("Enter round number: "))
            direction = int(input("Enter direction (1=C2S, 2=S2C): "))
            
            # Create header
            header = struct.pack('!B B I B', opcode, client_id, round_num, direction)
            
            # Generate random IV
            iv = CryptoUtils.generate_random_iv()
            
            # Create fake ciphertext
            ciphertext = b'\x00' * 32  # Fake encrypted data
            
            # Create fake HMAC
            fake_hmac = b'\x00' * 32
            
            message = header + iv + ciphertext + fake_hmac
            
            print(f"\n[CRAFTED] Message: {len(message)} bytes")
            print(f"[SENDING] Raw malicious message...")
            
            sock.sendall(struct.pack('!I', len(message)) + message)
            sock.settimeout(3)
            
            try:
                length_data = sock.recv(4)
                if length_data:
                    msg_len = struct.unpack('!I', length_data)[0]
                    response = sock.recv(msg_len)
                    print(f"[RESPONSE] Received {len(response)} bytes")
                    if len(response) >= 1:
                        resp_opcode = response[0]
                        print(f"[RESULT] Server responded with opcode: {resp_opcode}")
                else:
                    print("[RESULT] ✓ Attack BLOCKED - No response")
            except socket.timeout:
                print("[RESULT] ✓ Attack BLOCKED - Timeout")
                
            sock.close()
            
        except Exception as e:
            print(f"[ERROR] {e}")
            
    def manual_mitm_simulation(self):
        """Simulate man-in-the-middle attack"""
        print("\n" + "-"*70)
        print("MANUAL MITM SIMULATION")
        print("-"*70)
        
        print("\n[SCENARIO] Attacker intercepts messages between client and server")
        
        client_id = int(input("Enter legitimate client ID to monitor (1-5): "))
        
        if not self.setup_legitimate_client(client_id):
            return
            
        print("\n[STEP 1] Normal message exchange...")
        data = input("Enter data to send: ")
        
        print("\n[MITM] You are intercepting the message stream")
        print("Choose MITM action:")
        print("  1. Pass through unchanged (baseline)")
        print("  2. Modify one byte")
        print("  3. Drop message (DoS)")
        print("  4. Duplicate message")
        
        choice = input("Select (1-4): ")
        
        original_send = self.client.send_message
        
        if choice == '1':
            print("\n[MITM] Passing through unchanged...")
            success = self.client.send_data(data)
            print(f"[RESULT] Message delivered: {success}")
            
        elif choice == '2':
            def mitm_modify(msg):
                modified = bytearray(msg)
                pos = len(modified) // 2
                modified[pos] ^= 0xFF
                print(f"[MITM] Modified byte at position {pos}")
                original_send(bytes(modified))
                
            self.client.send_message = mitm_modify
            success = self.client.send_data(data)
            print(f"[RESULT] {'✓ Blocked' if not success else '⚠️ Accepted'}")
            
        elif choice == '3':
            def mitm_drop(msg):
                print("[MITM] Dropping message (DoS)")
                # Don't send anything
                
            self.client.send_message = mitm_drop
            success = self.client.send_data(data)
            print("[RESULT] Message dropped - connection will timeout")
            
        elif choice == '4':
            def mitm_duplicate(msg):
                print("[MITM] Sending message twice...")
                original_send(msg)
                original_send(msg)  # Send duplicate
                
            self.client.send_message = mitm_duplicate
            success = self.client.send_data(data)
            print("[RESULT] Second message should be rejected by round number check")
            
        self.client.disconnect()
        
    def run(self):
        """Main interactive loop"""
        while True:
            self.print_menu()
            
            try:
                choice = input("Select attack (1-9): ").strip()
                
                if choice == '1':
                    self.manual_replay_attack()
                elif choice == '2':
                    self.manual_modification_attack()
                elif choice == '3':
                    self.manual_key_desync_attack()
                elif choice == '4':
                    self.manual_reordering_attack()
                elif choice == '5':
                    self.manual_reflection_attack()
                elif choice == '6':
                    self.manual_unauthorized_client_attack()
                elif choice == '7':
                    self.manual_raw_injection()
                elif choice == '8':
                    self.manual_mitm_simulation()
                elif choice == '9':
                    print("\nExiting manual attack tool...")
                    break
                else:
                    print("[ERROR] Invalid choice")
                    
            except KeyboardInterrupt:
                print("\n\n[INTERRUPTED] Exiting...")
                break
            except Exception as e:
                print(f"\n[ERROR] {e}")
                import traceback
                traceback.print_exc()
                

def main():
    print("\n" + "="*70)
    print("  MANUAL ATTACK TOOL")
    print("  Interactive Security Testing for Protocol Vulnerabilities")
    print("="*70)
    print("\n⚠️  WARNING: Use only for authorized security testing")
    print("⚠️  Ensure the server is running on 127.0.0.1:9999\n")
    
    input("Press Enter to start...")
    
    tool = ManualAttackTool()
    tool.run()


if __name__ == "__main__":
    main()
