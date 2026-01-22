#!/usr/bin/env python3
"""
Test script to verify that clients with terminated sessions are excluded from aggregations.
"""

import time
import threading
import socket
import struct
from client import SecureClient
from server import SecureServer


def run_server():
    """Run server in background"""
    server = SecureServer()
    server.start()


def test_session_termination_aggregation():
    """
    Test scenario:
    1. Client 1 and 2 send round 1 data
    2. Client 3 sends tampered message (causes session termination)
    3. Client 4 sends round 1 data
       -> Should aggregate only from clients 1, 2, 4 (not 3)
    """
    print("="*80)
    print("TEST: Session Termination Excludes from Aggregations")
    print("="*80)
    
    # Start server
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1)
    
    print("\n[TEST] Step 1: Client 1 connects and sends round 1 data")
    client1 = SecureClient(1, b'client1_master_k', '127.0.0.1', 9999)
    client1.connect()
    client1.send_hello()
    client1.send_data("10,20,30")
    print("[TEST] Client 1 round 1 completed")
    time.sleep(0.5)
    
    print("\n[TEST] Step 2: Client 2 connects and sends round 1 data")
    client2 = SecureClient(2, b'client2_master_k', '127.0.0.1', 9999)
    client2.connect()
    client2.send_hello()
    client2.send_data("10,20,30")
    print("[TEST] Client 2 round 1 completed")
    time.sleep(0.5)
    
    print("\n[TEST] Step 3: Client 3 connects and sends TAMPERED message (causes termination)")
    client3 = SecureClient(3, b'client3_master_k', '127.0.0.1', 9999)
    client3.connect()
    client3.send_hello()
    
    # Send tampered message (modify HMAC)
    original_send = client3.send_message
    def tamper_send(msg_bytes):
        modified = bytearray(msg_bytes)
        if len(modified) > 32:
            modified[-1] ^= 0xFF  # Corrupt HMAC
            print("[TEST] Sending tampered message to trigger session termination")
        original_send(bytes(modified))
    
    client3.send_message = tamper_send
    result = client3.send_data("10,20,30")
    print(f"[TEST] Client 3 tampered message result: {result} (should be False/terminated)")
    time.sleep(1)
    
    print("\n[TEST] Step 4: Client 4 connects and sends round 1 data")
    client4 = SecureClient(4, b'client4_master_k', '127.0.0.1', 9999)
    client4.connect()
    client4.send_hello()
    client4.send_data("10,20,30")
    print("[TEST] Client 4 round 1 completed")
    time.sleep(0.5)
    
    print("\n" + "="*80)
    print("TEST COMPLETED")
    print("="*80)
    print("\nExpected behavior:")
    print("  - Client 3's session should be terminated due to HMAC failure")
    print("  - Client 3 should be excluded from all aggregations")
    print("  - Round 1 aggregate for Client 4 should only include clients 1, 2, 4")
    print("  - Client 3's data (if any was stored) should NOT affect aggregations")
    print("="*80)
    
    time.sleep(2)
    client1.disconnect()
    client2.disconnect()
    client4.disconnect()


if __name__ == "__main__":
    test_session_termination_aggregation()
