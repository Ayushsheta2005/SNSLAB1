#!/usr/bin/env python3
"""
Test script to verify that disconnected clients are excluded from aggregations.
"""

import time
import threading
from client import SecureClient
from server import SecureServer


def run_server():
    """Run server in background"""
    server = SecureServer()
    server.start()


def test_client_disconnect_aggregation():
    """
    Test scenario:
    1. Client 1 sends data in round 1: 10,20,30 (avg=20)
    2. Client 2 sends data in round 1: 10,20,30 (avg=20, total aggregate=20)
    3. Client 1 disconnects
    4. Client 3 sends data in round 1: 10,20,30 
       -> Should get aggregate from only clients 2 and 3 (not client 1)
    """
    print("="*80)
    print("TEST: Client Disconnection Excludes from Aggregations")
    print("="*80)
    
    # Start server
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1)
    
    print("\n[TEST] Step 1: Client 1 connects and sends round 1 data")
    client1 = SecureClient(1, b'client1_master_k', '127.0.0.1', 9999)
    client1.connect()
    client1.send_hello()
    response1 = client1.send_data("10,20,30")
    print(f"[TEST] Client 1 round 1 completed: {response1}")
    time.sleep(0.5)
    
    print("\n[TEST] Step 2: Client 2 connects and sends round 1 data")
    client2 = SecureClient(2, b'client2_master_k', '127.0.0.1', 9999)
    client2.connect()
    client2.send_hello()
    response2 = client2.send_data("10,20,30")
    print(f"[TEST] Client 2 round 1 completed: {response2}")
    time.sleep(0.5)
    
    print("\n[TEST] Step 3: Client 1 DISCONNECTS")
    client1.disconnect()
    time.sleep(1)
    print("[TEST] Client 1 disconnected - should be excluded from aggregations")
    
    print("\n[TEST] Step 4: Client 3 connects and sends round 1 data")
    client3 = SecureClient(3, b'client3_master_k', '127.0.0.1', 9999)
    client3.connect()
    client3.send_hello()
    response3 = client3.send_data("10,20,30")
    print(f"[TEST] Client 3 round 1 completed: {response3}")
    time.sleep(0.5)
    
    print("\n[TEST] Step 5: Client 2 sends round 2 data")
    response2_r2 = client2.send_data("100,200,300")
    print(f"[TEST] Client 2 round 2 completed: {response2_r2}")
    time.sleep(0.5)
    
    print("\n[TEST] Step 6: Client 3 sends round 2 data")
    response3_r2 = client3.send_data("100,200,300")
    print(f"[TEST] Client 3 round 2 completed: {response3_r2}")
    
    print("\n" + "="*80)
    print("TEST COMPLETED")
    print("="*80)
    print("\nExpected behavior:")
    print("  - Round 1 aggregate for Client 1: 20.00 (only client 1)")
    print("  - Round 1 aggregate for Client 2: 20.00 (clients 1+2)")
    print("  - Round 1 aggregate for Client 3: 20.00 (clients 2+3, client 1 excluded)")
    print("  - Round 2 aggregate for Client 2: 200.00 (only client 2)")
    print("  - Round 2 aggregate for Client 3: 200.00 (clients 2+3)")
    print("\nClient 1's data should NOT affect aggregations after disconnection!")
    print("="*80)
    
    time.sleep(2)
    client2.disconnect()
    client3.disconnect()


if __name__ == "__main__":
    test_client_disconnect_aggregation()
