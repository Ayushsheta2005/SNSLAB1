#!/usr/bin/env python3
"""
Test script to demonstrate round-by-round aggregation.
Follows the exact example provided by the user.
"""

import time
import socket
import struct
import threading
from client import SecureClient


def run_client_1():
    """
    Client 1 sequence:
    - Round 1: Send 10,20,30 (expects aggregate 20)
    - Round 2: Send 100,200,300 (expects aggregate 112.5)
    """
    print("[TEST] Starting Client 1")
    time.sleep(0.5)  # Small delay to let server start
    
    client = SecureClient(1, b'client1_master_k', '127.0.0.1', 9999)
    client.connect()
    client.send_hello()
    
    # Round 1: Send 10,20,30
    print("[CLIENT 1] Round 1: Sending 10,20,30")
    response = client.send_data("10,20,30")
    print(f"[CLIENT 1] Round 1 response: {response}")
    
    # Wait for client 2 to complete round 2 (but stay connected)
    time.sleep(2)
    
    # Round 2: Send 100,200,300
    print("[CLIENT 1] Round 2: Sending 100,200,300")
    response = client.send_data("100,200,300")
    print(f"[CLIENT 1] Round 2 response: {response}")
    
    time.sleep(1)
    client.disconnect()
    print("[CLIENT 1] Disconnected")


def run_client_2():
    """
    Client 2 sequence:
    - Round 1: Send 1,2,3 (expects aggregate 10.5)
    - Round 2: Send 15,25,35 (expects aggregate 25)
    """
    print("[TEST] Starting Client 2")
    time.sleep(1)  # Start slightly after client 1
    
    client = SecureClient(2, b'client2_master_k', '127.0.0.1', 9999)
    client.connect()
    client.send_hello()
    
    # Round 1: Send 1,2,3
    print("[CLIENT 2] Round 1: Sending 1,2,3")
    response = client.send_data("1,2,3")
    print(f"[CLIENT 2] Round 1 response: {response}")
    
    time.sleep(1)
    
    # Round 2: Send 15,25,35
    print("[CLIENT 2] Round 2: Sending 15,25,35")
    response = client.send_data("15,25,35")
    print(f"[CLIENT 2] Round 2 response: {response}")
    
    # Wait for client 1 to also complete round 2
    time.sleep(2)
    client.disconnect()
    print("[CLIENT 2] Disconnected")


def main():
    """Run the aggregation test"""
    print("="*80)
    print("ROUND-BY-ROUND AGGREGATION TEST")
    print("="*80)
    print("\nExpected results:")
    print("  Client 1, Round 1 (10,20,30): aggregate = 20")
    print("  Client 2, Round 1 (1,2,3):    aggregate = 10.5  (avg of 10,20,30,1,2,3)")
    print("  Client 2, Round 2 (15,25,35): aggregate = 25")
    print("  Client 1, Round 2 (100,200,300): aggregate = 112.5  (avg of 15,25,35,100,200,300)")
    print("="*80)
    print()
    
    # Start server in background
    from server import SecureServer
    server = SecureServer()
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    
    time.sleep(1)  # Let server initialize
    
    # Start client threads
    client1_thread = threading.Thread(target=run_client_1, daemon=True)
    client2_thread = threading.Thread(target=run_client_2, daemon=True)
    
    client1_thread.start()
    client2_thread.start()
    
    # Wait for clients to finish
    client1_thread.join()
    client2_thread.join()
    
    print("\n" + "="*80)
    print("TEST COMPLETED")
    print("="*80)
    
    # Keep server running briefly to see final output
    time.sleep(2)


if __name__ == "__main__":
    main()
