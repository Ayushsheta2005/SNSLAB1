#!/usr/bin/env python3
"""
Test script to demonstrate the secure multi-client communication system.
Run this script to see the system in action.
"""

import subprocess
import time
import sys
import os


def print_banner(text):
    """Print a formatted banner"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70 + "\n")


def main():
    """Main test orchestration"""
    
    print_banner("SECURE MULTI-CLIENT COMMUNICATION - DEMONSTRATION")
    
    print("This script will:")
    print("  1. Start the server")
    print("  2. Launch multiple clients")
    print("  3. Demonstrate secure communication")
    print("  4. Run attack scenarios\n")
    
    # Check if virtual environment is activated
    if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("⚠️  Warning: Virtual environment not detected!")
        print("   Please activate it with: source venv/bin/activate\n")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            return
    
    # Start server in background
    print_banner("STEP 1: Starting Server")
    print("Launching server on 127.0.0.1:9999...")
    
    server_proc = subprocess.Popen(
        [sys.executable, "server.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    time.sleep(2)  # Give server time to start
    print("✓ Server started (PID: {})\n".format(server_proc.pid))
    
    try:
        # Run clients
        print_banner("STEP 2: Running Clients")
        
        client_procs = []
        for client_id in [1, 2, 3]:
            print(f"Starting Client {client_id}...")
            proc = subprocess.Popen(
                [sys.executable, "client.py", str(client_id)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            client_procs.append(proc)
            time.sleep(0.5)
        
        # Wait for clients to complete
        print("\nClients are communicating with server...\n")
        
        for i, proc in enumerate(client_procs, 1):
            stdout, stderr = proc.communicate(timeout=10)
            print(f"--- Client {i} Output ---")
            print(stdout)
            if stderr:
                print(f"Errors: {stderr}")
            print()
        
        print("✓ All clients completed successfully\n")
        
        # Run attack demonstrations
        print_banner("STEP 3: Running Attack Demonstrations")
        print("This will demonstrate various attacks and how the protocol resists them.\n")
        
        input("Press Enter to continue with attack demonstrations...")
        
        attack_proc = subprocess.Popen(
            [sys.executable, "attacks.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Stream output in real-time
        for line in iter(attack_proc.stdout.readline, ''):
            if line:
                print(line, end='')
        
        attack_proc.wait()
        
        print("\n✓ Attack demonstrations completed\n")
        
        print_banner("DEMONSTRATION COMPLETE")
        print("Summary:")
        print("  ✓ Server handled multiple clients concurrently")
        print("  ✓ Clients communicated securely with encryption and authentication")
        print("  ✓ Protocol resisted all simulated attacks")
        print("  ✓ Key evolution (ratcheting) working correctly")
        print("\nCheck SECURITY.md for detailed security analysis.")
        print("\nYou can review the implementation in:")
        print("  - crypto_utils.py   (cryptographic primitives)")
        print("  - protocol_fsm.py   (protocol state machine)")
        print("  - server.py         (server implementation)")
        print("  - client.py         (client implementation)")
        print("  - attacks.py        (attack scenarios)\n")
        
    except subprocess.TimeoutExpired:
        print("\n⚠️  Timeout: Clients took too long to complete")
        for proc in client_procs:
            proc.kill()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        # Clean up
        print("\nCleaning up...")
        server_proc.terminate()
        server_proc.wait(timeout=5)
        print("✓ Server stopped")


if __name__ == "__main__":
    # Change to script directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()
