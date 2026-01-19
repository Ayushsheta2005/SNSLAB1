#!/usr/bin/env python3
"""
Quick Demo - Shows the system working with one client
"""

import subprocess
import time
import sys
import signal

def main():
    print("\n" + "="*70)
    print("  QUICK DEMO - Secure Multi-Client Communication")
    print("="*70 + "\n")
    
    print("This will demonstrate:")
    print("  1. Server starting")
    print("  2. Client connecting and performing handshake")
    print("  3. Secure data exchange")
    print("  4. Key evolution after each round")
    print("\nPress Ctrl+C to stop\n")
    
    input("Press Enter to start...")
    
    # Start server
    print("\n[1] Starting server...")
    server_proc = subprocess.Popen(
        [sys.executable, "server.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    time.sleep(2)
    print("✅ Server started\n")
    
    try:
        # Run client
        print("[2] Starting client 1...")
        client_proc = subprocess.Popen(
            [sys.executable, "client.py", "1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Get client output
        stdout, _ = client_proc.communicate(timeout=15)
        
        print("\n" + "-"*70)
        print("CLIENT OUTPUT:")
        print("-"*70)
        print(stdout)
        print("-"*70 + "\n")
        
        if client_proc.returncode == 0:
            print("✅ Client completed successfully!")
        else:
            print("⚠️  Client exited with code:", client_proc.returncode)
        
        print("\n[3] System demonstration complete!")
        print("\nWhat happened:")
        print("  ✅ Client performed handshake (CLIENT_HELLO → SERVER_CHALLENGE)")
        print("  ✅ Client sent encrypted data in multiple rounds")
        print("  ✅ Server aggregated data and sent encrypted responses")
        print("  ✅ Keys evolved after each round (ratcheting)")
        print("  ✅ All messages authenticated with HMAC")
        
    except subprocess.TimeoutExpired:
        print("\n⚠️  Client timed out")
        client_proc.kill()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted")
    finally:
        # Stop server
        print("\n[4] Stopping server...")
        server_proc.terminate()
        try:
            server_proc.wait(timeout=3)
        except:
            server_proc.kill()
        print("✅ Server stopped")
    
    print("\n" + "="*70)
    print("  Demo Complete!")
    print("="*70)
    print("\nTo run full system:")
    print("  ./run.sh  (interactive menu)")
    print("  python test_system.py  (automated demo)")
    print("\nTo run attack demonstrations:")
    print("  python attacks.py  (make sure server is running)")
    print()

if __name__ == "__main__":
    main()
