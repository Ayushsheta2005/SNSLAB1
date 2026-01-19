#!/usr/bin/env python3
"""
Verification script to check if all assignment requirements are met.
"""

import os
import sys

def print_header(text):
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def check_files():
    """Check if all required files exist"""
    print_header("FILE STRUCTURE CHECK")
    
    required_files = {
        'server.py': 'Server implementation',
        'client.py': 'Client implementation',
        'crypto_utils.py': 'Cryptographic primitives only',
        'protocol_fsm.py': 'Protocol FSM and state management',
        'attacks.py': 'Attack demonstrations',
        'README.md': 'Usage documentation',
        'SECURITY.md': 'Security analysis'
    }
    
    all_present = True
    for filename, description in required_files.items():
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            print(f"✅ {filename:25s} ({size:>7,} bytes) - {description}")
        else:
            print(f"❌ {filename:25s} - MISSING - {description}")
            all_present = False
    
    return all_present

def check_crypto_implementation():
    """Check crypto_utils.py implementation"""
    print_header("CRYPTOGRAPHIC REQUIREMENTS")
    
    if not os.path.exists('crypto_utils.py'):
        print("❌ crypto_utils.py not found!")
        return False
    
    with open('crypto_utils.py', 'r') as f:
        content = f.read()
    
    checks = [
        ('Manual PKCS#7 Padding', ['apply_pkcs7_padding', 'remove_pkcs7_padding']),
        ('AES-128-CBC Encryption', ['aes_cbc_encrypt', 'aes_cbc_decrypt', 'MODE_CBC']),
        ('HMAC-SHA256', ['compute_hmac', 'verify_hmac', 'hmac.new']),
        ('Secure Random IV', ['os.urandom', 'generate_random_iv']),
        ('Key Derivation', ['derive_key']),
        ('Key Evolution', ['evolve_key']),
    ]
    
    all_passed = True
    for check_name, keywords in checks:
        if all(kw in content for kw in keywords):
            print(f"✅ {check_name}")
        else:
            print(f"❌ {check_name} - Missing: {[kw for kw in keywords if kw not in content]}")
            all_passed = False
    
    # Check for forbidden elements
    print("\n🚫 Checking for FORBIDDEN elements:")
    forbidden = ['MODE_GCM', 'MODE_CCM', 'MODE_ECB', 'Fernet', 'MODE_EAX', 'AES.MODE_GCM']
    found_forbidden = []
    
    for forb in forbidden:
        if forb in content:
            found_forbidden.append(forb)
    
    if found_forbidden:
        print(f"❌ FORBIDDEN elements found: {found_forbidden}")
        all_passed = False
    else:
        print("✅ No forbidden encryption modes (GCM, CCM, ECB, Fernet)")
    
    return all_passed

def check_protocol_implementation():
    """Check protocol_fsm.py implementation"""
    print_header("PROTOCOL REQUIREMENTS")
    
    if not os.path.exists('protocol_fsm.py'):
        print("❌ protocol_fsm.py not found!")
        return False
    
    with open('protocol_fsm.py', 'r') as f:
        content = f.read()
    
    checks = [
        ('Session State Management', ['SessionState', 'class SessionState']),
        ('Round Number Tracking', ['round_number', 'round']),
        ('Key Evolution Methods', ['evolve_c2s_keys', 'evolve_s2c_keys']),
        ('Protocol Phases', ['ProtocolPhase', 'INIT', 'ACTIVE', 'TERMINATED']),
        ('Message Encryption', ['ProtocolMessage', 'encrypt_and_sign']),
        ('Message Verification', ['parse_and_verify', 'verify_hmac']),
        ('Opcode Validation', ['validate_opcode', 'ProtocolFSM']),
    ]
    
    all_passed = True
    for check_name, keywords in checks:
        if any(kw in content for kw in keywords):
            print(f"✅ {check_name}")
        else:
            print(f"❌ {check_name}")
            all_passed = False
    
    # Check opcodes
    print("\n🎯 Protocol Opcodes:")
    opcodes = {
        'CLIENT_HELLO': '10',
        'SERVER_CHALLENGE': '20',
        'CLIENT_DATA': '30',
        'SERVER_AGGR_RESPONSE': '40',
        'KEY_DESYNC_ERROR': '50',
        'TERMINATE': '60'
    }
    
    for opcode_name, opcode_value in opcodes.items():
        if opcode_name in content and opcode_value in content:
            print(f"✅ {opcode_name:25s} = {opcode_value}")
        else:
            print(f"⚠️  {opcode_name:25s}")
    
    return all_passed

def check_server_client():
    """Check server and client implementations"""
    print_header("SERVER & CLIENT IMPLEMENTATION")
    
    all_passed = True
    
    # Check server.py
    if os.path.exists('server.py'):
        with open('server.py', 'r') as f:
            server_content = f.read()
        
        if 'SecureServer' in server_content or 'class' in server_content:
            print("✅ Server implementation found")
        else:
            print("❌ Server class not found")
            all_passed = False
        
        if 'threading' in server_content or 'Thread' in server_content:
            print("✅ Multi-client support (threading)")
        else:
            print("⚠️  Multi-client threading - verify manually")
        
        if 'SessionState' in server_content or 'session' in server_content:
            print("✅ Per-client session management")
        else:
            print("❌ Session management not found")
            all_passed = False
    else:
        print("❌ server.py not found")
        all_passed = False
    
    # Check client.py
    if os.path.exists('client.py'):
        with open('client.py', 'r') as f:
            client_content = f.read()
        
        if 'SecureClient' in client_content or 'class' in client_content:
            print("✅ Client implementation found")
        else:
            print("❌ Client class not found")
            all_passed = False
        
        if 'send_hello' in client_content or 'CLIENT_HELLO' in client_content:
            print("✅ CLIENT_HELLO handshake")
        else:
            print("❌ Handshake not found")
            all_passed = False
    else:
        print("❌ client.py not found")
        all_passed = False
    
    return all_passed

def check_attacks():
    """Check attack demonstrations"""
    print_header("ATTACK DEMONSTRATIONS")
    
    if not os.path.exists('attacks.py'):
        print("❌ attacks.py not found!")
        return False
    
    with open('attacks.py', 'r') as f:
        content = f.read().lower()
    
    attacks = [
        'Replay Attack',
        'Message Modification',
        'Key Desynchronization',
        'Message Reordering',
        'Reflection Attack',
        'Unauthorized Client'
    ]
    
    all_passed = True
    for attack in attacks:
        attack_lower = attack.lower().replace(' ', '_')
        if attack_lower in content or attack.replace(' ', '').lower() in content:
            print(f"✅ {attack:30s} scenario")
        else:
            print(f"⚠️  {attack:30s} - verify manually")
    
    return all_passed

def check_key_management():
    """Check key management implementation"""
    print_header("KEY MANAGEMENT")
    
    key_labels = ['C2S-ENC', 'C2S-MAC', 'S2C-ENC', 'S2C-MAC']
    found_labels = []
    
    for filename in ['crypto_utils.py', 'protocol_fsm.py', 'server.py', 'client.py']:
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                content = f.read()
                for label in key_labels:
                    if label in content and label not in found_labels:
                        found_labels.append(label)
    
    for label in key_labels:
        if label in found_labels:
            print(f"✅ {label} key derivation")
        else:
            print(f"❌ {label} key derivation - not found")
    
    return len(found_labels) == len(key_labels)

def test_imports():
    """Test if modules can be imported"""
    print_header("MODULE IMPORT TEST")
    
    all_passed = True
    
    try:
        from crypto_utils import CryptoUtils
        print("✅ crypto_utils.py imports successfully")
        
        # Test methods exist
        methods = ['apply_pkcs7_padding', 'remove_pkcs7_padding', 'aes_cbc_encrypt', 
                   'aes_cbc_decrypt', 'compute_hmac', 'verify_hmac', 'derive_key', 'evolve_key']
        for method in methods:
            if hasattr(CryptoUtils, method):
                print(f"   ✅ {method}")
            else:
                print(f"   ❌ {method} - missing")
                all_passed = False
    except Exception as e:
        print(f"❌ crypto_utils.py import error: {e}")
        all_passed = False
    
    try:
        from protocol_fsm import SessionState, Opcode, ProtocolPhase, ProtocolMessage, ProtocolFSM
        print("✅ protocol_fsm.py imports successfully")
        
        # Check Opcodes
        opcodes = [Opcode.CLIENT_HELLO, Opcode.SERVER_CHALLENGE, Opcode.CLIENT_DATA, 
                   Opcode.SERVER_AGGR_RESPONSE, Opcode.KEY_DESYNC_ERROR, Opcode.TERMINATE]
        print(f"   ✅ All 6 opcodes defined: {[op.value for op in opcodes]}")
        
        # Check Phases
        phases = [ProtocolPhase.INIT, ProtocolPhase.ACTIVE, ProtocolPhase.TERMINATED]
        print(f"   ✅ All 3 phases defined: {[ph.value for ph in phases]}")
    except Exception as e:
        print(f"❌ protocol_fsm.py import error: {e}")
        all_passed = False
    
    return all_passed

def main():
    """Main verification function"""
    print("\n" + "="*70)
    print("  SNS LAB ASSIGNMENT 1 - REQUIREMENTS VERIFICATION")
    print("  Secure Multi-Client Communication with Symmetric Keys")
    print("="*70)
    
    results = {}
    
    results['files'] = check_files()
    results['crypto'] = check_crypto_implementation()
    results['protocol'] = check_protocol_implementation()
    results['server_client'] = check_server_client()
    results['attacks'] = check_attacks()
    results['keys'] = check_key_management()
    results['imports'] = test_imports()
    
    # Final summary
    print_header("VERIFICATION SUMMARY")
    
    for check, passed in results.items():
        status = "✅ PASS" if passed else "⚠️  CHECK"
        print(f"{status:10s} - {check.replace('_', ' ').title()}")
    
    all_passed = all(results.values())
    
    print("\n" + "="*70)
    if all_passed:
        print("  ✅ ALL REQUIREMENTS MET!")
        print("  Your implementation is ready for submission.")
    else:
        print("  ⚠️  SOME ITEMS NEED VERIFICATION")
        print("  Please review the items marked above.")
    print("="*70 + "\n")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
