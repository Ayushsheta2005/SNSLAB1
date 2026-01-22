#!/usr/bin/env python3
"""
Attack Verification Script
Verifies that all required attacks are implemented correctly.
"""

from attacks import AttackScenarios
import inspect

def verify_attacks():
    """Verify all required attacks are implemented"""
    
    print("="*70)
    print("ATTACK IMPLEMENTATION VERIFICATION")
    print("="*70)
    
    required_attacks = {
        "Core Adversarial Attacks": [
            ("Replay Attacks", "replay_attack"),
            ("Message Modification", "message_modification_attack"),
            ("Message Reordering", "message_reordering_attack"),
            ("Packet Dropping", "packet_dropping_attack"),
            ("Reflection Attacks", "reflection_attack")
        ],
        "Protocol-Specific Failures": [
            ("Key Desynchronization", "key_desync_attack"),
            ("Padding Attacks/Tampering", "padding_tampering_attack"),
            ("Invalid HMACs", "invalid_hmac_attack"),
            ("State Violations", "state_violation_attack")
        ]
    }
    
    attacker = AttackScenarios()
    all_present = True
    
    for category, attacks in required_attacks.items():
        print(f"\n{category}:")
        for name, method_name in attacks:
            if hasattr(attacker, method_name):
                method = getattr(attacker, method_name)
                if callable(method):
                    # Get docstring
                    doc = inspect.getdoc(method)
                    first_line = doc.split('\n')[0] if doc else "No description"
                    print(f"  ✅ {name:<30} -> {method_name}()")
                    print(f"     {first_line}")
                else:
                    print(f"  ❌ {name:<30} -> {method_name} (not callable)")
                    all_present = False
            else:
                print(f"  ❌ {name:<30} -> {method_name} (NOT FOUND)")
                all_present = False
    
    print("\n" + "="*70)
    if all_present:
        print("✅ ALL REQUIRED ATTACKS ARE IMPLEMENTED")
        print(f"   Total: {sum(len(attacks) for attacks in required_attacks.values())} attacks")
    else:
        print("❌ SOME ATTACKS ARE MISSING")
    print("="*70)
    
    return all_present


if __name__ == "__main__":
    verify_attacks()
