# Attack Implementation Summary

This document maps all required attacks to their implementations in the codebase.

## 1. Core Adversarial Attacks

### ✅ Replay Attacks
- **Method**: `replay_attack()`
- **Location**: `attacks.py` line 35
- **Description**: Captures a legitimate message and attempts to replay it. The protocol rejects it due to key evolution and round number tracking.

### ✅ Message Modification
- **Method**: `message_modification_attack()`
- **Location**: `attacks.py` line 119
- **Description**: Modifies ciphertext bytes during transit. Detected by HMAC verification failure.

### ✅ Message Reordering
- **Method**: `message_reordering_attack()`
- **Location**: `attacks.py` line 211
- **Description**: Attempts to send messages with wrong round numbers. Rejected by strict round number enforcement.

### ✅ Packet Dropping
- **Method**: `packet_dropping_attack()`
- **Location**: `attacks.py` line 325
- **Description**: Selectively drops packets to disrupt protocol flow. Handled by TCP reliability and application timeouts.

### ✅ Reflection Attacks
- **Method**: `reflection_attack()`
- **Location**: `attacks.py` line 258
- **Description**: Attempts to reflect server messages back to the server. Prevented by direction field and separate keys for each direction.

---

## 2. Protocol-Specific Failures

### ✅ Key Desynchronization
- **Method**: `key_desync_attack()`
- **Location**: `attacks.py` line 170
- **Description**: Corrupts encryption keys to cause state mismatch. Detected immediately via HMAC failure, session terminated.

### ✅ Padding Attacks/Tampering
- **Method**: `padding_tampering_attack()`
- **Location**: `attacks.py` line 381
- **Description**: Tampers with PKCS#7 padding bytes in ciphertext. Detected by HMAC verification before padding is even checked. Treated as data tampering.

### ✅ Invalid HMACs
- **Method**: `invalid_hmac_attack()`
- **Location**: `attacks.py` line 433
- **Description**: Corrupts HMAC values to demonstrate system's reaction. HMAC verification fails before any decryption, session terminated immediately.

### ✅ State Violations
- **Method**: `state_violation_attack()`
- **Location**: `attacks.py` line 484
- **Description**: Sends messages with wrong opcode for current protocol phase (e.g., CLIENT_DATA during INIT phase instead of ACTIVE). FSM validation rejects invalid state transitions.

---

## Attack Execution

All attacks can be run automatically using:

```bash
./run.sh  # Option 3: Run automated attack demonstrations
```

Or individually:

```bash
./venv/bin/python attacks.py
```

Or manually with interactive tool:

```bash
./venv/bin/python manual_attacks.py
```

---

## Attack Categories Summary

| Category | Attacks Implemented | Total Required |
|----------|---------------------|----------------|
| Core Adversarial Attacks | 5 | 5 |
| Protocol-Specific Failures | 4 | 4 |
| **TOTAL** | **9** | **9** |

✅ All required attacks are implemented and demonstrate the protocol's security properties.

---

## Defense Mechanisms

The protocol successfully defends against all attacks through:

1. **Encrypt-then-MAC**: HMAC computed over entire message including headers
2. **Key Evolution**: Keys ratchet after each successful message exchange
3. **Round Number Tracking**: Strict enforcement prevents replay and reordering
4. **Direction Fields**: Separate keys for C2S and S2C prevent reflection
5. **FSM Validation**: State machine enforces valid protocol transitions
6. **HMAC-before-Decrypt**: No decryption or processing until HMAC verified
7. **Immediate Termination**: Any security violation terminates session
8. **PKCS#7 Validation**: Padding errors treated as tampering

---

## Removed Attacks

- **Unauthorized Client Attack**: This was implemented but is not in the required list. However, it has been kept as an additional security demonstration (bonus).
