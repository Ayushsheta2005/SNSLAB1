# Security Analysis

## Overview

This document explains how the secure multi-client communication protocol defends against various attack scenarios. The protocol employs a stateful symmetric-key design with key evolution (ratcheting), HMAC authentication, and strict protocol state validation.

## Core Security Mechanisms

### 1. **Encrypt-then-MAC (EtM)**
- Messages are encrypted with AES-128-CBC, then authenticated with HMAC-SHA256
- HMAC covers the entire message: opcode, client ID, round number, direction, IV, and ciphertext
- Server verifies HMAC **before** decryption, preventing padding oracle and decryption oracle attacks
- Any tampering causes immediate HMAC failure and session termination

### 2. **Key Evolution (Ratcheting)**
- Keys evolve after every message exchange using HKDF-SHA256
- Separate key pairs for each direction: C2S (Client-to-Server) and S2C (Server-to-Client)
- Evolution formula: `new_key = HKDF(old_key, message_context)`
- Old keys cannot decrypt new messages, providing forward secrecy
- Keys evolve only after successful message exchange (atomic updates)

### 3. **Round Number Tracking**
- Each message includes a round number, starting from 0
- Server maintains expected round per client session
- Messages with incorrect round numbers are rejected
- Prevents replay, reordering, and duplication attacks

### 4. **Directional Authentication**
- Every message includes an explicit direction field (C2S or S2C)
- Direction is authenticated via HMAC
- Different encryption/MAC keys for each direction
- Prevents reflection attacks

### 5. **Finite State Machine (FSM)**
- Protocol phases: INIT → ACTIVE → TERMINATED
- Each phase allows only specific opcodes
- Invalid state transitions cause immediate termination
- Enforces proper handshake before data exchange

## Defense Against Specific Attacks

### 1. Replay Attacks ✓ DEFENDED
**Attack**: Adversary captures and resends old messages.

**Defense**:
- Round numbers prevent replay of old messages
- Keys evolve after each round, making old messages unverifiable
- Server tracks expected round per client
- HMAC fails for replayed messages due to key evolution

**Result**: Replayed messages are rejected with `KEY_DESYNC_ERROR`.

---

### 2. Message Modification ✓ DEFENDED
**Attack**: Adversary modifies ciphertext in transit.

**Defense**:
- HMAC-SHA256 covers entire message structure
- Any bit flip causes HMAC verification failure
- HMAC checked before decryption (Encrypt-then-MAC)
- Session terminated immediately on HMAC failure

**Result**: Modified messages are detected and rejected; session terminates.

---

### 3. Message Reordering ✓ DEFENDED
**Attack**: Adversary reorders messages or sends them out of sequence.

**Defense**:
- Strict round number enforcement
- Server expects exact round number for each client
- Round numbers authenticated via HMAC
- Cannot skip or repeat rounds

**Result**: Out-of-order messages are rejected; keys become desynchronized.

---

### 4. Key Desynchronization ✓ DETECTED
**Attack**: Client and server keys fall out of sync (protocol failure).

**Defense**:
- Deterministic key evolution on both sides
- Keys evolve only after complete successful exchange
- HMAC fails if keys don't match
- Explicit `KEY_DESYNC_ERROR` opcode

**Result**: Desynchronization detected immediately via HMAC failure.

---

### 5. Reflection Attacks ✓ DEFENDED
**Attack**: Adversary reflects server messages back to server.

**Defense**:
- Explicit direction field in every message
- Server expects `CLIENT_TO_SERVER` direction only
- Different keys for C2S and S2C directions
- Direction field authenticated via HMAC

**Result**: Reflected messages fail direction check and HMAC verification.

---

### 6. Packet Dropping ✓ MITIGATED
**Attack**: Adversary selectively drops packets (DoS).

**Defense**:
- TCP provides reliable delivery at transport layer
- Application-layer timeouts detect missing responses
- Session state preserved; clients can reconnect
- Dropped packets don't cause key desynchronization

**Result**: Timeouts trigger, but keys remain synchronized for retry.

---

### 7. Padding Tampering ✓ DEFENDED
**Attack**: Adversary modifies PKCS#7 padding bytes.

**Defense**:
- HMAC covers entire ciphertext including padding
- Padding validation occurs after HMAC verification
- Invalid padding treated as tampering
- Session terminated on padding errors

**Result**: Padding tampering detected via HMAC or padding validation.

---

### 8. Invalid HMAC ✓ DEFENDED
**Attack**: Adversary sends messages with incorrect HMAC.

**Defense**:
- HMAC verification before any processing
- Cryptographically secure HMAC-SHA256 (256-bit)
- No timing side channels (constant-time comparison)
- Session terminates on HMAC failure

**Result**: Invalid HMACs immediately rejected; no information leaked.

---

### 9. State Violation ✓ DEFENDED
**Attack**: Client sends wrong opcode for current protocol phase.

**Defense**:
- FSM validates opcode against current phase
- `CLIENT_HELLO` only in INIT phase
- `CLIENT_DATA` only in ACTIVE phase
- Invalid opcodes cause `TERMINATE` response

**Result**: Protocol violations detected and session terminated.

---

### 10. Unauthorized Client ✓ DEFENDED
**Attack**: Adversary attempts connection without valid credentials.

**Defense**:
- Pre-shared master keys for authorized clients only
- Server validates client ID against key database
- HMAC fails without correct master key
- No handshake completion without valid key

**Result**: Unauthorized clients cannot complete handshake; HMAC fails.

---

## Man-in-the-Middle (MITM) Attack Protection

The protocol defends against all three categories of MITM attacks through multiple layers of security:

### 1. Passive MITM (Eavesdropping) ✓ DEFENDED
**Attack**: Adversary passively monitors network traffic to steal information (passwords, keys, data).

**Defense**:
- **AES-128-CBC encryption**: All message payloads are encrypted
- Ciphertext is unreadable without the correct encryption keys
- Pre-shared master keys distributed via secure out-of-band channel
- Keys never transmitted over the network

**Result**: Eavesdropper sees only encrypted ciphertext; no plaintext exposed.

---

### 2. Active MITM (Interception & Modification) ✓ DEFENDED
**Attack**: Adversary actively intercepts and modifies messages in transit (drop, delay, replay, alter).

**Defense**:
- **HMAC-SHA256 authentication**: Every message authenticated before processing
- Any modification causes HMAC verification failure
- Encrypt-then-MAC design: integrity checked before decryption
- Round numbers prevent replay attacks
- Key evolution prevents delayed message injection

**Specific Sub-attacks Defended**:
- **Modification**: HMAC detects any bit flip
- **Replay**: Round numbers + key evolution reject old messages
- **Delay**: Stale messages fail round number check
- **Drop**: TCP reliability + timeouts detect missing messages

**Result**: Active tampering detected immediately; session terminates on integrity failure.

---

### 3. MITM with Impersonation ✓ DEFENDED
**Attack**: Adversary impersonates the server to the client or the client to the server.

**Defense**:
- **Pre-shared symmetric keys**: Each authorized client has a unique master key
- Attacker cannot generate valid HMACs without the master key
- Server validates client ID against its key database
- HMAC verification proves possession of the correct key
- Directional keys (C2S vs S2C) prevent key reuse attacks

**Authentication Flow**:
1. Client sends `CLIENT_HELLO` with HMAC using master-derived keys
2. Server verifies HMAC (proves client has valid master key)
3. Server responds with `SERVER_CHALLENGE` (proves server has valid master key)
4. Both sides authenticated via HMAC verification

**Result**: Impersonation impossible without pre-shared master key; HMAC fails.

---

### MITM Protection Summary

| MITM Type | Attack Goal | Defense Mechanism | Result |
|-----------|-------------|-------------------|--------|
| **Passive** | Steal data | AES-128-CBC encryption | Ciphertext unreadable |
| **Active** | Modify messages | HMAC-SHA256 + Round numbers | Tampering detected |
| **Impersonation** | Fake identity | Pre-shared keys + HMAC auth | Authentication fails |

**Key Assumption**: Pre-shared master keys are distributed securely via an out-of-band channel (e.g., in-person, secure USB, trusted courier). If this assumption holds, MITM attacks at the protocol level are defeated.

---

## Security Properties Summary

| Property | Status | Mechanism |
|----------|--------|-----------|
| **Confidentiality** | ✓ Provided | AES-128-CBC encryption |
| **Integrity** | ✓ Provided | HMAC-SHA256 authentication |
| **Authentication** | ✓ Provided | Pre-shared keys + HMAC |
| **Forward Secrecy** | ✓ Limited | Key evolution (within session) |
| **Replay Protection** | ✓ Provided | Round numbers + key evolution |
| **Order Protection** | ✓ Provided | Round number enforcement |
| **Freshness** | ✓ Provided | Key ratcheting |

## Assumptions and Limitations

### Assumptions
1. **Pre-shared Keys**: Clients possess valid master keys distributed securely out-of-band
2. **Trusted Endpoints**: Client and server software are trusted and not compromised
3. **Network**: TCP provides reliable, in-order delivery (but may be adversarial)
4. **Cryptographic Primitives**: AES-128-CBC and HMAC-SHA256 are secure

### Limitations
1. **No Long-term Forward Secrecy**: Master key compromise exposes all past sessions
2. **No Authentication Against Server Compromise**: If server is compromised, attacker can impersonate it
3. **DoS Vulnerability**: Adversary can always drop packets (network-layer attack)
4. **No Public Key Infrastructure**: Requires pre-shared symmetric keys
