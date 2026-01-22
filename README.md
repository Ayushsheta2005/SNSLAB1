# Secure Multi-Client Communication with Symmetric Keys

**IIIT Hyderabad - CS5.470 System and Network Security**  
**Lab Assignment 1**


## Assumptions and Limitations

### Assumptions

1. **Pre-shared Keys**: Each authorized client (IDs 1-5) possesses a unique master key distributed securely via an out-of-band channel (e.g., physical media, secure courier)

2. **Trusted Endpoints**: Client and server software are trusted and not compromised. The implementation is secure if endpoints are secure.

3. **TCP Reliability**: TCP provides reliable, in-order delivery at the transport layer. While the network may be adversarial, TCP handles basic packet ordering.

4. **Cryptographic Primitives**: AES-128-CBC and HMAC-SHA256 are assumed to be cryptographically secure and unbroken.

5. **Asynchronous Aggregation**: Clients do not synchronize before submitting data. Aggregation is computed on arrival without waiting.


## Overview

This project implements a **stateful, symmetric-key-based secure communication protocol** between a server and multiple clients operating in a hostile network environment. The protocol emphasizes state management, key evolution (ratcheting), and resistance to active adversarial attacks.

### Key Features
- ✅ **Stateful Protocol**: Round tracking, key evolution, and phase management
- ✅ **Encrypt-then-MAC**: AES-128-CBC encryption with HMAC-SHA256 authentication
- ✅ **Manual PKCS#7 Padding**: Explicit padding implementation (no automatic padding)
- ✅ **Key Ratcheting**: Keys evolve after every message exchange
- ✅ **Attack Resistance**: Defends against replay, modification, reordering, and reflection attacks
- ✅ **Multi-Client Aggregation**: Server-side secure data aggregation
- ✅ **Comprehensive Testing**: 10 attack scenarios with demonstrations

---

## System Architecture

### Components

| File | Description |
|------|-------------|
| `server.py` | Multi-client server with session management and aggregation |
| `client.py` | Client implementation with stateful communication |
| `crypto_utils.py` | Core cryptographic primitives (AES-CBC, PKCS#7, HMAC) |
| `protocol_fsm.py` | Protocol finite state machine and key evolution logic |
| `attacks.py` | Automated attack demonstrations (10 scenarios) |
| `manual_attacks.py` | Interactive attack testing tool |
| `test_system.py` | Integrated system testing script |
| `SECURITY.md` | Detailed security analysis and threat mitigation |

### Protocol Flow

```
Client                           Server
  |                                |
  |------ CLIENT_HELLO (R=0) ---->|  [INIT Phase]
  |                                |  (Verify HMAC, evolve keys)
  |<---- SERVER_CHALLENGE (R=0) --|
  |                                |
  | [Both advance to ACTIVE phase] |
  |                                |
  |------ CLIENT_DATA (R=1) ----->|  [ACTIVE Phase]
  |                                |  (Aggregate data)
  |<-- SERVER_AGGR_RESPONSE (R=1)-|
  |                                |
  | [Keys evolve after each round] |
  |                                |
  |------ CLIENT_DATA (R=2) ----->|
  |<-- SERVER_AGGR_RESPONSE (R=2)-|
  |                                |
```

---

## Cryptographic Specifications

### Primitives
- **Encryption**: AES-128-CBC (manual mode, no GCM/CCM)
- **MAC**: HMAC-SHA256 (32 bytes)
- **Padding**: Manual PKCS#7 implementation
- **IV**: 16 bytes, freshly generated per message
- **Key Derivation**: HKDF-SHA256

### Message Format
```
| Opcode (1) | Client ID (1) | Round (4) | Direction (1) | IV (16) | Ciphertext (variable) | HMAC (32) |
```

Total overhead: **55 bytes** (excluding ciphertext)

### Protocol Opcodes

| Opcode | Name | Description |
|--------|------|-------------|
| 10 | `CLIENT_HELLO` | Client initiates handshake |
| 20 | `SERVER_CHALLENGE` | Server responds to handshake |
| 30 | `CLIENT_DATA` | Encrypted client data submission |
| 40 | `SERVER_AGGR_RESPONSE` | Encrypted aggregated result |
| 50 | `KEY_DESYNC_ERROR` | Key desynchronization detected |
| 60 | `TERMINATE` | Session termination |

### Key Evolution (Ratcheting)

Keys evolve deterministically after each successful message exchange:

```python
# Client-to-Server Keys
C2S_Enc_{R+1} = HKDF(C2S_Enc_R, Ciphertext_R)
C2S_Mac_{R+1} = HKDF(C2S_Mac_R, IV_R)

# Server-to-Client Keys
S2C_Enc_{R+1} = HKDF(S2C_Enc_R, AggregatedData_R)
S2C_Mac_{R+1} = HKDF(S2C_Mac_R, StatusCode_R)
```

**Critical Rule**: Keys evolve only after successful verification and decryption. Any failure terminates the session without key updates.

---

## Requirements

### System Requirements
- **Python**: 3.7 or higher
- **OS**: Linux, macOS, or Windows
- **Network**: Localhost (127.0.0.1) or LAN

### Python Dependencies
```bash
pycryptodome==3.19.0
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Or use the provided virtual environment setup:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Quick Start

### Option 1: Automated Setup (Recommended)
```bash
chmod +x run.sh
./run.sh
```

This script will:
1. Create a virtual environment
2. Install dependencies
3. Provide menu options for server, client, and attack demonstrations

### Option 2: Manual Setup

#### Step 1: Start the Server
```bash
python3 server.py
```

The server will:
- Listen on `127.0.0.1:9999`
- Support clients with IDs 1-5
- Display connection status and aggregation results

#### Step 2: Start Clients (in separate terminals)
```bash
# Client 1
python3 client.py 1

# Client 2
python3 client.py 2

# Client 3 (and so on...)
python3 client.py 3
```

Each client will:
1. Complete handshake with server
2. Prompt for numeric data input (e.g., `10.5, 20.3, 30.1`)
3. Display aggregated results from server

#### Step 3: Run Attack Demonstrations
```bash
python3 attacks.py
```

This will automatically demonstrate all 10 attack scenarios and show how the protocol defends against them.

---

## Usage Examples

### Interactive Client Session
```bash
$ python3 client.py 1
[CLIENT 1] Connected to server at 127.0.0.1:9999
[CLIENT 1] Sending CLIENT_HELLO
[CLIENT 1] Received SERVER_CHALLENGE: Challenge from server
[CLIENT 1] Handshake complete, advancing to round 1
[CLIENT 1] Ready to send data
[CLIENT 1] Enter comma-separated numbers (e.g., 10.5, 20.3, 30.1)

[CLIENT 1] Enter data: 10.5, 20.3, 30.1
[CLIENT 1] Sending data: 10.5, 20.3, 30.1
[CLIENT 1] Received: Aggregated sum=60.9, count=3, avg=20.30
[CLIENT 1] Round complete, advancing to round 2
```

### Attack Demonstration
```bash
$ python3 attacks.py
==================================================
ATTACK SCENARIO 1: REPLAY ATTACK
==================================================
[ATTACK] Sending legitimate message...
[ATTACK] Captured message of length 128
[ATTACK] Attempting to replay captured message...
[RESULT] ✓ Attack BLOCKED - Server rejected replay

[ANALYSIS] The protocol rejects replay attacks because:
  1. Each message includes a round number
  2. Keys evolve after each round, making old messages invalid
  ...
```

### Manual Attack Testing
```bash
python3 manual_attacks.py
```

Interactive menu for security researchers to manually craft and test attacks.

---

## Server-Side Aggregation

### Aggregation Logic

The server performs **real-time multi-client aggregation** on numeric data:

```python
# For each round, aggregate data from all active clients
Sum = Σ(all_values_from_all_clients)
Count = total_number_of_values
Average = Sum / Count
```

### Important Aggregation Assumptions

1. **No Synchronization**: Aggregation includes all data submitted so far by currently connected clients
2. **Arrival-Based**: Results computed on message arrival, not waiting for all clients
3. **Round-Specific**: Each round maintains separate aggregation state
4. **Variable Results**: The same round may show different aggregates depending on when clients submit

**Example Scenario**:
```
Round 1:
  - Client 1 sends: 10.0, 20.0 (aggregated immediately)
  - Server responds to Client 1: sum=30.0, count=2, avg=15.0
  
  - Client 2 sends: 30.0, 40.0 (aggregated with Client 1's data)
  - Server responds to Client 2: sum=100.0, count=4, avg=25.0
```

This design reflects real-world scenarios where clients operate asynchronously.

---

## Security Properties

### Defenses Implemented

| Attack Type | Defense Mechanism | Status |
|-------------|-------------------|--------|
| Replay Attacks | Round numbers + Key evolution | ✅ Defended |
| Message Modification | HMAC-SHA256 (Encrypt-then-MAC) | ✅ Defended |
| Message Reordering | Strict round enforcement | ✅ Defended |
| Reflection Attacks | Directional keys + Direction field | ✅ Defended |
| Key Desynchronization | Atomic key updates + Detection | ✅ Detected |
| Padding Tampering | HMAC over entire ciphertext | ✅ Defended |
| Invalid HMAC | Pre-decryption verification | ✅ Defended |
| State Violations | FSM validation | ✅ Defended |
| Unauthorized Clients | Pre-shared key authentication | ✅ Defended |
| MITM Attacks | Encryption + Authentication | ✅ Defended |

See **[SECURITY.md](SECURITY.md)** for detailed security analysis.

---


### Limitations

1. **No Long-term Forward Secrecy**: Compromise of the master key exposes all past sessions. The protocol provides forward secrecy within a session (via key evolution), but not across sessions.

2. **No Server Authentication Against Compromise**: If the server is compromised, an attacker can impersonate it to clients. Mutual authentication exists, but assumes both parties are secure.

3. **DoS Vulnerability**: An adversary can always drop packets at the network layer (denial-of-service). The protocol detects drops via timeouts but cannot prevent them.

4. **No Public Key Infrastructure**: Requires symmetric pre-shared keys. Lacks the flexibility and scalability of PKI-based systems.

5. **Limited Scalability**: Master keys must be provisioned manually for each client. Not suitable for large-scale dynamic client populations.

### Not Defended Against

- **Traffic Analysis**: Message sizes, timing patterns, and connection metadata are observable
- **Network-Layer DoS**: Flooding, bandwidth exhaustion (out of protocol scope)
- **Endpoint Compromise**: If client or server is compromised, security guarantees void
- **Side-Channel Attacks**: Timing attacks, power analysis (implementation-specific, out of scope)

---

## Testing

### Automated Test Suite
```bash
python3 run_all_tests.py
```

Runs comprehensive tests including:
- Protocol state machine validation
- Cryptographic primitive correctness
- Multi-client scenarios
- Attack resistance verification

### Manual Testing
```bash
# Terminal 1: Server
python3 server.py

# Terminal 2: Client 1
python3 client.py 1

# Terminal 3: Attack simulation
python3 attacks.py
```

### Interactive Attack Tool
```bash
python3 manual_attacks.py
```

Features:
- Replay attack crafting
- Message modification
- Key desynchronization injection
- Custom message injection
- MITM simulation

---

## Project Structure

```
.
├── server.py                 # Multi-client server
├── client.py                 # Client implementation
├── crypto_utils.py           # Cryptographic primitives
├── protocol_fsm.py           # State machine & key evolution
├── attacks.py                # Automated attack demonstrations
├── manual_attacks.py         # Interactive attack tool
├── test_system.py            # Integration testing
├── run_all_tests.py          # Comprehensive test runner
├── logger.py                 # Colored logging utilities
├── requirements.txt          # Python dependencies
├── run.sh                    # Quick start script
├── README.md                 # This file
├── SECURITY.md               # Security analysis
└── IMPLEMENTATION_GUIDE.md   # Technical implementation details
```

---

## Implementation Highlights

### 1. Strict State Management
- Session phases: **INIT → ACTIVE → TERMINATED**
- FSM validates all opcode transitions
- Invalid transitions cause immediate termination

### 2. Atomic Key Evolution
- Keys evolve only after successful message exchange
- Failures do not update keys (prevents desynchronization)
- Deterministic evolution ensures client-server synchronization

### 3. Encrypt-then-MAC
- HMAC verification **before** decryption
- Prevents padding oracle attacks
- Protects against ciphertext tampering

### 4. Manual PKCS#7 Padding
- Explicit padding implementation (no library shortcuts)
- Validation detects tampering
- Conforms to assignment requirements

### 5. Multi-threaded Server
- Handles multiple concurrent clients
- Per-client session state
- Thread-safe aggregation with locking

---

## Troubleshooting

### Common Issues

**Issue**: `ModuleNotFoundError: No module named 'Crypto'`  
**Solution**: Install pycryptodome:
```bash
pip install pycryptodome
```

**Issue**: `Address already in use`  
**Solution**: Kill existing server process:
```bash
pkill -f server.py
# Or on Windows: taskkill /F /IM python.exe
```

**Issue**: Client connection refused  
**Solution**: Ensure server is running first:
```bash
python3 server.py  # Start this first
python3 client.py 1  # Then start clients
```

**Issue**: HMAC verification failures  
**Solution**: Ensure client ID matches server's master key database (valid IDs: 1-5)

---

## Assignment Compliance

This implementation fulfills all assignment requirements:

✅ **Stateful Protocol**: Round tracking, key evolution, phase management  
✅ **Manual PKCS#7**: Explicit padding implementation  
✅ **Encrypt-then-MAC**: HMAC before decryption  
✅ **Key Evolution**: Deterministic ratcheting after each round  
✅ **Attack Resistance**: 10+ attack scenarios demonstrated  
✅ **Multi-Client Aggregation**: Server-side secure aggregation  
✅ **Error Handling**: HMAC failures, replays, reordering, desync  
✅ **No Forbidden Libraries**: No AES-GCM, no automatic padding  
✅ **Documentation**: README.md and SECURITY.md provided  

---

## References

- **PKCS#7 Padding**: RFC 5652
- **HMAC**: RFC 2104
- **AES-CBC**: NIST FIPS 197
- **Key Derivation**: RFC 5869 (HKDF)

---

## Authors

**IIIT Hyderabad - CS5.470 System and Network Security**  
Lab Assignment 1 - January 2026

---

## License

This project is submitted as part of academic coursework at IIIT Hyderabad.  
**Academic Integrity**: Do not copy or redistribute without permission.

---

*For detailed security analysis, see [SECURITY.md](SECURITY.md)*  
