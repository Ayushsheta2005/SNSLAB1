# Secure Multi-Client Communication with Symmetric Keys

## Project Overview

This project implements a stateful, symmetric-key-based secure communication protocol between a server and multiple clients, designed to operate in a hostile network environment. The implementation emphasizes protocol state management, key evolution (ratcheting), and resistance to various cryptographic attacks.

## System Architecture

### Components

1. **crypto_utils.py**: Core cryptographic primitives
   - AES-128-CBC encryption/decryption
   - Manual PKCS#7 padding/unpadding
   - HMAC-SHA256 authentication
   - Key derivation and evolution

2. **protocol_fsm.py**: Protocol state machine
   - Session state management
   - Key evolution (ratcheting)
   - Round tracking
   - Opcode validation
   - Phase transitions

3. **server.py**: Multi-client server implementation
   - Handles multiple simultaneous clients
   - Maintains per-client session state
   - Performs secure aggregation
   - Enforces protocol constraints

4. **client.py**: Client implementation
   - Initiates secure sessions
   - Sends encrypted data
   - Validates server responses
   - Maintains synchronization

5. **attacks.py**: Attack demonstrations
   - Simulates 9 different attack scenarios
   - Demonstrates protocol security properties
   - Covers both adversarial and protocol-specific attacks

6. **manual_attacks.py**: Interactive attack tool
   - Manual attack testing interface
   - Custom message crafting
   - MITM simulation

## Requirements

### Python Version
- Python 3.7 or higher

### Dependencies
```bash
pip install pycryptodome
```

## Installation

1. Clone or download the project files
2. Install dependencies:
```bash
pip install pycryptodome
```

## Usage

### Starting the Server

Open a terminal and run:
```bash
python server.py
```

The server will start listening on `127.0.0.1:9999` and handle multiple clients concurrently.

### Running Clients

Open separate terminals for each client:

```bash
# Client 1
python client.py 1

# Client 2
python client.py 2

# Client 3
python client.py 3
```

Each client will:
1. Connect to the server
2. Perform handshake (CLIENT_HELLO → SERVER_CHALLENGE)
3. Send data in multiple rounds
4. Receive aggregated results from the server

### Running Attack Demonstrations

Ensure the server is running, then:

**Automated Attacks:**
```bash
python attacks.py
```

This will demonstrate 9 different attack scenarios:
- **Core Adversarial Attacks**: Replay, Message Modification, Message Reordering, Packet Dropping, Reflection
- **Protocol-Specific Failures**: Key Desynchronization, Padding Tampering, Invalid HMACs, State Violations

**Manual Interactive Attacks:**
```bash
python manual_attacks.py
```

**Verify All Attacks Are Implemented:**
```bash
python verify_attacks.py
```

## Protocol Flow

### Phase 1: Initialization (Round 0)
```
Client → Server: CLIENT_HELLO (encrypted with C2S_Enc_0, authenticated with C2S_Mac_0)
Server → Client: SERVER_CHALLENGE (encrypted with S2C_Enc_0, authenticated with S2C_Mac_0)
```

### Phase 2: Active Communication (Rounds 1, 2, ...)
```
Client → Server: CLIENT_DATA (encrypted data)
Server → Client: SERVER_AGGR_RESPONSE (aggregated results)
```

After each round, keys evolve:
- C2S_Enc_{R+1} = H(C2S_Enc_R || Ciphertext_R)
- C2S_Mac_{R+1} = H(C2S_Mac_R || Nonce_R)
- S2C_Enc_{R+1} = H(S2C_Enc_R || AggregatedData_R)
- S2C_Mac_{R+1} = H(S2C_Mac_R || StatusCode_R)

## Message Format

```
| Opcode (1 byte) | Client ID (1 byte) | Round (4 bytes) | Direction (1 byte) | 
| IV (16 bytes) | Ciphertext (variable) | HMAC (32 bytes) |
```

- **Opcode**: Operation type (CLIENT_HELLO=10, SERVER_CHALLENGE=20, etc.)
- **Client ID**: Unique client identifier (1-255)
- **Round**: Current round number (0, 1, 2, ...)
- **Direction**: CLIENT_TO_SERVER (1) or SERVER_TO_CLIENT (2)
- **IV**: Random initialization vector for AES-CBC
- **Ciphertext**: Encrypted payload (padded with PKCS#7)
- **HMAC**: Authentication tag over header + ciphertext

## Security Features

### 1. Confidentiality
- AES-128-CBC encryption with random IVs
- Separate encryption keys for each direction
- Keys evolve after each message

### 2. Integrity & Authentication
- HMAC-SHA256 over entire message
- Verification before decryption
- Separate MAC keys for each direction

### 3. Freshness & Replay Protection
- Round numbers strictly enforced
- Messages must match expected round
- Keys evolve, making old messages invalid

### 4. Key Evolution (Ratcheting)
- Keys update after each successful round
- Forward secrecy properties
- Desynchronization detection

### 5. State Management
- Explicit protocol phases (INIT, ACTIVE, TERMINATED)
- Strict FSM transitions
- Session termination on any violation

## Testing Multiple Clients

To test with multiple clients simultaneously:

1. Start the server:
```bash
python server.py
```

2. In separate terminals, start multiple clients:
```bash
# Terminal 1
python client.py 1

# Terminal 2
python client.py 2

# Terminal 3
python client.py 3
```

The server will aggregate data from all active clients and send personalized encrypted responses.

## Pre-Configured Master Keys

The following client IDs are pre-configured:
- Client 1: `client1_master_k`
- Client 2: `client2_master_k`
- Client 3: `client3_master_k`
- Client 4: `client4_master_k`
- Client 5: `client5_master_k`

**Note**: In production, these should be securely generated and distributed.

## Troubleshooting

### Connection Refused
- Ensure the server is running before starting clients
- Check that the port 9999 is not in use

### Session Terminated
- This is expected behavior when attacks are detected
- Check server logs for specific error messages

### HMAC Verification Failed
- Indicates message tampering or key desynchronization
- Session will be automatically terminated

## Project Structure

```
SNSLAB1/
├── crypto_utils.py       # Cryptographic primitives
├── protocol_fsm.py       # Protocol state machine
├── server.py            # Server implementation
├── client.py            # Client implementation
├── attacks.py           # Automated attack demonstrations (9 attacks)
├── manual_attacks.py    # Interactive attack tool
├── verify_attacks.py    # Attack implementation verification
├── test_system.py       # Automated system testing
├── test_round_aggregation.py  # Round-by-round aggregation test
├── run.sh               # Menu-driven launcher script
├── README.md            # This file
├── SECURITY.md          # Security analysis
├── ATTACKS_SUMMARY.md   # Attack implementation details
├── IMPLEMENTATION_GUIDE.md  # Detailed implementation guide
└── QUICK_START.md       # Quick start guide
```

## Development Notes

### Extending the Protocol

To add new opcodes:
1. Add to `Opcode` enum in `protocol_fsm.py`
2. Update `VALID_TRANSITIONS` in `ProtocolFSM`
3. Implement handlers in server and client

### Custom Aggregation

Modify `compute_aggregation()` in `server.py` to implement custom aggregation logic (e.g., sum, median, weighted average).

## License

This is an academic project for System and Network Security course.

## Authors

[Your Group Number and Names]

## Acknowledgments

- IIIT Hyderabad CS5.470 Course
- System and Network Security Lab Assignment 1