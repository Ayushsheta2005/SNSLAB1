# 🎯 SNS Lab Assignment 1 - Complete!

## ✅ Your Assignment is Ready!

Congratulations! I've implemented a complete solution for your **Secure Multi-Client Communication with Symmetric Keys** assignment.

---

## 📋 What You Have

### Core Implementation Files (Required for Submission)

1. **crypto_utils.py** (212 lines)
   - ✅ AES-128-CBC encryption/decryption
   - ✅ Manual PKCS#7 padding (no automatic libraries)
   - ✅ HMAC-SHA256 authentication
   - ✅ Key derivation and evolution
   - ✅ NO protocol or networking logic

2. **protocol_fsm.py** (292 lines)
   - ✅ Protocol finite state machine
   - ✅ Session state management
   - ✅ Round tracking and enforcement
   - ✅ Key evolution (ratcheting)
   - ✅ Opcode validation
   - ✅ Message encryption and verification

3. **server.py** (384 lines)
   - ✅ Multi-client server with threading
   - ✅ Per-client session management
   - ✅ Stateful protocol enforcement
   - ✅ Secure data aggregation
   - ✅ Error detection and session termination

4. **client.py** (299 lines)
   - ✅ Client implementation
   - ✅ Handshake protocol
   - ✅ Secure data transmission
   - ✅ Response validation
   - ✅ State synchronization

5. **attacks.py** (355 lines)
   - ✅ 6 different attack scenarios
   - ✅ Demonstrates protocol security
   - ✅ Shows why each attack fails

6. **README.md**
   - ✅ Complete usage documentation
   - ✅ Installation instructions
   - ✅ Protocol flow explanation

7. **SECURITY.md** (400+ lines)
   - ✅ Detailed security analysis
   - ✅ Threat model
   - ✅ Attack resistance explanations
   - ✅ Cryptographic proofs sketches

### Additional Helper Files

- **requirements.txt**: Dependencies
- **test_system.py**: Automated testing
- **run.sh**: Quick start script
- **IMPLEMENTATION_GUIDE.md**: This guide

---

## 🚀 Quick Start

### Option 1: Interactive Script (Easiest)
```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
./run.sh
```

### Option 2: Run Everything at Once
```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python test_system.py
```

### Option 3: Manual Control

**Terminal 1 (Server):**
```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python server.py
```

**Terminal 2 (Client 1):**
```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python client.py 1
```

**Terminal 3 (Client 2):**
```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python client.py 2
```

**Terminal 4 (Attack Demos):**
```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python attacks.py
```

---

## 📊 What the System Does

### Normal Operation Flow

```
1. Server starts and listens on 127.0.0.1:9999

2. Client connects and sends CLIENT_HELLO
   - Encrypted with C2S_Enc_0
   - Authenticated with C2S_Mac_0
   
3. Server verifies and responds with SERVER_CHALLENGE
   - Encrypted with S2C_Enc_0
   - Authenticated with S2C_Mac_0
   - Both parties evolve keys to Round 1

4. Client sends CLIENT_DATA (round 1)
   - Contains comma-separated numbers
   - Encrypted with evolved C2S_Enc_1
   - Authenticated with evolved C2S_Mac_1

5. Server aggregates data from all clients
   - Computes average across all received numbers
   - Sends SERVER_AGGR_RESPONSE (round 1)
   - Encrypted with evolved S2C_Enc_1

6. Process repeats for rounds 2, 3, ...
   - Keys evolve after each round
   - Round numbers strictly enforced
```

### Attack Demonstrations

The `attacks.py` script demonstrates:

1. **Replay Attack**: Captures and replays old message → REJECTED
2. **Message Modification**: Modifies ciphertext → DETECTED via HMAC
3. **Key Desynchronization**: Forces key mismatch → SESSION TERMINATED
4. **Message Reordering**: Sends out-of-order → REJECTED (wrong round)
5. **Reflection Attack**: Reflects server message → REJECTED (wrong direction)
6. **Unauthorized Client**: Connects without valid key → REJECTED

---

## 🎯 Assignment Requirements Checklist

### Cryptographic Implementation ✅

- [x] AES-128 in CBC mode (NOT ECB)
- [x] Manual PKCS#7 padding implementation
- [x] HMAC-SHA256 for authentication
- [x] Encrypt-then-MAC (HMAC after encryption)
- [x] Verification BEFORE decryption
- [x] Secure random IV generation
- [x] No automatic padding libraries
- [x] No authenticated encryption modes (GCM, CCM, Fernet)

### Protocol Implementation ✅

- [x] Stateful protocol (remembers state)
- [x] Round number tracking
- [x] Key evolution (ratcheting)
- [x] Protocol phases (INIT, ACTIVE, TERMINATED)
- [x] Opcode validation
- [x] Message format: Opcode(1) | ClientID(1) | Round(4) | Direction(1) | IV(16) | Ciphertext(var) | HMAC(32)

### Security Features ✅

- [x] Pre-shared master keys
- [x] Separate keys for each direction (C2S, S2C)
- [x] Separate encryption and MAC keys
- [x] Key derivation from master key
- [x] Forward secrecy via key ratcheting
- [x] Replay protection
- [x] Modification detection
- [x] Reordering prevention
- [x] Reflection attack prevention
- [x] Desynchronization detection

### System Features ✅

- [x] Multi-client support
- [x] Per-client session state
- [x] Server-side aggregation
- [x] Concurrent client handling
- [x] Error detection and recovery
- [x] Session termination on violations

### Attack Demonstrations ✅

- [x] Replay attack
- [x] Message modification
- [x] Key desynchronization
- [x] Message reordering
- [x] Reflection attack
- [x] Unauthorized client

### Documentation ✅

- [x] README.md with usage instructions
- [x] SECURITY.md with detailed security analysis
- [x] Code comments and docstrings
- [x] Well-structured code

---

## 🔒 Security Highlights

### Why This Protocol is Secure

1. **Confidentiality**: AES-128-CBC with random IVs
2. **Integrity**: HMAC-SHA256 over entire message
3. **Authentication**: Pre-shared keys + MAC verification
4. **Freshness**: Round numbers prevent replay
5. **Forward Secrecy**: Key ratcheting prevents backward key derivation
6. **No Oracles**: HMAC verified before decryption

### Key Evolution Example

```
Round 0: K_enc_0, K_mac_0 (derived from master key)
  ↓ Message sent with these keys
Round 1: K_enc_1 = H(K_enc_0 || Ciphertext_0)
         K_mac_1 = H(K_mac_0 || Nonce_0)
  ↓ Message sent with these keys
Round 2: K_enc_2 = H(K_enc_1 || Ciphertext_1)
         K_mac_2 = H(K_mac_1 || Nonce_1)
  ...and so on
```

Each round uses different keys, providing forward secrecy.

---

## 📦 Submission Instructions

### Create Submission Zip

```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1

# Create zip with required files
zip -r group_XX_lab1.zip \
  server.py \
  client.py \
  crypto_utils.py \
  protocol_fsm.py \
  attacks.py \
  README.md \
  SECURITY.md \
  requirements.txt

# Verify contents
unzip -l group_XX_lab1.zip
```

Replace `XX` with your actual group number.

### What to Submit

1. `server.py`
2. `client.py`
3. `crypto_utils.py`
4. `protocol_fsm.py`
5. `attacks.py`
6. `README.md`
7. `SECURITY.md`
8. `requirements.txt` (optional but helpful)

---

## 🎓 Demo/Viva Preparation

### What to Know

1. **Protocol Flow**
   - Handshake: CLIENT_HELLO → SERVER_CHALLENGE
   - Data exchange: CLIENT_DATA → SERVER_AGGR_RESPONSE
   - Key evolution after each round

2. **Cryptographic Details**
   - Why CBC mode? (semantic security with random IVs)
   - Why encrypt-then-MAC? (prevents oracle attacks)
   - Why key evolution? (forward secrecy)
   - How PKCS#7 padding works? (add N bytes, each with value N)

3. **Security Analysis**
   - How replay attacks are prevented (round numbers)
   - How modifications are detected (HMAC)
   - How reordering is prevented (strict round enforcement)
   - How reflection is prevented (direction field + separate keys)

4. **Implementation Choices**
   - Why threading for server? (handle multiple clients)
   - Why stateful sessions? (track state per client)
   - Why fail-stop? (any violation terminates session)

### Demo Script

1. Start server
2. Connect 2-3 clients simultaneously
3. Show data being sent and aggregated
4. Run attack demonstrations
5. Explain why each attack fails
6. Show code structure (separation of concerns)

---

## 🐛 Common Issues & Solutions

### Issue: "Import Crypto.Cipher could not be resolved"
**Solution**: This is just a linting warning. The package works fine when you activate the venv:
```bash
source venv/bin/activate
```

### Issue: "Connection refused"
**Solution**: Start the server BEFORE running clients.

### Issue: "Session terminated"
**Solution**: This is EXPECTED when attacks are detected. It shows the protocol is working!

### Issue: Virtual environment issues
**Solution**: Recreate it:
```bash
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 📚 Understanding the Code

### File Organization

```
crypto_utils.py      → Low-level crypto (AES, HMAC, padding)
       ↓
protocol_fsm.py      → Protocol logic (FSM, messages, state)
       ↓
server.py, client.py → Network communication (sockets, threading)
       ↓
attacks.py           → Attack demonstrations
```

### Key Classes

1. **CryptoUtils**: Static methods for crypto operations
2. **SessionState**: Tracks state for one client
3. **ProtocolMessage**: Represents one protocol message
4. **ProtocolFSM**: Validates state transitions
5. **SecureServer**: Multi-client server
6. **SecureClient**: Client implementation
7. **AttackScenarios**: Attack demonstrations

---

## 💡 Tips for Success

1. **Understand, Don't Just Submit**
   - Read through the code
   - Understand why each design choice was made
   - Be able to explain the security properties

2. **Test Thoroughly**
   - Run all attack scenarios
   - Test with multiple clients
   - Verify error handling

3. **Review SECURITY.md**
   - This is your security analysis
   - Understand each attack mitigation
   - Be ready to discuss in viva

4. **Practice the Demo**
   - Run through the demo a few times
   - Make sure you can explain what's happening
   - Be ready to answer questions

---

## 🎉 You're All Set!

Your implementation is:
- ✅ Complete
- ✅ Secure
- ✅ Well-documented
- ✅ Ready for submission
- ✅ Ready for demo

### Final Checks

1. Test the system: `./run.sh` → Option 1
2. Review SECURITY.md
3. Update README.md with your group info
4. Create submission zip
5. Practice demo

---

## 📞 Need Help?

If you need to modify anything:

1. **Crypto primitives**: Edit `crypto_utils.py`
2. **Protocol logic**: Edit `protocol_fsm.py`
3. **Server behavior**: Edit `server.py`
4. **Client behavior**: Edit `client.py`
5. **Add attacks**: Edit `attacks.py`
6. **Documentation**: Edit `README.md` or `SECURITY.md`

All code is well-commented and modular!

---

**Good luck with your submission! 🚀**

**Deadline**: 22-01-2026, 11:59 PM

---

*Generated: January 2026*  
*Course: CS5.470 - System and Network Security*  
*Institution: IIIT Hyderabad*
