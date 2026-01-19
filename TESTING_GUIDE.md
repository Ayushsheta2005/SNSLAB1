# 🧪 MANUAL TESTING GUIDE - Based on Assignment Requirements

## What You're Testing

According to the assignment document, you need to verify:

1. ✅ **Stateful Protocol** - Server remembers state for each client
2. ✅ **Key Evolution** - Keys change after each round
3. ✅ **Round Tracking** - Messages with wrong round are rejected
4. ✅ **Attack Resistance** - All 6 mandatory attacks are mitigated
5. ✅ **Multi-Client Support** - Server handles multiple clients
6. ✅ **Secure Aggregation** - Server aggregates data and encrypts separately for each client

---

## 📋 TEST PLAN

### PART 1: Normal Operation (What SHOULD Happen)

#### Step 1: Start Server
```bash
# Terminal 1
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python server.py
```

**EXPECTED OUTPUT:**
```
[SERVER] Listening on 127.0.0.1:9999
```

**✅ VERIFY:**
- [ ] Server starts without errors
- [ ] Shows "Listening" message
- [ ] No crashes

---

#### Step 2: Connect Client 1
```bash
# Terminal 2
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python client.py 1
```

**EXPECTED OUTPUT (Client Side):**
```
[CLIENT 1] Connected to server at 127.0.0.1:9999
[CLIENT 1] Sending CLIENT_HELLO
[CLIENT 1] Received SERVER_CHALLENGE: ServerChallenge-<timestamp>
[CLIENT 1] Handshake complete, advancing to round 1
[CLIENT 1] Sending data: 10.5, 20.3, 30.1
[CLIENT 1] Received: Aggregated: 20.30
[CLIENT 1] Round complete, advancing to round 2
[CLIENT 1] Sending data: 11.5, 21.3, 31.1
[CLIENT 1] Received: Aggregated: 21.30
[CLIENT 1] Round complete, advancing to round 3
[CLIENT 1] Sending data: 12.5, 22.3, 32.1
[CLIENT 1] Received: Aggregated: 22.30
[CLIENT 1] Round complete, advancing to round 4
[CLIENT 1] Communication complete
[CLIENT 1] Disconnected from server
```

**EXPECTED OUTPUT (Server Side - Terminal 1):**
```
[SERVER] New connection from ('127.0.0.1', <port>)
[SERVER] Processing CLIENT_HELLO from client 1
[SERVER] CLIENT_HELLO payload: Hello from client 1
[SERVER] Sent SERVER_CHALLENGE to client 1, advancing to round 1
[SERVER] Processing CLIENT_DATA from client 1
[SERVER] Received data from client 1: 10.5, 20.3, 30.1
[SERVER] Sent aggregation result to client 1, advancing to round 2
[SERVER] Processing CLIENT_DATA from client 1
[SERVER] Received data from client 1: 11.5, 21.3, 31.1
[SERVER] Sent aggregation result to client 1, advancing to round 2
[SERVER] Processing CLIENT_DATA from client 1
[SERVER] Received data from client 1: 12.5, 22.3, 32.1
[SERVER] Sent aggregation result to client 1, advancing to round 3
[SERVER] Connection closed for ('127.0.0.1', <port>)
```

**✅ VERIFY (Assignment Requirements):**
- [ ] **Round 0**: CLIENT_HELLO → SERVER_CHALLENGE exchange completes
- [ ] **Round 1-3**: CLIENT_DATA → SERVER_AGGR_RESPONSE exchanges work
- [ ] Round numbers advance: 0 → 1 → 2 → 3
- [ ] All messages are encrypted (you see encrypted payload, not plaintext in network)
- [ ] Server processes messages correctly
- [ ] Client disconnects gracefully

**📝 What's Happening Under the Hood:**
```
Round 0:
  - Client uses C2S_Enc_0, C2S_Mac_0 to send CLIENT_HELLO
  - Server uses S2C_Enc_0, S2C_Mac_0 to send SERVER_CHALLENGE
  - Both evolve keys to _1

Round 1:
  - Client uses C2S_Enc_1, C2S_Mac_1 (evolved keys!)
  - Server uses S2C_Enc_1, S2C_Mac_1
  - Both evolve keys to _2

Round 2:
  - Client uses C2S_Enc_2, C2S_Mac_2
  - Server uses S2C_Enc_2, S2C_Mac_2
  - Keys keep evolving...
```

---

#### Step 3: Connect Client 2 (Multi-Client Test)
```bash
# Terminal 3
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python client.py 2
```

**EXPECTED OUTPUT (Client 2):**
```
[CLIENT 2] Connected to server at 127.0.0.1:9999
[CLIENT 2] Sending CLIENT_HELLO
[CLIENT 2] Received SERVER_CHALLENGE: ServerChallenge-<timestamp>
[CLIENT 2] Handshake complete, advancing to round 1
[CLIENT 2] Sending data: 10.5, 20.3, 30.1
[CLIENT 2] Received: Aggregated: <different_value>  ← NOW INCLUDES DATA FROM BOTH CLIENTS!
...
```

**✅ VERIFY (Multi-Client Requirement):**
- [ ] Server handles both clients simultaneously
- [ ] Each client has independent session state
- [ ] Each client has independent round numbers
- [ ] Each client uses different master keys
- [ ] **Aggregation includes data from BOTH clients**
- [ ] Aggregated value changes when second client connects

**📝 Aggregation Example:**
```
Only Client 1: Sends [10.5, 20.3, 30.1]
  → Average = (10.5 + 20.3 + 30.1) / 3 = 20.30

Client 1 + Client 2 both active:
  Client 1 data: [10.5, 20.3, 30.1]
  Client 2 data: [10.5, 20.3, 30.1]
  → Average = (10.5 + 20.3 + 30.1 + 10.5 + 20.3 + 30.1) / 6 = 20.30
  (But different if Client 2 sends different numbers)
```

---

#### Step 4: Connect Client 3 (Test Multi-Client Further)
```bash
# Terminal 4
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python client.py 3
```

**✅ VERIFY:**
- [ ] Third client connects successfully
- [ ] Server maintains 3 separate sessions
- [ ] Aggregation now includes all 3 clients
- [ ] Each client gets personalized encrypted response

---

### PART 2: Attack Demonstrations (What SHOULD Fail)

**⚠️ IMPORTANT**: Keep server running from Part 1!

```bash
# Terminal 5
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python attacks.py
```

**EXPECTED OUTPUT:**

#### Attack 1: Replay Attack
```
==============================================================
ATTACK SCENARIO 1: REPLAY ATTACK
==============================================================

[ATTACK] Sending legitimate message...
[ATTACK] Captured message of length 150
[ATTACK] Attempting to replay captured message...
[ATTACK] ✓ Server rejected replayed message (connection closed)

[ANALYSIS] The protocol rejects replay attacks because:
  1. Each message includes a round number
  2. Server tracks expected round per client
  3. Messages with wrong round are rejected
  4. Keys evolve after each round, making old messages invalid
```

**✅ VERIFY (Assignment Requirement: "Replay attacks"):**
- [ ] Legitimate message is sent successfully
- [ ] Replay of same message is REJECTED
- [ ] Server terminates session
- [ ] Reason: Round number mismatch

---

#### Attack 2: Message Modification
```
==============================================================
ATTACK SCENARIO 2: MESSAGE MODIFICATION ATTACK
==============================================================

[ATTACK] Sending message and modifying ciphertext...
[ATTACK] Modified byte at position 50: 123 -> 124
[ATTACK] ✓ Server rejected modified message

[ANALYSIS] The protocol detects modifications because:
  1. HMAC covers entire message (header + ciphertext)
  2. Any modification causes HMAC verification to fail
  3. Server terminates session on HMAC failure
  4. Decryption happens ONLY after HMAC verification
```

**✅ VERIFY (Assignment Requirement: "Modify ciphertexts and MACs"):**
- [ ] Modified message is sent
- [ ] Server detects modification via HMAC
- [ ] Session is terminated
- [ ] No decryption occurs (secure!)

---

#### Attack 3: Key Desynchronization
```
==============================================================
ATTACK SCENARIO 3: KEY DESYNCHRONIZATION ATTACK
==============================================================

[ATTACK] Sending legitimate message...
[ATTACK] Manually evolving client keys (causing desync)...
[ATTACK] Attempting to send with desynchronized keys...
[ATTACK] ✓ Protocol detected key desynchronization

[ANALYSIS] The protocol handles desynchronization by:
  1. Keys evolve deterministically on both sides
  2. Any state mismatch causes HMAC failure
  3. Session is immediately terminated
  4. No partial updates - keys evolve only after full success
```

**✅ VERIFY (Assignment Requirement: "Loss of synchronization must result in session termination"):**
- [ ] Key mismatch is detected
- [ ] HMAC verification fails
- [ ] Session terminates immediately
- [ ] No key recovery attempted

---

#### Attack 4: Message Reordering
```
==============================================================
ATTACK SCENARIO 4: MESSAGE REORDERING ATTACK
==============================================================

[ATTACK] This attack attempts to send messages out of order
[ATTACK] Sending message in round 1...
[ATTACK] Current round: 2
[ATTACK] Attempting to send message with round number 0...
[ATTACK] ✓ Server rejected out-of-order message

[ANALYSIS] The protocol prevents reordering by:
  1. Strict round number enforcement
  2. Messages must match expected round exactly
  3. Round numbers are authenticated via HMAC
  4. Cannot skip or repeat rounds
```

**✅ VERIFY (Assignment Requirement: "Drop or reorder packets"):**
- [ ] Out-of-order message sent
- [ ] Server expects specific round number
- [ ] Mismatch detected
- [ ] Session terminated

---

#### Attack 5: Reflection Attack
```
==============================================================
ATTACK SCENARIO 5: REFLECTION ATTACK
==============================================================

[ATTACK] Capturing server response...
[ATTACK] Captured server response of length 180
[ATTACK] Attempting to reflect server message back to server...
[ATTACK] ✓ Server rejected reflected message

[ANALYSIS] The protocol prevents reflection by:
  1. Messages include explicit direction field
  2. Server expects CLIENT_TO_SERVER direction
  3. Different keys for each direction (C2S vs S2C)
  4. Direction field is authenticated via HMAC
```

**✅ VERIFY (Assignment Requirement: "Reflect messages back to the sender"):**
- [ ] Server message captured
- [ ] Reflected back to server
- [ ] Server rejects (wrong direction)
- [ ] Different keys prevent reflection

---

#### Attack 6: Unauthorized Client
```
==============================================================
ATTACK SCENARIO 6: UNAUTHORIZED CLIENT ATTACK
==============================================================

[ATTACK] Attempting to connect with invalid client ID...
[ATTACK] ✓ Server rejected unauthorized client

[ANALYSIS] The protocol handles unauthorized clients by:
  1. Pre-shared master keys for authorized clients only
  2. Server validates client ID against key database
  3. Invalid clients cannot complete handshake
  4. No information leaked to unauthorized parties
```

**✅ VERIFY (Assignment Requirement: "Pre-shared symmetric master key"):**
- [ ] Unauthorized client attempts connection
- [ ] HMAC fails (wrong master key)
- [ ] Handshake fails
- [ ] Connection rejected

---

### PART 3: Message Format Verification

**Assignment Requirement:**
```
| Opcode (1) | Client ID (1) | Round (4) | Direction (1) | IV (16)|
| Ciphertext (variable) | HMAC (32) |
```

**✅ HOW TO VERIFY:**

The message format is correct if:
- [ ] Header is 23 bytes (1+1+4+1+16)
- [ ] HMAC is 32 bytes
- [ ] Total message = Header + Ciphertext + HMAC
- [ ] HMAC covers Header + Ciphertext (not plaintext!)

**You can verify by adding debug prints in protocol_fsm.py**

---

### PART 4: Cryptographic Requirements Check

#### Manual PKCS#7 Padding
**Check in crypto_utils.py lines 23-69:**
```python
def apply_pkcs7_padding(data: bytes) -> bytes:
    # Should have MANUAL implementation
    # NO use of Crypto.Util.Padding
    
def remove_pkcs7_padding(padded_data: bytes) -> bytes:
    # Should manually check padding bytes
    # Treat invalid padding as tampering
```

**✅ VERIFY:**
- [ ] Padding implemented manually (not using library)
- [ ] Padding always applied
- [ ] Each padding byte equals padding length
- [ ] Invalid padding raises ValueError

---

#### AES-128-CBC (Not ECB!)
**Check in crypto_utils.py lines 78-113:**
```python
def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)  # ← Should be CBC!
    return cipher.encrypt(plaintext)
```

**✅ VERIFY:**
- [ ] Mode is CBC (not ECB, GCM, CCM, Fernet)
- [ ] Fresh random IV for each message
- [ ] Key is exactly 16 bytes (AES-128)

---

#### HMAC-SHA256
**Check in crypto_utils.py lines 115-134:**
```python
def compute_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()
```

**✅ VERIFY:**
- [ ] Uses HMAC-SHA256
- [ ] HMAC output is 32 bytes
- [ ] Verification uses constant-time comparison

---

#### Encrypt-then-MAC Order
**Check in protocol_fsm.py lines 143-171:**
```python
def encrypt_and_sign(self, enc_key: bytes, mac_key: bytes):
    # 1. Pad plaintext
    # 2. Encrypt
    # 3. Compute HMAC over (Header + Ciphertext)  ← Correct!
    # 4. Return message
```

**✅ VERIFY:**
- [ ] Padding applied BEFORE encryption
- [ ] HMAC computed AFTER encryption
- [ ] HMAC covers ciphertext (not plaintext)

---

#### HMAC Verified Before Decryption
**Check in protocol_fsm.py lines 173-227:**
```python
def parse_and_verify(...):
    # 1. Extract HMAC
    # 2. Verify HMAC ← MUST BE FIRST!
    # 3. If fails, raise ValueError
    # 4. ONLY THEN decrypt
```

**✅ VERIFY:**
- [ ] HMAC checked BEFORE decryption
- [ ] HMAC failure raises exception immediately
- [ ] No decryption if HMAC fails (prevents oracle attacks)

---

#### Key Evolution
**Check in protocol_fsm.py lines 63-84:**
```python
def evolve_c2s_keys(self, ciphertext: bytes, nonce: bytes):
    self.c2s_enc_key = CryptoUtils.evolve_key(self.c2s_enc_key, ciphertext)
    self.c2s_mac_key = CryptoUtils.evolve_key(self.c2s_mac_key, nonce)
```

**✅ VERIFY:**
- [ ] Keys evolve after SUCCESSFUL message processing
- [ ] Uses hash function (SHA-256)
- [ ] Evolution is one-way (can't reverse)
- [ ] Separate evolution for enc and mac keys

---

### PART 5: Protocol Opcodes Check

**Assignment Requirement:**
```
10 - CLIENT_HELLO
20 - SERVER_CHALLENGE
30 - CLIENT_DATA
40 - SERVER_AGGR_RESPONSE
50 - KEY_DESYNC_ERROR
60 - TERMINATE
```

**✅ VERIFY in protocol_fsm.py lines 10-17:**
```python
class Opcode(IntEnum):
    CLIENT_HELLO = 10
    SERVER_CHALLENGE = 20
    CLIENT_DATA = 30
    SERVER_AGGR_RESPONSE = 40
    KEY_DESYNC_ERROR = 50
    TERMINATE = 60
```
- [ ] All 6 opcodes defined
- [ ] Correct values (10, 20, 30, 40, 50, 60)

---

## 📊 FINAL VERIFICATION CHECKLIST

Based on Assignment "Evaluation Criteria":

### Protocol Correctness
- [ ] Handshake works (CLIENT_HELLO → SERVER_CHALLENGE)
- [ ] Data exchange works (CLIENT_DATA → SERVER_AGGR_RESPONSE)
- [ ] Round numbers advance correctly
- [ ] Sessions terminate on errors

### Key Evolution Logic
- [ ] Keys derived from master key correctly
- [ ] Keys evolve after each round
- [ ] Separate keys for each direction (C2S, S2C)
- [ ] Separate encryption and MAC keys

### Attack Handling
- [ ] Replay attack detected and rejected
- [ ] Message modification detected (HMAC)
- [ ] Message reordering detected (round numbers)
- [ ] Key desynchronization detected
- [ ] Reflection attack prevented
- [ ] Unauthorized clients rejected

### Cryptographic Correctness
- [ ] AES-128-CBC used (not ECB)
- [ ] Manual PKCS#7 padding
- [ ] HMAC-SHA256
- [ ] Encrypt-then-MAC order
- [ ] HMAC verified before decryption
- [ ] Random IVs generated securely

### Code Quality
- [ ] Clean separation: crypto_utils.py has ONLY crypto
- [ ] Protocol logic in protocol_fsm.py
- [ ] Networking in server.py / client.py
- [ ] Well-documented
- [ ] No crashes or errors

### Documentation
- [ ] README.md complete
- [ ] SECURITY.md explains attack mitigations
- [ ] Code has comments

---

## 🎯 SUMMARY: What Should Happen

### ✅ SHOULD WORK:
1. Server starts and listens
2. Multiple clients connect simultaneously
3. Each client completes handshake
4. Data is encrypted and transmitted
5. Server aggregates data from all clients
6. Each client receives encrypted response
7. Keys evolve after each round
8. Round numbers advance correctly

### ❌ SHOULD FAIL:
1. Replayed messages rejected
2. Modified messages detected
3. Out-of-order messages rejected
4. Reflected messages rejected
5. Desynchronized sessions terminated
6. Unauthorized clients rejected

---

## 🚀 START TESTING NOW!

**Follow these steps in order:**

1. **Terminal 1**: Start server
2. **Terminal 2**: Start client 1, watch output
3. **Terminal 3**: Start client 2, verify aggregation changes
4. **Terminal 4**: Start client 3, verify multi-client works
5. **Terminal 5**: Run attacks, verify all fail

**Take notes of any issues and compare with expected output above!**
