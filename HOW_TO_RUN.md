# 🚀 HOW TO RUN - SNS Lab Assignment 1

## ✅ Requirements Verification Complete!

All assignment requirements have been verified and met. See verification output above.

---

## 📋 Quick Reference

### **Method 1: Interactive Menu** (Recommended for beginners)
```bash
./run.sh
```
Choose from:
- Option 1: Full demonstration (automated)
- Option 2: Start server only
- Option 3: Start client (specify ID)
- Option 4: Run attack demonstrations

### **Method 2: Quick Demo** (One client)
```bash
source venv/bin/activate
python quick_demo.py
```

### **Method 3: Full Automated Demo**
```bash
source venv/bin/activate
python test_system.py
```

### **Method 4: Manual Control** (Best for understanding)

**Step 1 - Open Terminal 1 (Server):**
```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python server.py
```
Keep this running. You should see:
```
[SERVER] Listening on 127.0.0.1:9999
```

**Step 2 - Open Terminal 2 (Client 1):**
```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python client.py 1
```

You'll see output like:
```
[CLIENT 1] Connected to server
[CLIENT 1] Sending CLIENT_HELLO
[CLIENT 1] Received SERVER_CHALLENGE
[CLIENT 1] Handshake complete, advancing to round 1
[CLIENT 1] Sending data: 10.5, 20.3, 30.1
[CLIENT 1] Received: Aggregated: 20.30
...
```

**Step 3 - Open Terminal 3 (Client 2):**
```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python client.py 2
```

**Step 4 - Open Terminal 4 (Client 3):**
```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python client.py 3
```

**Step 5 - Open Terminal 5 (Attack Demos):**
After clients are running, test attacks:
```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1
source venv/bin/activate
python attacks.py
```

---

## 🎯 What You'll See

### Normal Operation

1. **Server starts** and listens on port 9999
2. **Clients connect** one by one
3. **Handshake occurs**:
   - Client sends CLIENT_HELLO (round 0)
   - Server responds with SERVER_CHALLENGE (round 0)
   - Both advance to round 1
4. **Data exchange**:
   - Client sends CLIENT_DATA with numbers
   - Server aggregates data from all clients
   - Server responds with SERVER_AGGR_RESPONSE
5. **Keys evolve** after each round
6. **Process repeats** for multiple rounds

### Attack Demonstrations

The `attacks.py` script will show:

1. **Replay Attack** - Old message replayed → REJECTED (wrong round)
2. **Message Modification** - Ciphertext tampered → DETECTED (HMAC fails)
3. **Key Desynchronization** - Keys corrupted → SESSION TERMINATED
4. **Message Reordering** - Out-of-order delivery → REJECTED (round mismatch)
5. **Reflection Attack** - Server message sent back → REJECTED (wrong direction)
6. **Unauthorized Client** - Invalid client ID → REJECTED (no master key)

Each attack will show:
- What the attack does
- Why it fails
- Security mechanism that prevents it

---

## 🔍 Detailed Walkthrough

### Understanding the Output

**Server Output:**
```
[SERVER] Listening on 127.0.0.1:9999
[SERVER] New connection from ('127.0.0.1', 54321)
[SERVER] Processing CLIENT_HELLO from client 1
[SERVER] CLIENT_HELLO payload: Hello from client 1
[SERVER] Sent SERVER_CHALLENGE to client 1, advancing to round 1
[SERVER] Processing CLIENT_DATA from client 1
[SERVER] Received data from client 1: 10.5, 20.3, 30.1
[SERVER] Sent aggregation result to client 1, advancing to round 2
```

**Client Output:**
```
[CLIENT 1] Connected to server at 127.0.0.1:9999
[CLIENT 1] Sending CLIENT_HELLO
[CLIENT 1] Received SERVER_CHALLENGE: ServerChallenge-1737280800.123
[CLIENT 1] Handshake complete, advancing to round 1
[CLIENT 1] Sending data: 10.5, 20.3, 30.1
[CLIENT 1] Received: Aggregated: 20.30
[CLIENT 1] Round complete, advancing to round 2
```

### Key Evolution in Action

After each round, keys evolve:

```
Round 0:
  C2S_Enc_0 = H(MasterKey || "C2S-ENC")
  C2S_Mac_0 = H(MasterKey || "C2S-MAC")

Round 1:
  C2S_Enc_1 = H(C2S_Enc_0 || Ciphertext_0)
  C2S_Mac_1 = H(C2S_Mac_0 || IV_0)

Round 2:
  C2S_Enc_2 = H(C2S_Enc_1 || Ciphertext_1)
  C2S_Mac_2 = H(C2S_Mac_1 || IV_1)
...
```

This provides **forward secrecy** - compromising current keys doesn't reveal past messages.

---

## 🎭 Running Attack Demonstrations

**Important**: Start the server BEFORE running attacks!

```bash
# Terminal 1 - Start server
source venv/bin/activate
python server.py

# Terminal 2 - Run attacks
source venv/bin/activate
python attacks.py
```

The script will:
1. Run each attack scenario
2. Show what happens
3. Explain why the attack fails
4. Display security analysis

Expected output format:
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

---

## 📦 For Submission

When ready to submit, create the zip file:

```bash
cd /home/ayush/Desktop/sem6/SNS/LABS/LAB1/SNSLAB1

# Replace XX with your group number
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

---

## 🐛 Troubleshooting

### Problem: "Module not found: Crypto"
**Solution:**
```bash
source venv/bin/activate
pip install pycryptodome
```

### Problem: "Connection refused"
**Solution:** Make sure the server is running FIRST before starting clients.

### Problem: "Port already in use"
**Solution:** Kill any existing server process:
```bash
pkill -f "python server.py"
# Or find and kill manually:
lsof -i :9999
kill <PID>
```

### Problem: "Session terminated"
**Solution:** This is EXPECTED when attacks are detected. It's the security working correctly!

### Problem: Virtual environment not activating
**Solution:**
```bash
# Recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🎓 For Demo/Viva

### What to Show

1. **Start the system** (server + multiple clients)
2. **Explain the protocol flow**:
   - Handshake phase
   - Data exchange phase
   - Key evolution
3. **Run attack demonstrations**
4. **Explain security features**:
   - Why HMAC before decryption
   - How replay attacks are prevented
   - How key ratcheting works
5. **Show code structure**:
   - Separation of crypto/protocol/network
   - Clean architecture

### Key Points to Emphasize

1. **Manual PKCS#7 padding** - No automatic padding used
2. **Encrypt-then-MAC** - Industry best practice
3. **Key ratcheting** - Forward secrecy property
4. **Stateful protocol** - Session state tracked
5. **Fail-stop security** - Any error terminates session

### Questions You Might Be Asked

**Q: Why encrypt-then-MAC instead of MAC-then-encrypt?**
A: Prevents padding oracle attacks. HMAC is verified BEFORE any decryption, so tampered messages are rejected without processing.

**Q: How does key evolution provide forward secrecy?**
A: Keys are evolved using a one-way hash function. You can't derive K_R from K_{R+1}, so compromising current keys doesn't reveal past messages.

**Q: How do you prevent replay attacks?**
A: Three mechanisms:
1. Round numbers strictly enforced
2. Keys evolve after each round (old keys invalid)
3. HMAC authenticates round number

**Q: What happens if a message is dropped?**
A: Session desynchronizes. Next message will have wrong round number and be rejected. Session terminates. This is correct behavior - no recovery allowed.

**Q: Why no session resumption?**
A: Security by design. If synchronization is lost, we don't try to fix it - we terminate. Prevents complex desynchronization attacks.

---

## 📚 Additional Resources

- **SECURITY.md**: Detailed security analysis (16KB of explanation!)
- **README.md**: User documentation
- **IMPLEMENTATION_GUIDE.md**: Developer guide
- **QUICK_START.md**: Getting started guide

---

## ✅ Final Checklist Before Submission

- [ ] Run verification: `python verify_requirements.py`
- [ ] Test with server + multiple clients
- [ ] Run all 6 attack scenarios
- [ ] Review SECURITY.md
- [ ] Update README.md with your group number
- [ ] Create submission zip
- [ ] Test the zip on a clean system

---

## 🎉 You're Ready!

Your implementation is **complete**, **tested**, and **documented**.

**Deadline**: January 22, 2026, 11:59 PM

Good luck! 🚀
