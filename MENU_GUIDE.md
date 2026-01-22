# Quick Reference - Menu Options

## Running the System

```bash
./run.sh
```

## Menu Options

### 1. Run complete demonstration (recommended)
- **What it does**: Runs the full automated test system
- **Demonstrates**: Server startup, multiple clients, data exchange, aggregation
- **Use when**: You want to see the entire system working end-to-end
- **Duration**: ~30 seconds

### 2. Start server only
- **What it does**: Starts the server on 127.0.0.1:9999
- **Use when**: You want to manually run clients or attacks in separate terminals
- **Note**: Server runs until you press Ctrl+C

### 3. Start client
- **What it does**: Starts a single client (you choose client ID 1-5)
- **Interactive**: Prompts you to enter comma-separated numbers
- **Use when**: You want to manually send data to test aggregation
- **Example input**: `10.5, 20.3, 30.1` or `100,200,300`

### 4. Run automated attack demonstrations (9 attacks)
- **What it does**: Runs all 9 required attacks automatically
- **Attacks demonstrated**:
  - **Core Adversarial (5)**: Replay, Message Modification, Message Reordering, Packet Dropping, Reflection
  - **Protocol-Specific (4)**: Key Desynchronization, Padding Tampering, Invalid HMAC, State Violations
- **Prerequisites**: Server must be running in another terminal
- **Duration**: ~2-3 minutes
- **Output**: Shows each attack and whether protocol successfully defends against it

### 5. Run manual attack tool (interactive)
- **What it does**: Launches interactive attack tool with menu
- **Features**: 7 different attack modes you can trigger manually
- **Use when**: You want fine-grained control over attacks
- **Prerequisites**: Server must be running in another terminal

### 6. Verify attack implementation
- **What it does**: Checks that all 9 required attacks are implemented
- **Output**: Shows checklist of all attacks with ✅ marks
- **Use when**: You want to verify completeness before submission
- **No prerequisites**: Just verification, doesn't run attacks

### 7. Test round-by-round aggregation
- **What it does**: Demonstrates proper per-round aggregation with 2 clients
- **Shows**: How each round's aggregate is independent
- **Example**: 
  - Client 1 Round 1: [10,20,30] → 20.00
  - Client 2 Round 1: [1,2,3] → 11.00 (aggregates both clients)
  - Client 2 Round 2: [15,25,35] → 25.00
  - Client 1 Round 2: [100,200,300] → 112.50 (aggregates both clients)

### 8. Test client disconnection behavior
- **What it does**: Verifies disconnected clients are excluded from aggregations
- **Demonstrates**: 
  - Client connects and sends data
  - Client disconnects
  - New client connects → aggregate excludes disconnected client
- **Use when**: You want to verify dynamic client handling

### 9. Exit
- **What it does**: Exits the menu

## Quick Commands (without menu)

```bash
# Verify attacks
./venv/bin/python verify_attacks.py

# Run server
./venv/bin/python server.py

# Run client (manual input)
./venv/bin/python client.py 1

# Run all attacks
./venv/bin/python attacks.py

# Test aggregation
./venv/bin/python test_round_aggregation.py

# Test disconnection
./venv/bin/python test_disconnect_aggregation.py
```

## For Development/Debugging

```bash
# Run specific test
./venv/bin/python test_system.py

# Check for errors
./venv/bin/python -m py_compile *.py

# View logs (if running server in background)
tail -f server.log  # if you redirect output to a log file
```

## Tips

- **Always start server first** when testing attacks or manual clients
- **Use separate terminals** for server and clients
- **Ctrl+C** stops any running process
- **Check the output carefully** - server logs show aggregation details
- **Port 9999** must be free (kill any process using it if needed)
