#!/bin/bash
# Quick start script for the SNS Lab Assignment

echo "=========================================="
echo "  SNS Lab 1 - Quick Start"
echo "=========================================="
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
# We will use explicit paths to ensure we use the venv
VENV_PYTHON="./venv/bin/python"
VENV_PIP="./venv/bin/pip"

if [ ! -f "$VENV_PYTHON" ]; then
    echo "Virtual environment seems incomplete. Recreating..."
    rm -rf venv
    python3 -m venv venv
fi

# Install dependencies
echo "Installing dependencies..."
$VENV_PIP install -r requirements.txt -q

echo ""
echo "Setup complete! Choose an option:"
echo ""
echo "1. Run complete demonstration (recommended)"
echo "2. Start server only"
echo "3. Start client (you'll be asked for client ID)"
echo "4. Run automated attack demonstrations"
echo "5. Run manual attack tool (interactive)"
echo "6. Exit"
echo ""
read -p "Enter choice (1-6): " choice

case $choice in
    1)
        echo ""
        echo "Running complete demonstration..."
        $VENV_PYTHON test_system.py
        ;;
    2)
        echo ""
        echo "Starting server on 127.0.0.1:9999..."
        echo "Press Ctrl+C to stop"
        $VENV_PYTHON server.py
        ;;
    3)
        read -p "Enter client ID (1-5): " client_id
        echo ""
        echo "Starting client $client_id..."
        echo "You will be prompted to enter comma-separated numbers"
        echo "Press Ctrl+C to exit"
        echo ""
        $VENV_PYTHON client.py $client_id
        ;;
    4)
        echo ""
        echo "Running automated attack demonstrations..."
        echo "Make sure the server is running in another terminal!"
        echo ""
        read -p "Press Enter to continue..."
        $VENV_PYTHON attacks.py
        ;;
    5)
        echo ""
        echo "Starting manual attack tool (interactive)..."
        echo "Make sure the server is running in another terminal!"
        echo ""
        read -p "Press Enter to continue..."
        $VENV_PYTHON manual_attacks.py
        ;;
    6)
        echo ""
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice"
        ;;
esac
