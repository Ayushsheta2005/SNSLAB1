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
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt -q

echo ""
echo "Setup complete! Choose an option:"
echo ""
echo "1. Run complete demonstration (recommended)"
echo "2. Start server only"
echo "3. Start client (you'll be asked for client ID)"
echo "4. Run attack demonstrations"
echo ""
read -p "Enter choice (1-4): " choice

case $choice in
    1)
        echo ""
        echo "Running complete demonstration..."
        python test_system.py
        ;;
    2)
        echo ""
        echo "Starting server on 127.0.0.1:9999..."
        echo "Press Ctrl+C to stop"
        python server.py
        ;;
    3)
        read -p "Enter client ID (1-5): " client_id
        echo ""
        echo "Starting client $client_id..."
        python client.py $client_id
        ;;
    4)
        echo ""
        echo "Make sure the server is running in another terminal!"
        read -p "Press Enter to continue..."
        python attacks.py
        ;;
    *)
        echo "Invalid choice"
        ;;
esac
