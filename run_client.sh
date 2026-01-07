#!/bin/bash
# Simple launcher for the Python chatroom client

echo "Starting Chatroom CLI Client..."
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

# Check if cryptography is installed
if ! python3 -c "import cryptography" &> /dev/null; then
    echo "Warning: cryptography module not installed"
    echo "Messages will not be encrypted"
    echo "Install with: pip3 install cryptography"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Run the client
python3 chatroom-cli.py
