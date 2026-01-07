#!/bin/bash

echo "========================================"
echo "Starting Go Chatroom Server..."
echo "========================================"
echo ""

cd "$(dirname "$0")/go-server" || exit 1

# If compiled binary exists, use it for faster startup
if [ -f "chatroom-server" ]; then
    echo "Using compiled binary (instant startup)..."
    ./chatroom-server
    exit $?
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed"
    echo "   Install Go from: https://go.dev/dl/"
    echo ""
    echo "TIP: Compile a binary for faster startup:"
    echo "   cd go-server && go build -o chatroom-server ."
    exit 1
fi

# Download dependencies if needed
if [ ! -f "go.sum" ]; then
    echo "Downloading Go dependencies..."
    go mod download
fi

# Run the server
echo "Starting server from source..."
echo "TIP: Compile for faster startup: cd go-server && go build -o chatroom-server ."
go run .
