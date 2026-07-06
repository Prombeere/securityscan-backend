#!/bin/bash
# Install Go security tools on Replit
# Run this once in the Replit Shell: bash tools/install_go_tools.sh

set -e

echo "=== Installing Go Tools ==="

# Create local bin directory
mkdir -p $HOME/.local/bin
export PATH=$HOME/.local/bin:$PATH

# Check if Go is available
if ! command -v go &> /dev/null; then
    echo "ERROR: Go not found. Install via Replit Tools."
    exit 1
fi

echo "Go version: $(go version)"

# Install gobuster (directory brute force)
if ! command -v gobuster &> /dev/null; then
    echo "Installing gobuster..."
    go install github.com/OJ/gobuster/v3@latest
    cp $(go env GOPATH)/bin/gobuster $HOME/.local/bin/ 2>/dev/null || true
    echo "gobuster installed"
else
    echo "gobuster already installed"
fi

# Install ffuf (fast web fuzzer)
if ! command -v ffuf &> /dev/null; then
    echo "Installing ffuf..."
    go install github.com/ffuf/ffuf/v2@latest
    cp $(go env GOPATH)/bin/ffuf $HOME/.local/bin/ 2>/dev/null || true
    echo "ffuf installed"
else
    echo "ffuf already installed"
fi

# Install httpx (fast HTTP prober)
if ! command -v httpx &> /dev/null; then
    echo "Installing httpx..."
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    cp $(go env GOPATH)/bin/httpx $HOME/.local/bin/ 2>/dev/null || true
    echo "httpx installed"
else
    echo "httpx already installed"
fi

echo "=== Go Tools Ready ==="
echo "Tools in: $HOME/.local/bin"
echo "Add to PATH: export PATH=\$HOME/.local/bin:\$PATH"
