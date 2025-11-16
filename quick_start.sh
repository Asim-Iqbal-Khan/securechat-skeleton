#!/bin/bash
# Quick Start Script for SecureChat
set -e

echo "=========================================="
echo "SecureChat Quick Start"
echo "=========================================="
echo ""

# Activate virtual environment
if [ -d .venv ]; then
    echo "[*] Activating virtual environment..."
    source .venv/bin/activate
else
    echo "[!] Virtual environment not found. Creating one..."
    python3 -m venv .venv
    source .venv/bin/activate
    echo "[*] Installing dependencies..."
    pip install -r requirements.txt
fi

# Check and install dependencies
echo "[*] Checking dependencies..."
pip install -q -r requirements.txt

# Check certificates
if [ ! -f certs/ca_cert.pem ]; then
    echo ""
    echo "[*] Generating certificates..."
    python scripts/gen_ca.py --name "FAST-NU Root CA"
    python scripts/gen_cert.py --cn server.local --out certs/server --server
    python scripts/gen_cert.py --cn client.local --out certs/client
    echo "[✓] Certificates generated"
else
    echo "[✓] Certificates already exist"
fi

# Check database
echo ""
echo "[*] Checking database..."
if python -m app.storage.db --init 2>/dev/null; then
    echo "[✓] Database initialized"
else
    echo "[!] Database setup needed. Run: ./setup_mysql.sh"
fi

echo ""
echo "=========================================="
echo "[✓] Setup Complete!"
echo "=========================================="
echo ""
echo "To run the application:"
echo ""
echo "  Terminal 1 (Server):"
echo "    source .venv/bin/activate"
echo "    python -m app.server"
echo ""
echo "  Terminal 2 (Client):"
echo "    source .venv/bin/activate"
echo "    python -m app.client"
echo ""
echo "To run tests:"
echo "    python tests/test_cert.py"
echo "    python tests/test_replay.py"
echo "    python tests/test_tamper.py"
echo ""

