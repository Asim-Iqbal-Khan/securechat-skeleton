#!/bin/bash
# Test all security features
set -e

echo "=========================================="
echo "SecureChat Security Tests"
echo "=========================================="
echo ""

source .venv/bin/activate

echo "[*] Test 1: Certificate Validation"
echo "-----------------------------------"
python tests/test_cert.py
echo ""

echo "[*] Test 2: Replay Attack Detection"
echo "-----------------------------------"
python tests/test_replay.py
echo ""

echo "[*] Test 3: Tamper Detection"
echo "-----------------------------------"
python tests/test_tamper.py
echo ""

echo "=========================================="
echo "[✓] All tests completed!"
echo "=========================================="

