# Running and Testing SecureChat

Complete guide to set up, run, and test the SecureChat application.

## Prerequisites Checklist

- [x] Python 3.12.3 installed
- [x] Virtual environment exists
- [ ] All dependencies installed
- [ ] MySQL database set up
- [ ] Certificates generated
- [ ] .env file configured

## Step-by-Step Setup

### 1. Install Dependencies

```bash
# Activate virtual environment
source .venv/bin/activate

# Install all requirements
pip install -r requirements.txt
```

### 2. Set Up Database

```bash
# Option A: Use Docker (recommended)
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 \
  mysql:8

# Wait for MySQL to start
sleep 5

# Update .env with:
# DB_USER=scuser
# DB_PASSWORD=scpass
# DB_NAME=securechat

# Option B: Use local MySQL
./setup_mysql.sh
# OR manually create database and user
```

### 3. Initialize Database Schema

```bash
python -m app.storage.db --init
```

Expected output:
```
[✓] Database 'securechat' created/verified
[✓] Database schema initialized
```

### 4. Generate Certificates

```bash
# Generate Root CA
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Generate server certificate
python scripts/gen_cert.py --cn server.local --out certs/server --server

# Generate client certificate
python scripts/gen_cert.py --cn client.local --out certs/client
```

Expected output:
```
[✓] Root CA generated successfully!
[✓] Certificate generated successfully!
```

Verify certificates exist:
```bash
ls -la certs/
# Should see:
# - ca_cert.pem
# - ca_private_key.pem
# - server_cert.pem
# - server_private_key.pem
# - client_cert.pem
# - client_private_key.pem
```

### 5. Configure .env File

Make sure your `.env` file has:

```env
# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=scuser          # or securechat_user
DB_PASSWORD=scpass      # or your password
DB_NAME=securechat

# Server
SERVER_HOST=localhost
SERVER_PORT=5555
```

## Running the Application

### Terminal 1: Start Server

```bash
source .venv/bin/activate
python -m app.server
```

Expected output:
```
[*] Server initialized
[*] Certificate CN: server.local
[*] Fingerprint: ...
[✓] Server listening on localhost:5555
[*] Waiting for client connection...
```

### Terminal 2: Start Client

```bash
source .venv/bin/activate
python -m app.client
```

Expected flow:
1. Client connects
2. Certificate exchange
3. Choose Register or Login
4. Enter credentials
5. Chat session starts

## Testing Security Features

### Test 1: Certificate Validation

```bash
python tests/test_cert.py
```

Expected:
- [✓] Valid certificate: VALID
- [✓] Expired certificate: BAD_CERT
- [✓] Self-signed rejected: BAD_CERT

### Test 2: Replay Attack Detection

```bash
python tests/test_replay.py
```

Expected:
- [✓] Normal sequence: ACCEPTED
- [✓] Replayed message: REPLAY detected

### Test 3: Tamper Detection

```bash
python tests/test_tamper.py
```

Expected:
- [✓] Original signature VALID
- [✓] Tampered ciphertext: SIG_FAIL

### Test 4: Non-Repudiation (Receipt Verification)

After a chat session, verify receipts:

```bash
# Find transcript and receipt files
ls transcripts/

# Verify client receipt
python tests/verify_receipt.py \
  transcripts/client_transcript_*.txt \
  transcripts/client_receipt_*.json \
  certs/client_cert.pem

# Verify server receipt
python tests/verify_receipt.py \
  transcripts/server_transcript_*.txt \
  transcripts/server_receipt_*.json \
  certs/server_cert.pem
```

Expected:
- [✓] All message signatures verified
- [✓] Transcript hash verified
- [✓] Receipt signature verified

## Manual Testing Checklist

### Phase 1: Control Plane
- [ ] Client sends hello with certificate
- [ ] Server validates client certificate
- [ ] Server sends hello with certificate
- [ ] Client validates server certificate
- [ ] Temporary DH exchange completes
- [ ] Registration/Login works

### Phase 2: Key Agreement
- [ ] Session DH exchange completes
- [ ] Session key established

### Phase 3: Data Plane
- [ ] Messages are encrypted
- [ ] Messages are signed
- [ ] Sequence numbers increment
- [ ] Messages can be decrypted
- [ ] Signatures verify correctly

### Phase 4: Teardown
- [ ] Transcript saved
- [ ] Receipt generated
- [ ] Receipt signature valid

## Wireshark Testing

1. Start Wireshark capture on loopback interface
2. Run server and client
3. Exchange messages
4. Stop capture
5. Verify:
   - [ ] No plaintext visible
   - [ ] Only encrypted payloads
   - [ ] Certificate exchange visible (but encrypted)

## Error Testing

### Test Invalid Certificate
1. Modify client certificate (corrupt it)
2. Try to connect
3. Should see: `BAD_CERT: Invalid signature`

### Test Replay Attack
1. Capture a message
2. Try to resend with same seqno
3. Should see: `REPLAY: Invalid sequence number`

### Test Tamper Detection
1. Modify ciphertext in transit
2. Should see: `SIG_FAIL: Invalid signature`

## Troubleshooting

### "Certificate not found"
- Run certificate generation scripts
- Check certs/ directory has all files

### "Database connection failed"
- Verify MySQL is running: `sudo systemctl status mysql`
- Check .env credentials
- Test connection: `mysql -u DB_USER -p`

### "Module not found"
- Activate virtual environment: `source .venv/bin/activate`
- Install dependencies: `pip install -r requirements.txt`

### "Port already in use"
- Change SERVER_PORT in .env
- Or kill process: `lsof -ti:5555 | xargs kill`

### "Permission denied"
- Check certificate file permissions
- Check database user permissions

## Quick Start Script

Save this as `quick_start.sh`:

```bash
#!/bin/bash
set -e

echo "=== SecureChat Quick Start ==="

# Activate venv
source .venv/bin/activate

# Check certificates
if [ ! -f certs/ca_cert.pem ]; then
    echo "[*] Generating certificates..."
    python scripts/gen_ca.py --name "FAST-NU Root CA"
    python scripts/gen_cert.py --cn server.local --out certs/server --server
    python scripts/gen_cert.py --cn client.local --out certs/client
fi

# Check database
echo "[*] Initializing database..."
python -m app.storage.db --init

echo "[✓] Setup complete!"
echo ""
echo "To run:"
echo "  Terminal 1: python -m app.server"
echo "  Terminal 2: python -m app.client"
```

## Next Steps

1. Run all tests
2. Capture Wireshark evidence
3. Test error scenarios
4. Verify non-repudiation
5. Document findings

