# Quick Reference - Running SecureChat

## ✅ Setup Complete!

All prerequisites are ready:
- ✓ Dependencies installed
- ✓ Certificates generated
- ✓ Database initialized
- ✓ Security tests passing

## 🚀 Running the Application

### Step 1: Start the Server

Open **Terminal 1**:

```bash
cd /home/munjenko/i220787_A2
source .venv/bin/activate
python -m app.server
```

You should see:
```
[*] Server initialized
[*] Certificate CN: server.local
[✓] Server listening on localhost:5555
[*] Waiting for client connection...
```

### Step 2: Start the Client

Open **Terminal 2** (new terminal):

```bash
cd /home/munjenko/i220787_A2
source .venv/bin/activate
python -m app.client
```

### Step 3: Follow the Flow

1. **Client connects** - You'll see certificate exchange
2. **Choose action**:
   - Type `1` to Register (new user)
   - Type `2` to Login (existing user)
3. **Enter credentials**:
   - For registration: email, username, password
   - For login: email, password
4. **Chat session starts**:
   - Type messages and press Enter
   - Type `/quit` to end session
5. **Session receipt** - Automatically saved to `transcripts/`

## 🧪 Running Tests

### All Security Tests
```bash
./test_all.sh
```

### Individual Tests
```bash
# Certificate validation
python tests/test_cert.py

# Replay attack detection
python tests/test_replay.py

# Tamper detection
python tests/test_tamper.py
```

### Verify Session Receipts
After a chat session:
```bash
# Find the latest transcript and receipt
ls -t transcripts/*.txt | head -1
ls -t transcripts/*.json | head -1

# Verify client receipt
python tests/verify_receipt.py \
  transcripts/client_transcript_*.txt \
  transcripts/client_receipt_*.json \
  certs/client_cert.pem
```

## 📋 Testing Checklist

### Basic Functionality
- [ ] Server starts successfully
- [ ] Client connects to server
- [ ] Certificate exchange works
- [ ] Registration creates new user
- [ ] Login authenticates user
- [ ] Messages can be sent and received
- [ ] Messages are encrypted (check Wireshark)
- [ ] Session receipt is generated

### Security Features
- [ ] Invalid certificate rejected (BAD_CERT)
- [ ] Replay attack detected (REPLAY)
- [ ] Tampered message rejected (SIG_FAIL)
- [ ] Receipt signature verifies correctly
- [ ] Transcript hash matches receipt

## 🔍 Wireshark Testing

1. Start Wireshark: `sudo wireshark`
2. Capture on `lo` (loopback) interface
3. Run server and client
4. Exchange messages
5. Stop capture
6. Verify:
   - No plaintext visible
   - Only encrypted payloads
   - Certificate exchange visible

## 🐛 Troubleshooting

### Server won't start
```bash
# Check if port is in use
lsof -i:5555

# Kill process if needed
kill -9 $(lsof -ti:5555)
```

### Client can't connect
```bash
# Check server is running
# Check .env SERVER_PORT matches
# Check firewall
```

### Database errors
```bash
# Reinitialize database
python -m app.storage.db --init

# Check MySQL is running
sudo systemctl status mysql
```

### Certificate errors
```bash
# Regenerate certificates
python scripts/gen_ca.py --name "FAST-NU Root CA"
python scripts/gen_cert.py --cn server.local --out certs/server --server
python scripts/gen_cert.py --cn client.local --out certs/client
```

## 📁 Important Files

- **Certificates**: `certs/`
- **Transcripts**: `transcripts/`
- **Configuration**: `.env`
- **Database**: MySQL `securechat_db`

## 🎯 Next Steps

1. Run server and client
2. Test registration and login
3. Exchange messages
4. Capture Wireshark evidence
5. Test error scenarios (invalid cert, replay, tamper)
6. Verify receipts offline
7. Document findings

