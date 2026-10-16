# SecureShare

SecureShare is a single-user, server-to-server encrypted file exchange. It listens on port `23456`.

## Start with Docker Compose

```bash
docker compose up --build -d
```

Open `http://localhost:23456`. Received encrypted files persist in `./inbox`.

To stop it:

```bash
docker compose down
```

Set `SECURESHARE_PORT` before starting if the host needs a different port, for example `SECURESHARE_PORT=34567 docker compose up -d`.

## Start with Docker

```bash
docker build -t secureshare .
docker run --rm -p 23456:23456 -v "$(pwd)/inbox:/app/inbox" secureshare
```

The bind mount is required for persistent encrypted inbox data.

## Pairing flow

1. On first open, create a password. The browser generates an RSA-OAEP key pair locally and encrypts the private key in local browser storage with a password-derived AES-GCM key.
2. The public key is published at `GET /api/public-key` so another server can fetch it from its domain or IP.
3. A connection request encrypts its note, pairing AES key, and one-time transport credential to the recipient’s public key. The recipient server stores the ciphertext only.
4. The recipient unlocks the page, verifies the source URL and public-key fingerprint, then confirms. Both local clients retain the pair AES key encrypted under their local password key.
5. Files are encrypted in the browser with AES-256-GCM before upload. The receiving server stores only ciphertext, encrypted metadata, checksums, and arrival metadata in `inbox/_peers/<pair-id>/`.

The server never receives a private key, password, plaintext file, or plaintext filename.

## Public endpoints

- `GET /api/public-key` — published public key and SHA-256 fingerprint
- `POST /api/invitations` — encrypted invitation delivery
- `POST /api/acceptances` — encrypted pairing acceptance delivery

Use HTTPS and a valid certificate before exposing this service to the public internet. The recipient must independently verify the displayed fingerprint through a separate trusted channel before confirming a pairing.
