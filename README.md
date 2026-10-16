# SecureShare

SecureShare is a single-user, server-to-server encrypted file exchange. The browser encrypts files before upload; the receiving server stores ciphertext, encrypted metadata, checksums, and arrival metadata in `./inbox`.

The application is served only through HTTPS on port `23456`. Node runs on a private Docker network and Caddy terminates TLS 1.2/1.3 at the published port. Do not publish the Node container's port directly.

## Install with Docker Compose

1. Create the ignored certificate directory:

   ```bash
   mkdir -p tls
   ```

2. Put a certificate and private key in `tls/cert.pem` and `tls/key.pem`. They are mounted read-only, excluded from the image, and ignored by Git.

3. Create `.env` with the exact HTTPS address other servers should use:

   ```dotenv
   SECURESHARE_HOST=share.example.net
   PUBLIC_URL=https://share.example.net:23456
   # Optional: use a different host port.
   # SECURESHARE_HTTPS_PORT=443
   ```

4. Start it:

   ```bash
   docker compose up --build -d
   ```

5. Open the URL in `PUBLIC_URL`. Received encrypted files persist in `./inbox`.

To stop it:

```bash
docker compose down
```

`PUBLIC_URL` is not cosmetic: it is the callback address embedded in encrypted invitations and pairing acceptances. It must be reachable by the peer and match the certificate hostname, including a non-default port.

## Domain certificate

Use a certificate from a trusted certificate authority for your SecureShare domain. Its hostname must match both `SECURESHARE_HOST` and the hostname in `PUBLIC_URL`. Place the certificate chain in `tls/cert.pem` and its private key in `tls/key.pem`.

## Verify TLS

These commands must be run with a hostname covered by the certificate. Do not use `-k` for a real deployment; it is appropriate only when testing a temporary self-signed certificate.

```bash
curl --tlsv1.2 --tls-max 1.2 -v https://share.example.net:23456/api/health
curl --tlsv1.3 -v https://share.example.net:23456/api/health
```

The verbose output should show `TLSv1.2` and `TLSv1.3` respectively, followed by an HTTP `200` response. `docker compose ps` should show a healthy `secureshare` service.

## Pairing flow

1. On first open, create a password. The browser generates an RSA-OAEP key pair locally and encrypts the private key in local browser storage with a password-derived AES-GCM key.
2. The public key is published at `GET /api/public-key` so another server can fetch it from its configured HTTPS address.
3. A connection request encrypts its note, pairing AES key, and one-time transport credential to the recipient’s public key. The recipient server stores ciphertext only.
4. The recipient unlocks the page, verifies the source URL and public-key fingerprint, then confirms. Both local clients retain the pair AES key encrypted under their local password key.
5. Files are encrypted in the browser with AES-256-GCM before upload. The receiving server stores only ciphertext, encrypted metadata, checksums, and arrival metadata in `inbox/_peers/<pair-id>/`.

The server never receives a private key, password, plaintext file, or plaintext filename.

## Public endpoints

- `GET /api/public-key` — published public key and SHA-256 fingerprint
- `POST /api/invitations` — encrypted invitation delivery
- `POST /api/acceptances` — encrypted pairing acceptance delivery

The recipient must independently verify the displayed fingerprint through a separate trusted channel before confirming a pairing.
