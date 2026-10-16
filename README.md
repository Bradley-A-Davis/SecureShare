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

## Tailscale

Use the machine's MagicDNS fully-qualified name, not its `100.x.y.z` address. A certificate issued for `machine.tailnet.ts.net` cannot validate for `100.102.168.125`.

1. In the Tailscale admin console, enable MagicDNS and HTTPS.
2. On the Docker host, issue the certificate for its MagicDNS name:

   ```bash
   sudo tailscale cert --cert-file tls/cert.pem --key-file tls/key.pem machine.tailnet.ts.net
   ```

3. Set `.env`:

   ```dotenv
   SECURESHARE_HOST=machine.tailnet.ts.net
   PUBLIC_URL=https://machine.tailnet.ts.net:23456
   ```

4. Start Compose and open `https://machine.tailnet.ts.net:23456` from another device in the tailnet.

`tailscale cert` files expire, so renew them before expiry and restart the `caddy` service after replacing the files. Keep the private key in `tls/`; never commit it.

## Localhost and LAN

Use a certificate that matches the address clients use:

- For localhost, use a locally trusted development CA certificate with `localhost`, `127.0.0.1`, and `::1` as SANs.
- For a LAN address, use an organization/internal CA certificate with the LAN DNS name (and IP SAN only when the CA supports it). Install that CA's public root on the client devices.
- For a public DNS name, use a certificate from a public CA for that DNS name.

For each case, set `SECURESHARE_HOST` to the certificate hostname/address and `PUBLIC_URL` to its reachable HTTPS URL. A self-signed certificate is useful only for curl testing unless its issuing CA is trusted by the browser.

## Verify TLS

These commands must be run with a hostname covered by the certificate. Do not use `-k` for a real deployment; it is appropriate only when testing a temporary self-signed certificate.

```bash
curl --tlsv1.2 --tls-max 1.2 -v https://machine.tailnet.ts.net:23456/api/health
curl --tlsv1.3 -v https://machine.tailnet.ts.net:23456/api/health
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
