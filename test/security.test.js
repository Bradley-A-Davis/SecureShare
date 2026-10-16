import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

const inbox = await fs.mkdtemp(path.join(os.tmpdir(), 'secureshare-test-'))
process.env.NODE_ENV = 'test'
process.env.INBOX_DIR = inbox
process.env.SECURESHARE_SETUP_TOKEN = 'test-setup-credential-that-is-long-and-random'
const { default: app } = await import(`../server.js?test=${Date.now()}`)
const server = app.listen(0)
await new Promise((resolve) => server.once('listening', resolve))
const base = `http://127.0.0.1:${server.address().port}`
const pairId = 'pairing-id-1234567890'
const fingerprint = 'a'.repeat(64)
const publicKey = { kty: 'RSA', n: 'test-modulus', e: 'AQAB' }
const publicFingerprint = crypto.createHash('sha256').update(JSON.stringify(publicKey)).digest('hex')
const signingKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1', publicKeyEncoding: { format: 'jwk' }, privateKeyEncoding: { format: 'jwk' } })
const attackerSigningKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1', publicKeyEncoding: { format: 'jwk' }, privateKeyEncoding: { format: 'jwk' } })
let adminToken
let peerToken

async function request(pathname, options) { return fetch(`${base}${pathname}`, options) }
async function json(pathname, options) { const response = await request(pathname, options); return { response, body: await response.json() } }
const admin = () => ({ Authorization: `Bearer ${adminToken}` })
function ownerAuthorization(action, { pairId, peerUrl, peerFingerprint }, privateKey = signingKeys.privateKey) {
  const authorization = { v: 1, action, pairId, peerFingerprint, peerUrl, nonce: crypto.randomUUID(), issuedAt: new Date().toISOString(), ownerFingerprint: publicFingerprint }
  const message = JSON.stringify(authorization)
  authorization.signature = crypto.sign('sha256', Buffer.from(message), { key: crypto.createPrivateKey({ key: privateKey, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }).toString('base64')
  return authorization
}

test('identity registration requires the single-use setup credential', async () => {
  let result = await json('/api/identity', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey, fingerprint: publicFingerprint }) })
  assert.equal(result.response.status, 401)
  result = await json('/api/identity', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Setup-Token': process.env.SECURESHARE_SETUP_TOKEN }, body: JSON.stringify({ publicKey, fingerprint: publicFingerprint, ownerVerificationKey: signingKeys.publicKey }) })
  assert.equal(result.response.status, 201)
  assert.match(result.body.adminToken, /^[A-Za-z0-9_-]{20,}$/)
  adminToken = result.body.adminToken
  result = await json('/api/identity', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey, fingerprint: publicFingerprint, ownerVerificationKey: signingKeys.publicKey }) })
  assert.equal(result.response.status, 401)
  const statePath = path.join(inbox, 'server-state.json')
  const legacyState = JSON.parse(await fs.readFile(statePath, 'utf8'))
  delete legacyState.identity.adminTokenHash
  await fs.writeFile(statePath, JSON.stringify(legacyState))
  result = await json('/api/identity', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Setup-Token': process.env.SECURESHARE_SETUP_TOKEN }, body: JSON.stringify({ publicKey, fingerprint: publicFingerprint, ownerVerificationKey: signingKeys.publicKey }) })
  assert.equal(result.response.status, 200)
  adminToken = result.body.adminToken
  assert.match(adminToken, /^[A-Za-z0-9_-]{20,}$/)
})

test('provisioning and activation require fresh owner signatures, not only administrator proof', async () => {
  const details = { pairId, peerUrl: 'http://127.0.0.1:23456', peerFingerprint: fingerprint }
  let result = await json('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pairId, peerUrl: 'http://127.0.0.1:23456', peerFingerprint: fingerprint }) })
  assert.equal(result.response.status, 401)
  result = await json('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify(details) })
  assert.equal(result.response.status, 403)
  result = await json('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ ...details, authorization: ownerAuthorization('provision', details, attackerSigningKeys.privateKey) }) })
  assert.equal(result.response.status, 403)
  const provisionAuthorization = ownerAuthorization('provision', details)
  result = await json('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ ...details, authorization: provisionAuthorization }) })
  assert.equal(result.response.status, 201)
  peerToken = result.body.inboundToken
  result = await json(`/api/peers/${pairId}/activate`, { method: 'POST' })
  assert.equal(result.response.status, 401)
  result = await json(`/api/peers/${pairId}/activate`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ authorization: provisionAuthorization }) })
  assert.equal(result.response.status, 403)
  result = await json(`/api/peers/${pairId}/activate`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ authorization: ownerAuthorization('activate', details) }) })
  assert.equal(result.response.status, 200)
})

test('expired pairings cannot be activated', async () => {
  const expiredPair = 'expired-pair-id-12345'
  const details = { pairId: expiredPair, peerUrl: 'http://127.0.0.1:23456', peerFingerprint: fingerprint }
  let result = await json('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ ...details, authorization: ownerAuthorization('provision', details) }) })
  assert.equal(result.response.status, 201)
  const statePath = path.join(inbox, 'server-state.json')
  const state = JSON.parse(await fs.readFile(statePath, 'utf8'))
  state.peers.find((peer) => peer.pairId === expiredPair).expiresAt = new Date(0).toISOString()
  await fs.writeFile(statePath, JSON.stringify(state))
  result = await json(`/api/peers/${expiredPair}/activate`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ authorization: ownerAuthorization('activate', details) }) })
  assert.equal(result.response.status, 403)
})

test('proofs cannot be copied, tampered with, or used after revocation', async () => {
  const replayDetails = { pairId: 'replay-owner-proof-123', peerUrl: 'http://127.0.0.1:23456', peerFingerprint: fingerprint }
  const provision = ownerAuthorization('provision', replayDetails)
  let result = await json('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ ...replayDetails, authorization: provision }) })
  assert.equal(result.response.status, 201)
  // Copying a signature to a different peer or changing a signed field fails.
  result = await json('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ ...replayDetails, pairId: 'copied-owner-proof-123', authorization: provision }) })
  assert.equal(result.response.status, 403)
  const activation = ownerAuthorization('activate', replayDetails)
  result = await json(`/api/peers/${replayDetails.pairId}/activate`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ authorization: { ...activation, peerFingerprint: 'b'.repeat(64) } }) })
  assert.equal(result.response.status, 403)
  result = await json(`/api/peers/${replayDetails.pairId}/activate`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ authorization: activation }) })
  assert.equal(result.response.status, 200)
  const revocation = ownerAuthorization('revoke', replayDetails)
  result = await json(`/api/peers/${replayDetails.pairId}`, { method: 'DELETE', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ authorization: revocation }) })
  assert.equal(result.response.status, 200)
  // A direct API caller cannot reactivate a revoked pairing with a captured proof.
  const statePath = path.join(inbox, 'server-state.json')
  const state = JSON.parse(await fs.readFile(statePath, 'utf8'))
  state.peers.find((peer) => peer.pairId === replayDetails.pairId).status = 'provisioned'
  await fs.writeFile(statePath, JSON.stringify(state))
  result = await json(`/api/peers/${replayDetails.pairId}/activate`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ authorization: activation }) })
  assert.equal(result.response.status, 403)
})

test('unsigned or tampered stored peers are never returned as trusted connections', async () => {
  const statePath = path.join(inbox, 'server-state.json')
  const state = JSON.parse(await fs.readFile(statePath, 'utf8'))
  state.peers.push({ pairId: 'forged-storage-peer-123', peerUrl: 'http://127.0.0.1:23456', peerFingerprint: fingerprint, inboundTokenHash: crypto.createHash('sha256').update('attacker-token').digest('hex'), status: 'active' })
  await fs.writeFile(statePath, JSON.stringify(state))
  const result = await json('/api/peers', { headers: admin() })
  assert.equal(result.response.status, 200)
  assert.equal(result.body.some((peer) => peer.pairId === 'forged-storage-peer-123'), false)
  const cleanup = await json('/api/peers/cleanup', { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ pairIds: ['forged-storage-peer-123'] }) })
  assert.equal(cleanup.response.status, 200)
})

test('an unlocked owner can safely migrate a matching legacy pairing', async () => {
  const details = { pairId: 'legacy-pairing-proof-123', peerUrl: 'http://127.0.0.1:23456', peerFingerprint: fingerprint }
  const statePath = path.join(inbox, 'server-state.json')
  const state = JSON.parse(await fs.readFile(statePath, 'utf8'))
  state.peers.push({ ...details, inboundTokenHash: crypto.createHash('sha256').update('legacy-token').digest('hex'), status: 'active' })
  await fs.writeFile(statePath, JSON.stringify(state))
  let result = await json(`/api/peers/${details.pairId}/authorize-legacy`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ provisionAuthorization: ownerAuthorization('provision', details), activationAuthorization: ownerAuthorization('activate', details) }) })
  assert.equal(result.response.status, 200)
  result = await json('/api/peers', { headers: admin() })
  assert.equal(result.body.some((peer) => peer.pairId === details.pairId), true)
})

test('file resources reject missing or wrong peer credentials', async () => {
  let result = await json(`/api/peers/${pairId}/files`, {})
  assert.equal(result.response.status, 401)
  result = await json(`/api/peers/${pairId}/files/not-a-real-file-id-123`, { method: 'DELETE' })
  assert.equal(result.response.status, 401)
  result = await json(`/api/peers/${pairId}/files`, { headers: { Authorization: 'Bearer wrong-token-that-is-definitely-long-enough' } })
  assert.equal(result.response.status, 401)
  result = await json(`/api/peers/${pairId}/files`, { headers: { Authorization: `Bearer ${peerToken}` } })
  assert.equal(result.response.status, 200)
})

test('pairing envelopes cannot be replayed and malformed requests are rejected', async () => {
  const envelope = { pairId: 'replay-pair-id-12345', sourceUrl: 'http://127.0.0.1:9999', sourceFingerprint: fingerprint, ciphertext: 'ciphertextvalue' }
  let result = await json('/api/invitations', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(envelope) })
  assert.equal(result.response.status, 202)
  result = await json('/api/invitations', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(envelope) })
  assert.equal(result.response.status, 409)
  result = await json('/api/invitations', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...envelope, pairId: '../escape' }) })
  assert.equal(result.response.status, 400)
})

test('encrypted uploads are not limited by file or storage quota size', async () => {
  const form = new FormData()
  form.append('ciphertext', new Blob([new Uint8Array(65)]), 'encrypted.bin')
  form.append('iv', 'AAAAAAAAAAAAAAAA')
  form.append('metadataIv', 'AAAAAAAAAAAAAAAA')
  form.append('metadata', 'AAAA')
  const result = await json(`/api/peers/${pairId}/files`, { method: 'POST', headers: { Authorization: `Bearer ${peerToken}` }, body: form })
  assert.equal(result.response.status, 201)
  const index = await json(`/api/peers/${pairId}/files`, { headers: { Authorization: `Bearer ${peerToken}` } })
  assert.equal(index.body.length, 1)
  assert.equal(index.body[0].bytes, 65)
})

test.after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  await fs.rm(inbox, { recursive: true, force: true })
})
