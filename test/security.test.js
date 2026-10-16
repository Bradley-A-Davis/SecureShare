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
let adminToken
let peerToken

async function request(pathname, options) { return fetch(`${base}${pathname}`, options) }
async function json(pathname, options) { const response = await request(pathname, options); return { response, body: await response.json() } }
const admin = () => ({ Authorization: `Bearer ${adminToken}` })

test('identity registration requires the single-use setup credential', async () => {
  let result = await json('/api/identity', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey, fingerprint: publicFingerprint }) })
  assert.equal(result.response.status, 401)
  result = await json('/api/identity', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Setup-Token': process.env.SECURESHARE_SETUP_TOKEN }, body: JSON.stringify({ publicKey, fingerprint: publicFingerprint }) })
  assert.equal(result.response.status, 201)
  assert.match(result.body.adminToken, /^[A-Za-z0-9_-]{20,}$/)
  adminToken = result.body.adminToken
  result = await json('/api/identity', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey, fingerprint: publicFingerprint }) })
  assert.equal(result.response.status, 401)
  const statePath = path.join(inbox, 'server-state.json')
  const legacyState = JSON.parse(await fs.readFile(statePath, 'utf8'))
  delete legacyState.identity.adminTokenHash
  await fs.writeFile(statePath, JSON.stringify(legacyState))
  result = await json('/api/identity', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Setup-Token': process.env.SECURESHARE_SETUP_TOKEN }, body: JSON.stringify({ publicKey, fingerprint: publicFingerprint }) })
  assert.equal(result.response.status, 200)
  adminToken = result.body.adminToken
  assert.match(adminToken, /^[A-Za-z0-9_-]{20,}$/)
})

test('provisioning and activation require administrator proof', async () => {
  let result = await json('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pairId, peerUrl: 'http://127.0.0.1:23456', peerFingerprint: fingerprint }) })
  assert.equal(result.response.status, 401)
  result = await json('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ pairId, peerUrl: 'http://127.0.0.1:23456', peerFingerprint: fingerprint }) })
  assert.equal(result.response.status, 201)
  peerToken = result.body.inboundToken
  result = await json(`/api/peers/${pairId}/activate`, { method: 'POST' })
  assert.equal(result.response.status, 401)
  result = await json(`/api/peers/${pairId}/activate`, { method: 'POST', headers: admin() })
  assert.equal(result.response.status, 200)
})

test('expired pairings cannot be activated', async () => {
  const expiredPair = 'expired-pair-id-12345'
  let result = await json('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json', ...admin() }, body: JSON.stringify({ pairId: expiredPair, peerUrl: 'http://127.0.0.1:23456', peerFingerprint: fingerprint }) })
  assert.equal(result.response.status, 201)
  const statePath = path.join(inbox, 'server-state.json')
  const state = JSON.parse(await fs.readFile(statePath, 'utf8'))
  state.peers.find((peer) => peer.pairId === expiredPair).expiresAt = new Date(0).toISOString()
  await fs.writeFile(statePath, JSON.stringify(state))
  result = await json(`/api/peers/${expiredPair}/activate`, { method: 'POST', headers: admin() })
  assert.equal(result.response.status, 403)
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
