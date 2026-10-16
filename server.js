import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { createReadStream } from 'node:fs'
import express from 'express'
import multer from 'multer'

const app = express()
const port = Number(process.env.PORT || 23456)
const production = process.env.NODE_ENV === 'production'
const root = path.resolve(process.env.INBOX_DIR || path.join(process.cwd(), 'inbox'))
const statePath = path.join(root, 'server-state.json')
const invitesPath = path.join(root, '_invitations')
const acceptancesPath = path.join(root, '_acceptances')
const peersPath = path.join(root, '_peers')
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_BYTES || 25 * 1024 * 1024)
const MAX_PEER_BYTES = Number(process.env.MAX_PEER_BYTES || 250 * 1024 * 1024)
const MAX_TOTAL_BYTES = Number(process.env.MAX_TOTAL_BYTES || 2 * 1024 * 1024 * 1024)
const MAX_PENDING_UPLOADS = Number(process.env.MAX_PENDING_UPLOADS || 4)
const MAX_TOTAL_PENDING_UPLOADS = Number(process.env.MAX_TOTAL_PENDING_UPLOADS || 12)
const MAX_PENDING_PAIRINGS = Number(process.env.MAX_PENDING_PAIRINGS || 20)
const PAIRING_TTL_MS = Number(process.env.PAIRING_TTL_MS || 24 * 60 * 60 * 1000)
const now = () => new Date().toISOString()
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex')
const tokenHash = (value) => crypto.createHash('sha256').update(value).digest('hex')
const setupToken = process.env.SECURESHARE_SETUP_TOKEN

if (!setupToken) throw new Error('SECURESHARE_SETUP_TOKEN must be set before SecureShare starts.')

function safeId(value) { const input = String(value || ''); return /^[A-Za-z0-9_-]{16,80}$/.test(input) ? input : null }
function tokenEquals(expectedHash, supplied) {
  if (!expectedHash || typeof supplied !== 'string' || supplied.length > 512) return false
  const left = Buffer.from(expectedHash, 'hex'); const right = Buffer.from(tokenHash(supplied), 'hex')
  return left.length === right.length && crypto.timingSafeEqual(left, right)
}
function bearer(req) { return req.get('authorization')?.match(/^Bearer\s+([A-Za-z0-9_-]{20,512})$/i)?.[1] || null }
function originOf(value) { try { return new URL(value).origin } catch { return null } }
function isSafeUrl(value) {
  try {
    const url = new URL(value)
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) return false
    if (production && url.protocol !== 'https:') return false
    if (!production && !['http:', 'https:'].includes(url.protocol)) return false
    if (production && (url.hostname === 'localhost' || /^127\.|^0\.0\.0\.0$|^\[?::1\]?$/i.test(url.hostname))) return false
    return url.href.replace(/\/$/, '')
  } catch { return false }
}
function validEnvelope(value) {
  return value && typeof value === 'object' && safeId(value.pairId) && isSafeUrl(value.sourceUrl) && /^[a-f0-9]{64}$/i.test(String(value.sourceFingerprint || '')) && typeof value.ciphertext === 'string' && /^[A-Za-z0-9+/_-]+={0,2}$/.test(value.ciphertext) && value.ciphertext.length <= 12000
}
function validB64(value, limit) { return typeof value === 'string' && value.length > 0 && value.length <= limit && /^[A-Za-z0-9+/]+={0,2}$/.test(value) }
function expired(value) { return !value?.expiresAt || Date.parse(value.expiresAt) <= Date.now() }
async function readState() { try { const state = JSON.parse(await fs.readFile(statePath, 'utf8')); return { version: 3, identity: state.identity || null, peers: Array.isArray(state.peers) ? state.peers : [] } } catch (error) { if (error.code === 'ENOENT') return { version: 3, identity: null, peers: [] }; throw error } }
async function writeState(state) { const temp = `${statePath}.${process.pid}.${crypto.randomUUID()}.tmp`; await fs.writeFile(temp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 }); await fs.rename(temp, statePath) }
function peerFolder(pairId) { return path.join(peersPath, pairId) }
async function readIndex(pairId) { return JSON.parse(await fs.readFile(path.join(peerFolder(pairId), 'encrypted-index.json'), 'utf8')) }
async function fileHash(filePath) { return new Promise((resolve, reject) => { const hash = crypto.createHash('sha256'); const input = createReadStream(filePath); input.on('data', (chunk) => hash.update(chunk)); input.on('error', reject); input.on('end', () => resolve(hash.digest('hex'))) }) }
async function cleanupExpired(directory) {
  const names = await fs.readdir(directory)
  await Promise.all(names.filter((name) => name.endsWith('.json')).map(async (name) => { const target = path.join(directory, name); try { if (expired(JSON.parse(await fs.readFile(target, 'utf8')))) await fs.unlink(target) } catch (error) { if (error.code !== 'ENOENT') throw error } }))
}
async function readEnvelopes(directory) { await cleanupExpired(directory); const names = await fs.readdir(directory); return Promise.all(names.filter((name) => name.endsWith('.json')).map(async (name) => JSON.parse(await fs.readFile(path.join(directory, name), 'utf8')))) }
async function storeEnvelope(directory, envelope) {
  if (!validEnvelope(envelope)) { const error = new Error('Invalid pairing request.'); error.status = 400; throw error }
  await cleanupExpired(directory); const target = path.join(directory, `${envelope.pairId}.json`)
  try { await fs.access(target); const error = new Error('This pairing request already exists.'); error.status = 409; throw error } catch (error) { if (error.status || error.code !== 'ENOENT') throw error }
  if ((await readEnvelopes(directory)).length >= MAX_PENDING_PAIRINGS) { const error = new Error('Too many pending pairing requests.'); error.status = 429; throw error }
  const record = { pairId: envelope.pairId, sourceUrl: isSafeUrl(envelope.sourceUrl), sourceFingerprint: envelope.sourceFingerprint.toLowerCase(), ciphertext: envelope.ciphertext, receivedAt: now(), expiresAt: new Date(Date.now() + PAIRING_TTL_MS).toISOString() }
  await fs.writeFile(target, `${JSON.stringify(record, null, 2)}\n`, { flag: 'wx', mode: 0o600 })
}
async function deleteEnvelope(directory, pairId) { if (!safeId(pairId)) { const error = new Error('A valid pairing ID is required.'); error.status = 400; throw error }; try { await fs.unlink(path.join(directory, `${pairId}.json`)) } catch (error) { if (error.code === 'ENOENT') error.status = 404; throw error } }
async function totalStorage() { const state = await readState(); let bytes = 0; for (const peer of state.peers) { try { bytes += (await readIndex(peer.pairId)).reduce((sum, entry) => sum + Number(entry.bytes || 0), 0) } catch {} } return bytes }

await fs.mkdir(root, { recursive: true, mode: 0o700 })
await Promise.all([fs.mkdir(invitesPath, { recursive: true, mode: 0o700 }), fs.mkdir(acceptancesPath, { recursive: true, mode: 0o700 }), fs.mkdir(peersPath, { recursive: true, mode: 0o700 })])
const rateBuckets = new Map()
function rateLimit({ windowMs, max, key = (req) => `${req.ip}:${req.path}` }) { return (req, res, next) => { const bucketKey = key(req); const cutoff = Date.now() - windowMs; const values = (rateBuckets.get(bucketKey) || []).filter((time) => time > cutoff); if (values.length >= max) return res.status(429).json({ error: 'Too many requests. Please try again later.' }); values.push(Date.now()); rateBuckets.set(bucketKey, values); next() } }
const unauthPairLimit = rateLimit({ windowMs: 60_000, max: 10 }); const adminLimit = rateLimit({ windowMs: 60_000, max: 30 })

app.disable('x-powered-by'); app.set('trust proxy', false)
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()', 'Content-Security-Policy': `default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; img-src 'self' blob: data:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https:${production ? '' : ' http:'}`, 'Cache-Control': 'no-store, private', Pragma: 'no-cache' })
  if (production) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  const publicPath = ['/api/public-key', '/api/invitations', '/api/acceptances'].includes(req.path); const uploadMatch = req.path.match(/^\/api\/peers\/([A-Za-z0-9_-]{16,80})\/files$/); const requestOrigin = originOf(req.get('origin'))
  if (publicPath) res.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Max-Age': '600' })
  else if (uploadMatch && requestOrigin) return readState().then((state) => { const peer = state.peers.find((entry) => entry.pairId === uploadMatch[1]); if (peer && originOf(peer.peerUrl) === requestOrigin) res.set({ Vary: 'Origin', 'Access-Control-Allow-Origin': requestOrigin, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Max-Age': '600' }); if (req.method === 'OPTIONS') return res.sendStatus(204); next() }).catch(next)
  if (req.method === 'OPTIONS') return res.sendStatus(204); next()
})
app.use(express.json({ limit: '32kb', strict: true }))
async function authorizeAdmin(req, res, next) { try { const identity = (await readState()).identity; if (!identity || !tokenEquals(identity.adminTokenHash, bearer(req))) return res.status(401).json({ error: 'Administrator authorization is required.' }); req.admin = true; next() } catch (error) { next(error) } }
async function authorizePeer(req, res, next) { try { const pairId = safeId(req.params.pairId); const peer = (await readState()).peers.find((entry) => entry.pairId === pairId); if (!pairId || !peer || peer.status !== 'active' || !tokenEquals(peer.inboundTokenHash, bearer(req))) return res.status(401).json({ error: 'Invalid or inactive peer credential.' }); req.peer = peer; next() } catch (error) { next(error) } }

app.get('/api/health', (_req, res) => res.json({ ok: true, port }))
app.get('/api/public-key', async (_req, res, next) => { try { const { identity } = await readState(); if (!identity) return res.status(503).json({ error: 'This server has not completed local key setup.' }); res.json({ publicKey: identity.publicKey, fingerprint: identity.fingerprint }) } catch (error) { next(error) } })
app.put('/api/identity', rateLimit({ windowMs: 60_000, max: 5 }), async (req, res, next) => {
  try {
    const { publicKey, fingerprint } = req.body || {}
    if (!publicKey || typeof publicKey !== 'object' || Array.isArray(publicKey) || !/^[a-f0-9]{64}$/i.test(String(fingerprint || '')) || JSON.stringify(publicKey).length > 16000 || publicKey.kty !== 'RSA' || typeof publicKey.n !== 'string' || typeof publicKey.e !== 'string' || sha256(JSON.stringify(publicKey)) !== String(fingerprint).toLowerCase()) return res.status(400).json({ error: 'A valid public key and fingerprint are required.' })
    const state = await readState()
    if (state.identity) {
      if (state.identity.fingerprint !== String(fingerprint).toLowerCase()) return res.status(409).json({ error: 'A server identity already exists.' })
      if (!state.identity.adminTokenHash) {
        if (!tokenEquals(tokenHash(setupToken), req.get('x-setup-token') || '')) return res.status(401).json({ error: 'A setup credential is required to recover administrator access.' })
        const adminToken = crypto.randomBytes(32).toString('base64url')
        state.identity.adminTokenHash = tokenHash(adminToken); await writeState(state)
        return res.json({ publicKey: state.identity.publicKey, fingerprint: state.identity.fingerprint, adminToken })
      }
      if (!tokenEquals(state.identity.adminTokenHash, bearer(req))) return res.status(401).json({ error: 'Administrator authorization is required.' })
      return res.json({ publicKey: state.identity.publicKey, fingerprint: state.identity.fingerprint })
    }
    if (!tokenEquals(tokenHash(setupToken), req.get('x-setup-token') || '')) return res.status(401).json({ error: 'A valid setup credential is required.' })
    const adminToken = crypto.randomBytes(32).toString('base64url'); state.identity = { publicKey, fingerprint: String(fingerprint).toLowerCase(), adminTokenHash: tokenHash(adminToken), createdAt: now() }; await writeState(state); res.status(201).json({ publicKey, fingerprint: state.identity.fingerprint, adminToken })
  } catch (error) { next(error) }
})
app.get('/api/invitations', authorizeAdmin, async (_req, res, next) => { try { res.json(await readEnvelopes(invitesPath)) } catch (error) { next(error) } })
app.post('/api/invitations', unauthPairLimit, async (req, res, next) => { try { await storeEnvelope(invitesPath, req.body); res.status(202).json({ accepted: true }) } catch (error) { next(error) } })
app.delete('/api/invitations/:pairId', authorizeAdmin, async (req, res, next) => { try { await deleteEnvelope(invitesPath, req.params.pairId); res.json({ deleted: true }) } catch (error) { next(error) } })
app.get('/api/acceptances', authorizeAdmin, async (_req, res, next) => { try { res.json(await readEnvelopes(acceptancesPath)) } catch (error) { next(error) } })
app.post('/api/acceptances', unauthPairLimit, async (req, res, next) => { try { if (!validEnvelope(req.body)) { const error = new Error('Invalid pairing request.'); error.status = 400; throw error }; const peer = (await readState()).peers.find((entry) => entry.pairId === req.body.pairId); if (!peer || peer.status !== 'provisioned' || peer.peerFingerprint !== req.body.sourceFingerprint.toLowerCase() || expired(peer)) return res.status(403).json({ error: 'This pairing is not awaiting an acceptance.' }); await storeEnvelope(acceptancesPath, req.body); res.status(202).json({ accepted: true }) } catch (error) { next(error) } })
app.delete('/api/acceptances/:pairId', authorizeAdmin, async (req, res, next) => { try { await deleteEnvelope(acceptancesPath, req.params.pairId); res.json({ deleted: true }) } catch (error) { next(error) } })
app.post('/api/peers/provision', adminLimit, authorizeAdmin, async (req, res, next) => {
  try { const pairId = safeId(req.body?.pairId); const peerUrl = isSafeUrl(req.body?.peerUrl); const peerFingerprint = String(req.body?.peerFingerprint || '').toLowerCase(); if (!pairId || !peerUrl || !/^[a-f0-9]{64}$/.test(peerFingerprint)) return res.status(400).json({ error: 'Invalid pairing details.' }); const state = await readState(); if (state.peers.some((peer) => peer.pairId === pairId)) return res.status(409).json({ error: 'This pairing already exists.' }); const inboundToken = crypto.randomBytes(32).toString('base64url'); const createdAt = now(); const expiresAt = new Date(Date.now() + PAIRING_TTL_MS).toISOString(); state.peers.push({ pairId, peerUrl, peerFingerprint, inboundTokenHash: tokenHash(inboundToken), status: 'provisioned', approvedAt: createdAt, expiresAt, createdAt }); await fs.mkdir(peerFolder(pairId), { recursive: false, mode: 0o700 }); await fs.writeFile(path.join(peerFolder(pairId), 'arrival-log.txt'), `SecureShare encrypted arrival log\npair_id=${pairId}\ncreated_at=${createdAt}\n\n`, { mode: 0o600 }); await fs.writeFile(path.join(peerFolder(pairId), 'encrypted-index.json'), '[]\n', { mode: 0o600 }); await writeState(state); res.status(201).json({ inboundToken, expiresAt }) } catch (error) { next(error) }
})
app.post('/api/peers/:pairId/activate', adminLimit, authorizeAdmin, async (req, res, next) => { try { const pairId = safeId(req.params.pairId); const state = await readState(); const peer = state.peers.find((entry) => entry.pairId === pairId); if (!peer) return res.status(404).json({ error: 'Unknown pairing.' }); if (peer.status !== 'provisioned' || !peer.approvedAt || expired(peer)) return res.status(403).json({ error: 'This pairing is not approved for activation.' }); peer.status = 'active'; peer.activatedAt = now(); delete peer.expiresAt; await writeState(state); res.json({ active: true }) } catch (error) { next(error) } })

const pendingUploads = new Map()
let totalPendingUploads = 0
async function uploadGate(req, res, next) { try { const pairId = req.peer.pairId; const count = pendingUploads.get(pairId) || 0; if (count >= MAX_PENDING_UPLOADS || totalPendingUploads >= MAX_TOTAL_PENDING_UPLOADS) return res.status(429).json({ error: 'Too many pending uploads.' }); const [index, serverBytes] = await Promise.all([readIndex(pairId), totalStorage()]); if (index.reduce((sum, entry) => sum + Number(entry.bytes || 0), 0) >= MAX_PEER_BYTES || serverBytes >= MAX_TOTAL_BYTES) return res.status(507).json({ error: 'Encrypted storage quota exceeded.' }); pendingUploads.set(pairId, count + 1); totalPendingUploads += 1; let released = false; const release = () => { if (!released) { released = true; pendingUploads.set(pairId, Math.max(0, (pendingUploads.get(pairId) || 1) - 1)); totalPendingUploads = Math.max(0, totalPendingUploads - 1) } }; res.once('finish', release); res.once('close', release); next() } catch (error) { next(error) } }
const upload = multer({ storage: multer.diskStorage({ destination: (req, _file, callback) => callback(null, peerFolder(req.peer.pairId)), filename: (_req, _file, callback) => callback(null, `${crypto.randomUUID()}.bin`) }), limits: { fileSize: MAX_FILE_BYTES, files: 1, fields: 4, fieldSize: 16 * 1024, parts: 5 } })
async function removeUploaded(req) { if (req.file?.path) await fs.unlink(req.file.path).catch(() => {}) }
app.post('/api/peers/:pairId/files', rateLimit({ windowMs: 60000, max: 30, key: (req) => `upload:${req.ip}:${req.params.pairId}` }), authorizePeer, uploadGate, upload.single('ciphertext'), async (req, res, next) => { try { if (!req.file || !validB64(req.body?.iv, 32) || !validB64(req.body?.metadataIv, 32) || !validB64(req.body?.metadata, 16 * 1024)) { await removeUploaded(req); return res.status(400).json({ error: 'Valid encrypted file, IV, and encrypted metadata are required.' }) }; const [index, serverBytes] = await Promise.all([readIndex(req.peer.pairId), totalStorage()]); const peerBytes = index.reduce((sum, entry) => sum + Number(entry.bytes || 0), 0); if (req.file.size > MAX_FILE_BYTES || peerBytes + req.file.size > MAX_PEER_BYTES || serverBytes + req.file.size > MAX_TOTAL_BYTES) { await removeUploaded(req); return res.status(507).json({ error: 'Encrypted storage quota exceeded.' }) }; const encryptedId = path.basename(req.file.filename, '.bin'); const record = { encryptedId, storedName: req.file.filename, iv: req.body.iv, metadata: req.body.metadata, metadataIv: req.body.metadataIv, bytes: req.file.size, arrivedAt: now(), sha256: await fileHash(req.file.path) }; index.push(record); await fs.writeFile(path.join(peerFolder(req.peer.pairId), 'encrypted-index.json'), `${JSON.stringify(index, null, 2)}\n`, { mode: 0o600 }); await fs.appendFile(path.join(peerFolder(req.peer.pairId), 'arrival-log.txt'), `encrypted_arrival_at=${record.arrivedAt} encrypted_id=${encryptedId} cipher_bytes=${record.bytes} sha256=${record.sha256}\n`); res.status(201).json({ encryptedId, arrivedAt: record.arrivedAt }) } catch (error) { await removeUploaded(req); next(error) } })
app.get('/api/peers/:pairId/files', authorizePeer, async (req, res, next) => { try { res.json(await readIndex(req.peer.pairId)) } catch (error) { if (error.code === 'ENOENT') return res.status(404).json({ error: 'Unknown pairing.' }); next(error) } })
app.delete('/api/peers/:pairId/files/:encryptedId', authorizePeer, async (req, res, next) => { try { const encryptedId = safeId(req.params.encryptedId); if (!encryptedId) return res.status(400).json({ error: 'A valid encrypted file ID is required.' }); const index = await readIndex(req.peer.pairId); const record = index.find((entry) => entry.encryptedId === encryptedId); if (!record) return res.status(404).json({ error: 'Encrypted file not found.' }); const storedName = path.basename(record.storedName || ''); if (storedName !== `${encryptedId}.bin`) return res.status(409).json({ error: 'Encrypted file record is invalid.' }); await fs.unlink(path.join(peerFolder(req.peer.pairId), storedName)).catch((error) => { if (error.code !== 'ENOENT') throw error }); await fs.writeFile(path.join(peerFolder(req.peer.pairId), 'encrypted-index.json'), `${JSON.stringify(index.filter((entry) => entry.encryptedId !== encryptedId), null, 2)}\n`, { mode: 0o600 }); await fs.appendFile(path.join(peerFolder(req.peer.pairId), 'arrival-log.txt'), `encrypted_deleted_at=${now()} encrypted_id=${encryptedId}\n`); res.json({ deleted: true }) } catch (error) { next(error) } })
app.get('/api/peers/:pairId/files/:encryptedId', authorizePeer, async (req, res) => { const encryptedId = safeId(req.params.encryptedId); if (!encryptedId) return res.status(400).json({ error: 'A valid encrypted file ID is required.' }); const target = path.join(peerFolder(req.peer.pairId), `${encryptedId}.bin`); try { await fs.access(target); res.type('application/octet-stream').set('Content-Disposition', 'attachment').sendFile(target) } catch { res.status(404).json({ error: 'Encrypted file not found.' }) } })
app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found.' }))
app.use(express.static(path.join(process.cwd(), 'dist'), { fallthrough: true, maxAge: 0 }))
app.use((_req, res) => res.sendFile(path.join(process.cwd(), 'dist', 'index.html')))
app.use((error, _req, res, _next) => { if (error instanceof multer.MulterError) return res.status(error.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: error.code === 'LIMIT_FILE_SIZE' ? 'Encrypted file exceeds the upload size limit.' : 'Malformed upload.' }); const status = Number.isInteger(error.status) ? error.status : 500; if (status >= 500) console.error(`SecureShare request failed: ${error.name}`); res.status(status).json({ error: status >= 500 ? 'The server could not complete this request.' : error.message || 'Request rejected.' }) })
if (process.env.NODE_ENV !== 'test') app.listen(port, () => console.log(`SecureShare listening on port ${port}`))
export default app
