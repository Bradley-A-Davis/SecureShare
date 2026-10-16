import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { createReadStream } from 'node:fs'
import express from 'express'
import multer from 'multer'

const app = express()
const port = Number(process.env.PORT || 23456)
const root = path.resolve(process.env.INBOX_DIR || path.join(process.cwd(), 'inbox'))
const statePath = path.join(root, 'server-state.json')
const invitesPath = path.join(root, '_invitations')
const acceptancesPath = path.join(root, '_acceptances')
const peersPath = path.join(root, '_peers')
const now = () => new Date().toISOString()
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex')

function id(value) {
  return String(value || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80)
}

function tokenEquals(expectedHash, supplied) {
  const left = Buffer.from(expectedHash, 'hex')
  const right = Buffer.from(sha256(supplied), 'hex')
  return left.length === right.length && crypto.timingSafeEqual(left, right)
}

function originOf(value) {
  try { return new URL(value).origin } catch { return null }
}

async function readState() {
  try { return JSON.parse(await fs.readFile(statePath, 'utf8')) }
  catch (error) { if (error.code === 'ENOENT') return { version: 2, identity: null, peers: [] }; throw error }
}

async function writeState(state) {
  const temp = `${statePath}.${process.pid}.tmp`
  await fs.writeFile(temp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 })
  await fs.rename(temp, statePath)
}

async function fileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    const input = createReadStream(filePath)
    input.on('data', (chunk) => hash.update(chunk))
    input.on('error', reject)
    input.on('end', () => resolve(hash.digest('hex')))
  })
}

function peerFolder(pairId) {
  return path.join(peersPath, id(pairId))
}

async function storeEnvelope(directory, envelope) {
  const pairId = id(envelope.pairId)
  if (!pairId || !envelope.ciphertext || !envelope.sourceUrl) throw new Error('Malformed encrypted envelope.')
  const target = path.join(directory, `${pairId}.json`)
  await fs.writeFile(target, `${JSON.stringify({ ...envelope, receivedAt: now() }, null, 2)}\n`, { flag: 'wx', mode: 0o600 })
}

await fs.mkdir(root, { recursive: true, mode: 0o700 })
await Promise.all([fs.mkdir(invitesPath, { recursive: true, mode: 0o700 }), fs.mkdir(acceptancesPath, { recursive: true, mode: 0o700 }), fs.mkdir(peersPath, { recursive: true, mode: 0o700 })])

app.disable('x-powered-by')
app.use(async (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'no-referrer')
  const setCors = (origin) => {
    res.setHeader('Access-Control-Allow-Origin', origin)
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    res.setHeader('Access-Control-Max-Age', '600')
  }
  try {
    // These unauthenticated pairing endpoints must be discoverable by a new,
    // independently hosted SecureShare instance.
    if (['/api/public-key', '/api/invitations', '/api/acceptances'].includes(req.path)) {
      setCors('*')
    } else {
      // Uploads carry a bearer token and must come from the origin registered
      // for this pair.  Reflecting only that origin lets arbitrary SecureShare
      // domains communicate without giving every website CORS access.
      const match = req.path.match(/^\/api\/peers\/([a-zA-Z0-9_-]+)\/files$/)
      const requestOrigin = originOf(req.get('origin'))
      if (match && requestOrigin) {
        const peer = (await readState()).peers.find((entry) => entry.pairId === match[1])
        if (peer && originOf(peer.peerUrl) === requestOrigin) {
          res.setHeader('Vary', 'Origin')
          setCors(requestOrigin)
        }
      }
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204)
    next()
  } catch (error) { next(error) }
})
app.use(express.json({ limit: '256kb' }))

app.get('/api/health', async (_req, res) => res.json({ ok: true, port }))
app.get('/api/public-key', async (_req, res, next) => {
  try {
    const { identity } = await readState()
    if (!identity) return res.status(503).json({ error: 'This server has not completed local key setup.' })
    res.json(identity)
  } catch (error) { next(error) }
})

app.put('/api/identity', async (req, res, next) => {
  try {
    const { publicKey, fingerprint } = req.body || {}
    if (!publicKey || !fingerprint || !/^[a-f0-9]{64}$/i.test(fingerprint)) return res.status(400).json({ error: 'A valid public key and fingerprint are required.' })
    const state = await readState()
    if (state.identity && state.identity.fingerprint !== fingerprint) return res.status(409).json({ error: 'A server identity already exists. It cannot be replaced through the API.' })
    state.identity = { publicKey, fingerprint: fingerprint.toLowerCase(), createdAt: state.identity?.createdAt || now() }
    await writeState(state)
    res.status(201).json(state.identity)
  } catch (error) { next(error) }
})

app.get('/api/invitations', async (_req, res, next) => {
  try {
    const names = await fs.readdir(invitesPath)
    const invitations = await Promise.all(names.filter((name) => name.endsWith('.json')).map(async (name) => JSON.parse(await fs.readFile(path.join(invitesPath, name), 'utf8'))))
    res.json(invitations)
  } catch (error) { next(error) }
})

app.post('/api/invitations', async (req, res, next) => {
  try {
    await storeEnvelope(invitesPath, req.body || {})
    res.status(202).json({ accepted: true })
  } catch (error) { res.status(400).json({ error: error.message }) }
})

app.get('/api/acceptances', async (_req, res, next) => {
  try {
    const names = await fs.readdir(acceptancesPath)
    const acceptances = await Promise.all(names.filter((name) => name.endsWith('.json')).map(async (name) => JSON.parse(await fs.readFile(path.join(acceptancesPath, name), 'utf8'))))
    res.json(acceptances)
  } catch (error) { next(error) }
})

app.post('/api/acceptances', async (req, res) => {
  try {
    await storeEnvelope(acceptancesPath, req.body || {})
    res.status(202).json({ accepted: true })
  } catch (error) { res.status(400).json({ error: error.message }) }
})

app.post('/api/peers/provision', async (req, res, next) => {
  try {
    const pairId = id(req.body?.pairId)
    const peerUrl = String(req.body?.peerUrl || '').replace(/\/$/, '')
    const peerFingerprint = String(req.body?.peerFingerprint || '').toLowerCase()
    if (!pairId || !/^https?:\/\//.test(peerUrl) || !/^[a-f0-9]{64}$/.test(peerFingerprint)) return res.status(400).json({ error: 'Invalid pairing details.' })
    const state = await readState()
    if (state.peers.some((peer) => peer.pairId === pairId)) return res.status(409).json({ error: 'This pairing already exists.' })
    const inboundToken = crypto.randomBytes(32).toString('base64url')
    state.peers.push({ pairId, peerUrl, peerFingerprint, inboundTokenHash: sha256(inboundToken), status: 'provisioned', createdAt: now() })
    await fs.mkdir(peerFolder(pairId), { recursive: false, mode: 0o700 })
    await fs.writeFile(path.join(peerFolder(pairId), 'arrival-log.txt'), `SecureShare encrypted arrival log\npair_id=${pairId}\ncreated_at=${now()}\n\n`, { mode: 0o600 })
    await fs.writeFile(path.join(peerFolder(pairId), 'encrypted-index.json'), '[]\n', { mode: 0o600 })
    await writeState(state)
    res.status(201).json({ inboundToken })
  } catch (error) { next(error) }
})

app.post('/api/peers/:pairId/activate', async (req, res, next) => {
  try {
    const state = await readState()
    const peer = state.peers.find((entry) => entry.pairId === req.params.pairId)
    if (!peer) return res.status(404).json({ error: 'Unknown pairing.' })
    peer.status = 'active'
    peer.activatedAt = now()
    await writeState(state)
    res.json({ active: true })
  } catch (error) { next(error) }
})

async function authorizePeer(req, res, next) {
  try {
    const supplied = req.get('authorization')?.match(/^Bearer\s+(.+)$/i)?.[1]
    const peer = (await readState()).peers.find((entry) => entry.pairId === req.params.pairId)
    if (!supplied || !peer || peer.status !== 'active' || !tokenEquals(peer.inboundTokenHash, supplied)) return res.status(401).json({ error: 'Invalid or inactive peer credential.' })
    req.peer = peer
    next()
  } catch (error) { next(error) }
}

const upload = multer({ storage: multer.diskStorage({
  destination: (req, _file, callback) => callback(null, peerFolder(req.peer.pairId)),
  filename: (_req, _file, callback) => callback(null, `${crypto.randomUUID()}.bin`),
}) })

app.post('/api/peers/:pairId/files', authorizePeer, upload.single('ciphertext'), async (req, res, next) => {
  try {
    if (!req.file || !req.body?.iv || !req.body?.metadata || !req.body?.metadataIv) return res.status(400).json({ error: 'Encrypted file, IV, and encrypted metadata are required.' })
    const encryptedId = path.basename(req.file.filename, '.bin')
    const record = { encryptedId, storedName: req.file.filename, iv: req.body.iv, metadata: req.body.metadata, metadataIv: req.body.metadataIv, bytes: req.file.size, arrivedAt: now(), sha256: await fileHash(req.file.path) }
    const indexPath = path.join(peerFolder(req.peer.pairId), 'encrypted-index.json')
    const index = JSON.parse(await fs.readFile(indexPath, 'utf8'))
    index.push(record)
    await fs.writeFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, { mode: 0o600 })
    await fs.appendFile(path.join(peerFolder(req.peer.pairId), 'arrival-log.txt'), `encrypted_arrival_at=${record.arrivedAt} encrypted_id=${encryptedId} cipher_bytes=${record.bytes} sha256=${record.sha256}\n`)
    res.status(201).json({ encryptedId, arrivedAt: record.arrivedAt })
  } catch (error) { next(error) }
})

app.get('/api/peers/:pairId/files', async (req, res, next) => {
  try { res.json(JSON.parse(await fs.readFile(path.join(peerFolder(req.params.pairId), 'encrypted-index.json'), 'utf8'))) }
  catch (error) { if (error.code === 'ENOENT') return res.status(404).json({ error: 'Unknown pairing.' }); next(error) }
})

app.delete('/api/peers/:pairId/files/:encryptedId', async (req, res, next) => {
  try {
    const encryptedId = id(req.params.encryptedId)
    if (!encryptedId) return res.status(400).json({ error: 'A valid encrypted file ID is required.' })
    const folder = peerFolder(req.params.pairId)
    const indexPath = path.join(folder, 'encrypted-index.json')
    const index = JSON.parse(await fs.readFile(indexPath, 'utf8'))
    const record = index.find((entry) => entry.encryptedId === encryptedId)
    if (!record) return res.status(404).json({ error: 'Encrypted file not found.' })
    const storedName = path.basename(record.storedName || '')
    if (!storedName || storedName !== `${encryptedId}.bin`) return res.status(500).json({ error: 'Stored file record is invalid.' })
    try { await fs.unlink(path.join(folder, storedName)) }
    catch (error) { if (error.code !== 'ENOENT') throw error }
    await fs.writeFile(indexPath, `${JSON.stringify(index.filter((entry) => entry.encryptedId !== encryptedId), null, 2)}\n`, { mode: 0o600 })
    await fs.appendFile(path.join(folder, 'arrival-log.txt'), `encrypted_deleted_at=${now()} encrypted_id=${encryptedId}\n`)
    res.json({ deleted: true })
  } catch (error) { next(error) }
})

app.get('/api/peers/:pairId/files/:encryptedId', async (req, res) => {
  const fileName = `${id(req.params.encryptedId)}.bin`
  const target = path.join(peerFolder(req.params.pairId), fileName)
  try { await fs.access(target); res.type('application/octet-stream').sendFile(target) }
  catch { res.status(404).json({ error: 'Encrypted file not found.' }) }
})

app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found.' }))
app.use(express.static(path.join(process.cwd(), 'dist')))
app.use((_req, res) => res.sendFile(path.join(process.cwd(), 'dist', 'index.html')))
app.use((error, _req, res, _next) => { console.error(error); res.status(500).json({ error: 'The server could not complete this request.' }) })
app.listen(port, () => console.log(`SecureShare listening on port ${port}`))
