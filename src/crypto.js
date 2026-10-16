const encoder = new TextEncoder()
const decoder = new TextDecoder()
const identityStorage = 'secureshare.identity.v1'
const peersStorage = 'secureshare.peers.v1'
const iterations = 600000

const bytes = (length) => crypto.getRandomValues(new Uint8Array(length))
const encode = (value) => encoder.encode(typeof value === 'string' ? value : JSON.stringify(value))
const toBase64 = (value) => btoa(String.fromCharCode(...new Uint8Array(value)))
const fromBase64 = (value) => Uint8Array.from(atob(value), (character) => character.charCodeAt(0))

async function masterKey(password, salt) {
  const material = await crypto.subtle.importKey('raw', encode(password), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

async function encryptText(key, value) {
  const iv = bytes(12)
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encode(value))
  return { iv: toBase64(iv), ciphertext: toBase64(ciphertext) }
}

async function decryptText(key, payload) {
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(payload.iv) }, key, fromBase64(payload.ciphertext))
  return decoder.decode(plaintext)
}

export const hasLocalIdentity = () => Boolean(localStorage.getItem(identityStorage))

export async function fingerprint(publicKey) {
  const digest = await crypto.subtle.digest('SHA-256', encode(publicKey))
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

export async function setupIdentity(password) {
  const keyPair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt'])
  const publicKey = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  const privateKey = await crypto.subtle.exportKey('jwk', keyPair.privateKey)
  const salt = bytes(16)
  const key = await masterKey(password, salt)
  const encryptedPrivate = await encryptText(key, privateKey)
  const identity = { version: 1, salt: toBase64(salt), publicKey, encryptedPrivate }
  localStorage.setItem(identityStorage, JSON.stringify(identity))
  return { ...await unlockIdentity(password), created: true }
}

export async function unlockIdentity(password) {
  const stored = JSON.parse(localStorage.getItem(identityStorage) || 'null')
  if (!stored) throw new Error('No local identity is configured.')
  const key = await masterKey(password, fromBase64(stored.salt))
  const privateJwk = JSON.parse(await decryptText(key, stored.encryptedPrivate))
  const privateKey = await crypto.subtle.importKey('jwk', privateJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt'])
  const serverCredential = stored.encryptedServerCredential ? await decryptText(key, stored.encryptedServerCredential) : null
  return { key, privateKey, publicKey: stored.publicKey, fingerprint: await fingerprint(stored.publicKey), serverCredential }
}

// The server administrator credential is encrypted with the same non-extractable
// password-derived key as the local peer list. It is never sent to another peer.
export async function saveServerCredential(key, credential) {
  if (typeof credential !== 'string' || credential.length < 20) throw new Error('Invalid server credential.')
  const stored = JSON.parse(localStorage.getItem(identityStorage) || 'null')
  if (!stored) throw new Error('No local identity is configured.')
  stored.encryptedServerCredential = await encryptText(key, credential)
  localStorage.setItem(identityStorage, JSON.stringify(stored))
}

export async function encryptForPublicKey(publicJwk, value) {
  const key = await crypto.subtle.importKey('jwk', publicJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt'])
  const payload = encode(value)
  if (payload.byteLength > 430) throw new Error('Invite note or server URL is too long for this encryption envelope.')
  return toBase64(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, payload))
}

export async function decryptFromPrivateKey(privateKey, ciphertext) {
  return JSON.parse(decoder.decode(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, fromBase64(ciphertext))))
}

export const createPairKey = () => toBase64(bytes(32))

async function pairCryptoKey(pairKey, usage) {
  return crypto.subtle.importKey('raw', fromBase64(pairKey), { name: 'AES-GCM' }, false, usage)
}

export async function encryptFile(pairKey, file, pairId, message = {}) {
  const key = await pairCryptoKey(pairKey, ['encrypt'])
  const iv = bytes(12)
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encode(pairId) }, key, await file.arrayBuffer())
  const metadataIv = bytes(12)
  const metadata = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: metadataIv, additionalData: encode(pairId) }, key, encode({ name: file.name, type: file.type, size: file.size, title: String(message.title || ''), text: String(message.text || '') }))
  return { ciphertext: new Blob([encrypted], { type: 'application/octet-stream' }), iv: toBase64(iv), metadata: toBase64(metadata), metadataIv: toBase64(metadataIv) }
}

export async function decryptMessageMetadata(pairKey, pairId, record) {
  const key = await pairCryptoKey(pairKey, ['decrypt'])
  return JSON.parse(decoder.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(record.metadataIv), additionalData: encode(pairId) }, key, fromBase64(record.metadata))))
}

export async function decryptFile(pairKey, pairId, record, ciphertext) {
  const key = await pairCryptoKey(pairKey, ['decrypt'])
  const metadata = await decryptMessageMetadata(pairKey, pairId, record)
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(record.iv), additionalData: encode(pairId) }, key, await ciphertext.arrayBuffer())
  return { metadata, blob: new Blob([plain], { type: metadata.type || 'application/octet-stream' }) }
}

export async function loadPeers(key) {
  const stored = localStorage.getItem(peersStorage)
  if (!stored) return []
  return JSON.parse(await decryptText(key, JSON.parse(stored)))
}

export async function savePeers(key, peers) {
  localStorage.setItem(peersStorage, JSON.stringify(await encryptText(key, peers)))
}
