import { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { createPairKey, decryptFile, decryptFromPrivateKey, encryptFile, encryptForPublicKey, hasLocalIdentity, loadPeers, savePeers, setupIdentity, unlockIdentity } from './crypto'
import './styles.css'

const api = async (path, options = {}) => {
  const response = await fetch(path, options)
  const result = await response.json()
  if (!response.ok) throw new Error(result.error || 'Request failed.')
  return result
}
const remote = (url, path) => `${url.replace(/\/$/, '')}${path}`

function LockScreen({ onUnlock }) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const isSetup = !hasLocalIdentity()
  const submit = async (event) => {
    event.preventDefault(); setError('')
    if (isSetup && password !== confirm) return setError('Passwords do not match.')
    if (password.length < 12) return setError('Use at least 12 characters.')
    setBusy(true)
    try { await onUnlock(password, isSetup) } catch (failure) { setError(failure.message) } finally { setBusy(false) }
  }
  return <main className="lock-screen"><section className="lock-card"><div className="lock-mark"><i></i><i></i><i></i></div><p className="eyebrow">SECURESHARE</p><h1>{isSetup ? 'Create this server’s key' : 'Unlock SecureShare'}</h1><p>{isSetup ? 'This password encrypts the private key only in this browser.' : 'Your private key is decrypted locally for this session.'}</p><form onSubmit={submit}><label>Password<input type="password" autoFocus required value={password} onChange={(event) => setPassword(event.target.value)} /></label>{isSetup && <label>Confirm password<input type="password" required value={confirm} onChange={(event) => setConfirm(event.target.value)} /></label>}{error && <span className="form-error">{error}</span>}<button disabled={busy}>{busy ? 'Preparing secure keys…' : isSetup ? 'Create and unlock' : 'Unlock'}</button></form></section></main>
}

function App() {
  const [session, setSession] = useState(null)
  const [peers, setPeers] = useState([])
  const [invites, setInvites] = useState([])
  const [acceptances, setAcceptances] = useState([])
  const [targetUrl, setTargetUrl] = useState('')
  const [note, setNote] = useState('')
  const [notice, setNotice] = useState('')
  const [selectedPeer, setSelectedPeer] = useState('')
  const [selectedFile, setSelectedFile] = useState(null)
  const [received, setReceived] = useState([])
  const [publicUrl, setPublicUrl] = useState('')

  const persistPeers = async (next) => { setPeers(next); await savePeers(session.key, next) }
  const refreshEncryptedMessages = async (activeSession = session) => {
    if (!activeSession) return
    const decode = async (item) => { try { return { ...item, payload: await decryptFromPrivateKey(activeSession.privateKey, item.ciphertext) } } catch { return null } }
    const [pendingInvites, pendingAcceptances] = await Promise.all([api('/api/invitations'), api('/api/acceptances')])
    setInvites((await Promise.all(pendingInvites.map(decode))).filter(Boolean))
    setAcceptances((await Promise.all(pendingAcceptances.map(decode))).filter(Boolean))
  }
  const unlock = async (password, isSetup) => {
    const configuration = await api('/api/config')
    if (!configuration.publicUrl) throw new Error('This server needs PUBLIC_URL set to its externally reachable HTTPS address.')
    const nextSession = isSetup ? await setupIdentity(password) : await unlockIdentity(password)
    await api('/api/identity', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey: nextSession.publicKey, fingerprint: nextSession.fingerprint }) })
    setSession(nextSession)
    setPublicUrl(configuration.publicUrl)
    setPeers(await loadPeers(nextSession.key))
    await refreshEncryptedMessages(nextSession)
  }
  useEffect(() => { if (session) refreshEncryptedMessages() }, [session])
  useEffect(() => {
    const peer = peers.find((entry) => entry.pairId === selectedPeer)
    if (!peer) return setReceived([])
    api(`/api/peers/${peer.pairId}/files`).then(setReceived).catch(() => setReceived([]))
  }, [selectedPeer, peers])

  const invitePeer = async (event) => {
    event.preventDefault(); setNotice('')
    try {
      const url = targetUrl.replace(/\/$/, '')
      const target = await (await fetch(remote(url, '/api/public-key'))).json()
      if (!target.publicKey) throw new Error(target.error || 'The target has no public key.')
      const pairId = crypto.randomUUID()
      const provision = await api('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pairId, peerUrl: url, peerFingerprint: target.fingerprint }) })
      const pairKey = createPairKey()
      const ciphertext = await encryptForPublicKey(target.publicKey, { v: 1, p: pairId, u: publicUrl, k: pairKey, t: provision.inboundToken, n: note.slice(0, 80) })
      const response = await fetch(remote(url, '/api/invitations'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pairId, sourceUrl: publicUrl, sourceFingerprint: session.fingerprint, ciphertext }) })
      if (!response.ok) throw new Error((await response.json()).error || 'Invitation delivery failed.')
      await persistPeers([...peers, { pairId, targetUrl: url, targetFingerprint: target.fingerprint, pairKey, status: 'invited' }])
      setTargetUrl(''); setNote(''); setNotice('Encrypted invitation delivered and awaiting confirmation.')
    } catch (failure) { setNotice(failure.message) }
  }

  const confirmInvite = async (invite) => {
    setNotice('')
    try {
      const source = await (await fetch(remote(invite.sourceUrl, '/api/public-key'))).json()
      if (source.fingerprint !== invite.sourceFingerprint) throw new Error('The public-key fingerprint does not match the invitation.')
      const provision = await api('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pairId: invite.payload.p, peerUrl: invite.sourceUrl, peerFingerprint: invite.sourceFingerprint }) })
      const ciphertext = await encryptForPublicKey(source.publicKey, { v: 1, p: invite.payload.p, u: publicUrl, t: provision.inboundToken })
      const response = await fetch(remote(invite.sourceUrl, '/api/acceptances'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pairId: invite.payload.p, sourceUrl: publicUrl, sourceFingerprint: session.fingerprint, ciphertext }) })
      if (!response.ok) throw new Error('Acceptance delivery failed.')
      await api(`/api/peers/${invite.payload.p}/activate`, { method: 'POST' })
      await persistPeers([...peers.filter((peer) => peer.pairId !== invite.payload.p), { pairId: invite.payload.p, targetUrl: invite.sourceUrl, targetFingerprint: invite.sourceFingerprint, pairKey: invite.payload.k, uploadToken: invite.payload.t, status: 'active' }])
      setInvites((current) => current.filter((entry) => entry.pairId !== invite.pairId)); setNotice('Pairing confirmed. This peer can now exchange encrypted files.')
    } catch (failure) { setNotice(failure.message) }
  }

  const activateAcceptance = async (acceptance) => {
    const pending = peers.find((peer) => peer.pairId === acceptance.payload.p)
    if (!pending) return setNotice('This acceptance does not match a local invitation.')
    await api(`/api/peers/${pending.pairId}/activate`, { method: 'POST' })
    await persistPeers(peers.map((peer) => peer.pairId === pending.pairId ? { ...peer, targetUrl: acceptance.payload.u, uploadToken: acceptance.payload.t, status: 'active' } : peer))
    setAcceptances((current) => current.filter((entry) => entry.pairId !== acceptance.pairId)); setNotice('Pairing activated.')
  }

  const sendFile = async (event) => {
    event.preventDefault(); setNotice('')
    const peer = peers.find((entry) => entry.pairId === selectedPeer)
    if (!peer || !selectedFile || peer.status !== 'active') return setNotice('Choose an active peer and a file.')
    try {
      const encrypted = await encryptFile(peer.pairKey, selectedFile, peer.pairId)
      const form = new FormData(); form.append('ciphertext', encrypted.ciphertext, 'encrypted.bin'); form.append('iv', encrypted.iv); form.append('metadata', encrypted.metadata); form.append('metadataIv', encrypted.metadataIv)
      const response = await fetch(remote(peer.targetUrl, `/api/peers/${peer.pairId}/files`), { method: 'POST', headers: { Authorization: `Bearer ${peer.uploadToken}` }, body: form })
      if (!response.ok) throw new Error((await response.json()).error || 'Encrypted upload failed.')
      setSelectedFile(null); setNotice('Encrypted file delivered.')
    } catch (failure) { setNotice(failure.message) }
  }

  const download = async (record) => {
    const peer = peers.find((entry) => entry.pairId === selectedPeer)
    try {
      const encrypted = await fetch(`/api/peers/${peer.pairId}/files/${record.encryptedId}`)
      const result = await decryptFile(peer.pairKey, peer.pairId, record, await encrypted.blob())
      const link = Object.assign(document.createElement('a'), { href: URL.createObjectURL(result.blob), download: result.metadata.name })
      link.click(); URL.revokeObjectURL(link.href)
    } catch { setNotice('Could not decrypt this file.') }
  }

  if (!session) return <LockScreen onUnlock={unlock} />
  const activePeers = peers.filter((peer) => peer.status === 'active')
  return <main className="workspace"><header><div className="brand"><span className="brand-mark"><i></i><i></i><i></i></span>secure<span>share</span></div><div className="fingerprint">Public key <code>{session.fingerprint.slice(0, 16)}…</code></div><button onClick={() => setSession(null)}>Lock</button></header><section className="layout"><aside><h2>Connections</h2><form className="connect-form" onSubmit={invitePeer}><label>Server address<input required placeholder="https://server.example:23456" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} /></label><label>Encrypted note<textarea maxLength="80" value={note} onChange={(event) => setNote(event.target.value)} /></label><button>Request connection</button></form><div className="peer-list">{peers.map((peer) => <div key={peer.pairId}><strong>{peer.targetUrl}</strong><small>{peer.status}</small></div>)}</div></aside><section className="main-pane"><h1>Encrypted inbox</h1>{notice && <p className="notice">{notice}</p>}<div className="pending">{invites.map((invite) => <article key={invite.pairId}><p><b>Connection request</b> from {invite.sourceUrl}</p><code>{invite.sourceFingerprint.slice(0, 16)}…</code>{invite.payload.n && <p className="invite-note">{invite.payload.n}</p>}<button onClick={() => confirmInvite(invite)}>Verify and confirm</button></article>)}{acceptances.map((acceptance) => <article key={acceptance.pairId}><p>Connection acceptance received.</p><button onClick={() => activateAcceptance(acceptance)}>Activate pairing</button></article>)}</div><form className="send-form" onSubmit={sendFile}><label>Send to<select value={selectedPeer} onChange={(event) => setSelectedPeer(event.target.value)}><option value="">Choose a paired server</option>{activePeers.map((peer) => <option value={peer.pairId} key={peer.pairId}>{peer.targetUrl}</option>)}</select></label><input type="file" onChange={(event) => setSelectedFile(event.target.files[0])} /><button>Encrypt and send</button></form><div className="files">{received.map((record) => <button key={record.encryptedId} onClick={() => download(record)}>Decrypt and download · {record.arrivedAt}</button>)}</div></section></section></main>
}

createRoot(document.getElementById('root')).render(<App />)
