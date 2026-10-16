import { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { createPairKey, decryptFile, decryptFromPrivateKey, decryptMessageMetadata, encryptFile, encryptForPublicKey, hasLocalIdentity, loadPeers, savePeers, saveServerCredential, setupIdentity, unlockIdentity } from './crypto'
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
  const [setupCredential, setSetupCredential] = useState('')
  const isSetup = !hasLocalIdentity()
  const submit = async (event) => {
    event.preventDefault(); setError('')
    if (isSetup && password !== confirm) return setError('Passwords do not match.')
    if (password.length < 12) return setError('Use at least 12 characters.')
    setBusy(true)
    try { await onUnlock(password, isSetup, setupCredential) } catch (failure) { setError(failure.message) } finally { setBusy(false) }
  }
  return <main className="lock-screen"><section className="lock-card"><div className="lock-mark"><i></i><i></i><i></i></div><p className="eyebrow">SECURESHARE</p><h1>{isSetup ? 'Create this server’s key' : 'Unlock SecureShare'}</h1><p>{isSetup ? 'Enter the one-time server setup credential, then choose a password that encrypts the private key only in this browser.' : 'Your private key is decrypted locally for this session.'}</p><form onSubmit={submit}><label>{isSetup ? 'Server setup credential' : 'Server recovery credential (only after upgrade)'}<input type="password" autoFocus={isSetup} required={isSetup} value={setupCredential} onChange={(event) => setSetupCredential(event.target.value)} /></label><label>Password<input type="password" autoFocus={!isSetup} required value={password} onChange={(event) => setPassword(event.target.value)} /></label>{isSetup && <label>Confirm password<input type="password" required value={confirm} onChange={(event) => setConfirm(event.target.value)} /></label>}{error && <span className="form-error">{error}</span>}<button disabled={busy}>{busy ? 'Preparing secure keys…' : isSetup ? 'Create and unlock' : 'Unlock'}</button></form></section></main>
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
  const [messageTitle, setMessageTitle] = useState('')
  const [messageText, setMessageText] = useState('')
  const [received, setReceived] = useState([])

  const adminHeaders = (activeSession = session) => activeSession?.serverCredential ? { Authorization: `Bearer ${activeSession.serverCredential}` } : {}

  const persistPeers = async (next) => { setPeers(next); await savePeers(session.key, next) }
  const refreshEncryptedMessages = async (activeSession = session) => {
    if (!activeSession) return
    const decode = async (item) => { try { return { ...item, payload: await decryptFromPrivateKey(activeSession.privateKey, item.ciphertext) } } catch { return null } }
    const headers = adminHeaders(activeSession)
    const [pendingInvites, pendingAcceptances] = await Promise.all([api('/api/invitations', { headers }), api('/api/acceptances', { headers })])
    setInvites((await Promise.all(pendingInvites.map(decode))).filter(Boolean))
    setAcceptances((await Promise.all(pendingAcceptances.map(decode))).filter(Boolean))
  }
  const unlock = async (password, isSetup, setupCredential) => {
    const nextSession = isSetup ? await setupIdentity(password) : await unlockIdentity(password)
    const headers = { 'Content-Type': 'application/json', ...(nextSession.serverCredential ? { Authorization: `Bearer ${nextSession.serverCredential}` } : {}), ...(setupCredential ? { 'X-Setup-Token': setupCredential } : {}) }
    const registration = await api('/api/identity', { method: 'PUT', headers, body: JSON.stringify({ publicKey: nextSession.publicKey, fingerprint: nextSession.fingerprint }) })
    if (registration.adminToken) { await saveServerCredential(nextSession.key, registration.adminToken); nextSession.serverCredential = registration.adminToken }
    if (!nextSession.serverCredential) throw new Error('This browser does not hold the server administrator credential.')
    setSession(nextSession)
    setPeers(await loadPeers(nextSession.key))
    await refreshEncryptedMessages(nextSession)
  }
  useEffect(() => { if (session) refreshEncryptedMessages() }, [session])
  useEffect(() => {
    const peer = peers.find((entry) => entry.pairId === selectedPeer)
    if (!peer) return setReceived([])
    let cancelled = false
    const refreshReceived = async () => {
      try {
        const records = await api(`/api/peers/${peer.pairId}/files`, { headers: { Authorization: `Bearer ${peer.inboxToken}` } })
        const messages = await Promise.all(records.map(async (record) => {
          try { return { ...record, message: await decryptMessageMetadata(peer.pairKey, peer.pairId, record) } }
          catch { return record }
        }))
        if (!cancelled) setReceived(messages)
      } catch { if (!cancelled) setReceived([]) }
    }
    refreshReceived()
    const interval = window.setInterval(refreshReceived, 5000)
    return () => { cancelled = true; window.clearInterval(interval) }
  }, [selectedPeer, peers])

  const invitePeer = async (event) => {
    event.preventDefault(); setNotice('')
    try {
      const url = targetUrl.replace(/\/$/, '')
      const target = await (await fetch(remote(url, '/api/public-key'))).json()
      if (!target.publicKey) throw new Error(target.error || 'The target has no public key.')
      const pairId = crypto.randomUUID()
      const provision = await api('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json', ...adminHeaders() }, body: JSON.stringify({ pairId, peerUrl: url, peerFingerprint: target.fingerprint }) })
      const pairKey = createPairKey()
      const ciphertext = await encryptForPublicKey(target.publicKey, { v: 1, p: pairId, u: location.origin, k: pairKey, t: provision.inboundToken, n: note.slice(0, 80) })
      const response = await fetch(remote(url, '/api/invitations'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pairId, sourceUrl: location.origin, sourceFingerprint: session.fingerprint, ciphertext }) })
      if (!response.ok) throw new Error((await response.json()).error || 'Invitation delivery failed.')
      await persistPeers([...peers, { pairId, targetUrl: url, targetFingerprint: target.fingerprint, pairKey, inboxToken: provision.inboundToken, status: 'invited' }])
      setTargetUrl(''); setNote(''); setNotice('Encrypted invitation delivered and awaiting confirmation.')
    } catch (failure) { setNotice(failure.message) }
  }

  const confirmInvite = async (invite) => {
    setNotice('')
    try {
      const source = await (await fetch(remote(invite.sourceUrl, '/api/public-key'))).json()
      if (source.fingerprint !== invite.sourceFingerprint) throw new Error('The public-key fingerprint does not match the invitation.')
      const provision = await api('/api/peers/provision', { method: 'POST', headers: { 'Content-Type': 'application/json', ...adminHeaders() }, body: JSON.stringify({ pairId: invite.payload.p, peerUrl: invite.sourceUrl, peerFingerprint: invite.sourceFingerprint }) })
      const ciphertext = await encryptForPublicKey(source.publicKey, { v: 1, p: invite.payload.p, u: location.origin, t: provision.inboundToken })
      const response = await fetch(remote(invite.sourceUrl, '/api/acceptances'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pairId: invite.payload.p, sourceUrl: location.origin, sourceFingerprint: session.fingerprint, ciphertext }) })
      if (!response.ok) throw new Error('Acceptance delivery failed.')
      await api(`/api/peers/${invite.payload.p}/activate`, { method: 'POST', headers: adminHeaders() })
      await persistPeers([...peers.filter((peer) => peer.pairId !== invite.payload.p), { pairId: invite.payload.p, targetUrl: invite.sourceUrl, targetFingerprint: invite.sourceFingerprint, pairKey: invite.payload.k, uploadToken: invite.payload.t, inboxToken: provision.inboundToken, status: 'active' }])
      try { await api(`/api/invitations/${invite.pairId}`, { method: 'DELETE', headers: adminHeaders() }) } catch { /* The active pairing also suppresses a stale request. */ }
      setInvites((current) => current.filter((entry) => entry.pairId !== invite.pairId)); setNotice('Pairing confirmed. This peer can now exchange encrypted files.')
    } catch (failure) { setNotice(failure.message) }
  }

  const activateAcceptance = async (acceptance) => {
    const pending = peers.find((peer) => peer.pairId === acceptance.payload.p)
    if (!pending) return setNotice('This acceptance does not match a local invitation.')
    try {
      await api(`/api/peers/${pending.pairId}/activate`, { method: 'POST', headers: adminHeaders() })
      await persistPeers(peers.map((peer) => peer.pairId === pending.pairId ? { ...peer, targetUrl: acceptance.payload.u, uploadToken: acceptance.payload.t, status: 'active' } : peer))
      try { await api(`/api/acceptances/${acceptance.pairId}`, { method: 'DELETE', headers: adminHeaders() }) } catch { /* The active pairing also suppresses a stale request. */ }
      setAcceptances((current) => current.filter((entry) => entry.pairId !== acceptance.pairId)); setNotice('Pairing activated.')
    } catch (failure) { setNotice(failure.message) }
  }

  const sendFile = async (event) => {
    event.preventDefault(); setNotice('')
    const peer = peers.find((entry) => entry.pairId === selectedPeer)
    if (!peer || !selectedFile || peer.status !== 'active') return setNotice('Choose an active peer and a file.')
    if (!messageTitle.trim()) return setNotice('Add a message title.')
    try {
      const encrypted = await encryptFile(peer.pairKey, selectedFile, peer.pairId, { title: messageTitle.trim(), text: messageText.trim() })
      const form = new FormData(); form.append('ciphertext', encrypted.ciphertext, 'encrypted.bin'); form.append('iv', encrypted.iv); form.append('metadata', encrypted.metadata); form.append('metadataIv', encrypted.metadataIv)
      const response = await fetch(remote(peer.targetUrl, `/api/peers/${peer.pairId}/files`), { method: 'POST', headers: { Authorization: `Bearer ${peer.uploadToken}` }, body: form })
      if (!response.ok) throw new Error((await response.json()).error || 'Encrypted upload failed.')
      setSelectedFile(null); setMessageTitle(''); setMessageText(''); setNotice('Encrypted file delivered.')
    } catch (failure) { setNotice(failure.message) }
  }

  const download = async (record) => {
    const peer = peers.find((entry) => entry.pairId === selectedPeer)
    try {
      const encrypted = await fetch(`/api/peers/${peer.pairId}/files/${record.encryptedId}`, { headers: { Authorization: `Bearer ${peer.inboxToken}` } })
      if (!encrypted.ok) throw new Error('Encrypted file download failed.')
      const result = await decryptFile(peer.pairKey, peer.pairId, record, await encrypted.blob())
      const link = Object.assign(document.createElement('a'), { href: URL.createObjectURL(result.blob), download: result.metadata.name })
      link.click(); URL.revokeObjectURL(link.href)
    } catch { setNotice('Could not decrypt this file.') }
  }

  const deleteMessage = async (record) => {
    const peer = peers.find((entry) => entry.pairId === selectedPeer)
    if (!peer || !window.confirm(`Delete “${record.message?.title || record.message?.name || 'this message'}” from this inbox?`)) return
    try {
      await api(`/api/peers/${peer.pairId}/files/${record.encryptedId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${peer.inboxToken}` } })
      setReceived((current) => current.filter((entry) => entry.encryptedId !== record.encryptedId))
      setNotice('Message deleted.')
    } catch (failure) { setNotice(failure.message) }
  }

  const deleteRequest = async (kind, request) => {
    if (!window.confirm('Delete this connection request?')) return
    try {
      await api(`/api/${kind}/${request.pairId}`, { method: 'DELETE', headers: adminHeaders() })
      if (kind === 'invitations') setInvites((current) => current.filter((entry) => entry.pairId !== request.pairId))
      else setAcceptances((current) => current.filter((entry) => entry.pairId !== request.pairId))
      setNotice('Connection request deleted.')
    } catch (failure) { setNotice(failure.message) }
  }

  if (!session) return <LockScreen onUnlock={unlock} />
  const activePeers = peers.filter((peer) => peer.status === 'active')
  const pendingInvites = invites.filter((invite) => peers.find((peer) => peer.pairId === invite.payload.p)?.status !== 'active')
  const pendingAcceptances = acceptances.filter((acceptance) => peers.find((peer) => peer.pairId === acceptance.payload.p)?.status !== 'active')
  return <main className="workspace"><header><div className="brand"><span className="brand-mark"><i></i><i></i><i></i></span>secure<span>share</span></div><div className="fingerprint">Public key <code>{session.fingerprint.slice(0, 16)}…</code></div><button onClick={() => setSession(null)}>Lock</button></header><section className="layout"><aside><h2>Connections</h2><form className="connect-form" onSubmit={invitePeer}><label>Server address<input required placeholder="https://server.example:23456" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} /></label><label>Encrypted note<textarea maxLength="80" value={note} onChange={(event) => setNote(event.target.value)} /></label><button>Request connection</button></form><div className="peer-list">{peers.map((peer) => <div key={peer.pairId}><strong>{peer.targetUrl}</strong><small>{peer.status}</small></div>)}</div></aside><section className="main-pane"><h1>Encrypted inbox</h1>{notice && <p className="notice">{notice}</p>}<div className="pending">{pendingInvites.map((invite) => <article key={invite.pairId}><p><b>Connection request</b> from {invite.sourceUrl}</p><code>{invite.sourceFingerprint.slice(0, 16)}…</code>{invite.payload.n && <p className="invite-note">{invite.payload.n}</p>}<div className="request-actions"><button onClick={() => confirmInvite(invite)}>Verify and confirm</button><button className="delete-request" type="button" onClick={() => deleteRequest('invitations', invite)}>Delete request</button></div></article>)}{pendingAcceptances.map((acceptance) => <article key={acceptance.pairId}><p>Connection acceptance received.</p><div className="request-actions"><button onClick={() => activateAcceptance(acceptance)}>Activate pairing</button><button className="delete-request" type="button" onClick={() => deleteRequest('acceptances', acceptance)}>Delete request</button></div></article>)}</div><form className="send-form" onSubmit={sendFile}><label>Send to<select value={selectedPeer} onChange={(event) => setSelectedPeer(event.target.value)}><option value="">Choose a paired server</option>{activePeers.map((peer) => <option value={peer.pairId} key={peer.pairId}>{peer.targetUrl}</option>)}</select></label><label>Message title<input required maxLength="120" value={messageTitle} onChange={(event) => setMessageTitle(event.target.value)} placeholder="Title" /></label><label>Message<textarea maxLength="2000" value={messageText} onChange={(event) => setMessageText(event.target.value)} placeholder="Optional encrypted note" /></label><input required type="file" onChange={(event) => setSelectedFile(event.target.files[0])} /><button>Encrypt and send</button></form><div className="files">{received.map((record) => <article className="file-message" key={record.encryptedId}><button className="download-message" onClick={() => download(record)}><strong>{record.message?.title || record.message?.name || 'Encrypted file'}</strong>{record.message?.text && <span>{record.message.text}</span>}<small>{record.arrivedAt}</small></button><button className="delete-message" type="button" onClick={() => deleteMessage(record)}>Delete</button></article>)}</div></section></section></main>
}

createRoot(document.getElementById('root')).render(<App />)
