import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import {
  Activity, AlertCircle, ArrowDownToLine, ArrowLeft, ArrowRight, ArrowUpRight, BadgeCheck,
  Binary, Check, CheckCircle2, ChevronDown, ChevronRight, CircleHelp,
  Clock3, CloudUpload, Cpu, Database, File, FileCheck2, FileImage,
  FileSearch, FileText, Fingerprint, Gauge, HardDrive, History, Image as ImageIcon,
  Info, Layers3, LockKeyhole, LogOut, Menu, Network, RefreshCw, ScanLine, Search,
  Shield, ShieldAlert, ShieldCheck, Sparkles, Upload, X, Zap,
} from 'lucide-react'
import { api } from './api'
import { supabase, supabaseConfigured } from './supabase'
import { investigationStore } from './investigationStore'

const MAX_BYTES = 15 * 1024 * 1024
const ACCEPTED = ['.jpg', '.jpeg', '.png', '.webp', '.pdf']

// Full investigation reports live in IndexedDB so OCR and forensic payloads
// do not compete with the small localStorage history index.
const ARCHIVE_DB = 'scamscan.archive'
const ARCHIVE_STORE = 'reports'
function openArchiveDB() {
  return new Promise((resolve, reject) => {
    if (!('indexedDB' in window)) return reject(new Error('This browser does not support local report storage.'))
    const request = indexedDB.open(ARCHIVE_DB, 1)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(ARCHIVE_STORE)) db.createObjectStore(ARCHIVE_STORE, { keyPath: 'scan_id' })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error || new Error('Could not open the local report archive.'))
  })
}
function saveArchivedReport(record) {
  return openArchiveDB().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(ARCHIVE_STORE, 'readwrite')
    tx.objectStore(ARCHIVE_STORE).put(record)
    tx.oncomplete = () => { db.close(); resolve(true) }
    tx.onerror = tx.onabort = () => { db.close(); reject(tx.error || new Error('Could not save this report.')) }
  }))
}
function readArchivedReport(scanId) {
  return openArchiveDB().then((db) => new Promise((resolve, reject) => {
    const request = db.transaction(ARCHIVE_STORE, 'readonly').objectStore(ARCHIVE_STORE).get(scanId)
    request.onsuccess = () => { const value = request.result || null; db.close(); resolve(value) }
    request.onerror = () => { db.close(); reject(request.error || new Error('Could not read this report.')) }
  }))
}
function clearArchivedReports() {
  return openArchiveDB().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(ARCHIVE_STORE, 'readwrite')
    tx.objectStore(ARCHIVE_STORE).clear()
    tx.oncomplete = () => { db.close(); resolve(true) }
    tx.onerror = tx.onabort = () => { db.close(); reject(tx.error || new Error('Could not clear the report archive.')) }
  }))
}

const NAV = [
  { id: 'overview', label: 'Overview', icon: Gauge, group: 'WORKSPACE' },
  { id: 'new-scan', label: 'New investigation', icon: ScanLine, group: 'WORKSPACE' },
  { id: 'history', label: 'Scan history', icon: History, group: 'WORKSPACE' },
]

function formatBytes(bytes = 0) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}
function titleCase(value = '') {
  return String(value).replaceAll('_', ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}
function dateLabel(value) {
  try { return new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) }
  catch { return '—' }
}
function riskTone(level = '') {
  const v = String(level).toLowerCase()
  if (v === 'high') return 'danger'
  if (v === 'medium') return 'warning'
  if (v === 'low') return 'caution'
  return 'safe'
}
function IconBox({ icon: Icon, tone = 'blue' }) {
  return <span className={`icon-box ${tone}`}><Icon size={17} strokeWidth={1.8} /></span>
}
function EmptyState({ icon: Icon = FileSearch, title, detail, action }) {
  return <div className="empty-state"><span className="empty-icon"><Icon size={23} /></span><h3>{title}</h3><p>{detail}</p>{action}</div>
}
function SectionTitle({ eyebrow, title, detail, right }) {
  return <div className="section-title"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1>{detail && <p>{detail}</p>}</div>{right}</div>
}

function DashboardApp({ user, onSignOut }) {
  const [page, setPage] = useState('overview')
  const [health, setHealth] = useState(null)
  const [system, setSystem] = useState(null)
  const [backendError, setBackendError] = useState('')
  const [file, setFile] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)
  const [stage, setStage] = useState('')
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [ocr, setOcr] = useState(null)
  const [originalFile, setOriginalFile] = useState(null)
  const [activeTab, setActiveTab] = useState('summary')
  const [history, setHistory] = useState([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const [mobileNav, setMobileNav] = useState(false)
  const [accountMenuOpen, setAccountMenuOpen] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  const [language, setLanguage] = useState(() => localStorage.getItem('scamscan.language') || 'en')
  const [showGuide, setShowGuide] = useState(() => localStorage.getItem('scamscan.guide.seen') !== 'yes')
  const inputRef = useRef(null)

  const refreshSystem = useCallback(async () => {
    try {
      const [h, s] = await Promise.all([api.health(), api.systemInfo()])
      setHealth(h); setSystem(s); setBackendError('')
    } catch (e) { setHealth(null); setSystem(null); setBackendError(e.message) }
  }, [])

  useEffect(() => { refreshSystem() }, [refreshSystem])

  // Cloud history is reloaded for each authenticated account. RLS also enforces
  // ownership on the server, even if a client-side filter is bypassed.
  useEffect(() => {
    let active = true
    setHistoryLoading(true)
    investigationStore.list(user.id)
      .then((rows) => { if (active) setHistory(rows) })
      .catch((loadError) => { if (active) setError(`Could not load cloud history: ${loadError.message}`) })
      .finally(() => { if (active) setHistoryLoading(false) })
    return () => { active = false }
  }, [user.id])

  const setSelectedFile = (candidate) => {
    setError(''); setResult(null); setOcr(null)
    if (!candidate) return
    const ext = `.${candidate.name.split('.').pop().toLowerCase()}`
    if (!ACCEPTED.includes(ext)) { setFile(null); setError('Unsupported file type. Upload JPG, JPEG, PNG, WEBP or PDF.'); return }
    if (candidate.size > MAX_BYTES) { setFile(null); setError('File exceeds the backend limit of 15 MB.'); return }
    if (!candidate.size) { setFile(null); setError('This file is empty. Choose another document.'); return }
    setFile(candidate)
  }

  const runAnalysis = async () => {
    if (!file || busy) return
    setBusy(true); setError(''); setResult(null); setOcr(null); setStage('Running OCR extraction…')
    try {
      // The current backend returns OCR text from /api/ocr, while /api/analyze
      // returns the intelligence, forensic and risk modules. Run both on one file.
      const ocrPromise = api.ocr(file).then((data) => { setOcr(data); return data })
      setStage('Inspecting document structure and forensic indicators…')
      const analysisPromise = api.analyze(file)
      const [ocrData, analysisData] = await Promise.all([ocrPromise, analysisPromise])
      setOcr(ocrData); setResult(analysisData); setActiveTab('summary'); setPage('results')
      // Create a stable local ID even if an older backend response omits scan_id.
      const scanId = analysisData.scan_id || (crypto.randomUUID ? crypto.randomUUID() : `scan-${Date.now()}`)
      const savedResult = { ...analysisData, scan_id: scanId, filename: analysisData.filename || file.name, file_size_bytes: analysisData.file_size_bytes || file.size }
      const entry = {
        scan_id: scanId,
        filename: savedResult.filename,
        file_type: savedResult.file_type || file.name.split('.').pop(),
        file_size_bytes: savedResult.file_size_bytes,
        risk_score: savedResult.risk_assessment?.risk_score ?? null,
        risk_level: savedResult.risk_assessment?.risk_level || 'unknown',
        finding_count: savedResult.risk_assessment?.finding_count ?? 0,
        created_at: new Date().toISOString(),
        has_report: true,
      }
      // Persist the report, OCR output and original document in IndexedDB.
      // Store the original as a Blob plus its filename/type metadata.
      try {
        await saveArchivedReport({
          scan_id: scanId,
          owner_user_id: user.id,
          // Store only the original file locally. Full report/OCR now live in Supabase.
          original_blob: file,
          original_file_name: file.name,
          original_file_type: file.type || 'application/octet-stream',
          original_last_modified: file.lastModified || Date.now(),
          saved_at: entry.created_at,
        })
        setOriginalFile(file)
      } catch (storageError) {
        console.error('ScamScan report archive:', storageError)
        entry.has_report = false
        setOriginalFile(file)
        setError('Analysis completed, but this browser could not save the complete archive. The original file is still available until you leave this report.')
      }
      setResult(savedResult)
      // Store the complete analysis and OCR payload in Supabase JSONB.
      // The original uploaded file remains local and is never sent to cloud storage.
      try {
        const cloudEntry = await investigationStore.save(user.id, savedResult, ocrData)
        setHistory((items) => [cloudEntry, ...items.filter((item) => item.scan_id !== cloudEntry.scan_id)])
      } catch (cloudError) {
        console.error('ScamScan cloud history save:', cloudError)
        setError(`Analysis completed, but cloud history could not be saved: ${cloudError.message}. Your report remains open on this device.`)
      }
    } catch (e) {
      setError(e.message || 'Analysis failed. Please try again.')
    } finally { setBusy(false); setStage('') }
  }

  const openHistoryItem = async (item) => {
    setError('')
    try {
      // Fetch report JSON from the authenticated user's cloud archive.
      const cloudRecord = await investigationStore.get(user.id, item.scan_id)
      setResult(cloudRecord.report)
      setOcr(cloudRecord.ocr || null)

      // Original document bytes are deliberately not uploaded. Restore them
      // only if this browser still has the local IndexedDB copy.
      try {
        const localRecord = await readArchivedReport(item.scan_id)
        if (localRecord?.owner_user_id === user.id && localRecord?.original_blob) {
          const restoredFile = new File(
            [localRecord.original_blob],
            localRecord.original_file_name || item.filename || 'original-document',
            {
              type: localRecord.original_file_type || localRecord.original_blob.type || 'application/octet-stream',
              lastModified: localRecord.original_last_modified || Date.now(),
            }
          )
          setOriginalFile(restoredFile)
        } else setOriginalFile(null)
      } catch { setOriginalFile(null) }

      setActiveTab('summary')
      setPage('results')
    } catch (cloudError) {
      setError(`Could not open this cloud report: ${cloudError.message}`)
      setPage('history')
    }
  }

  const openOriginalDocument = () => {
    if (!originalFile) {
      setError('Original document is not available for this history entry. Older scans may only contain report data.')
      return
    }

    const blob = originalFile instanceof Blob
      ? originalFile
      : new Blob([originalFile], { type: originalFile.type || 'application/octet-stream' })
    const objectUrl = URL.createObjectURL(blob)
    const openedWindow = window.open(objectUrl, '_blank')
    if (openedWindow) openedWindow.opener = null

    if (!openedWindow) {
      const downloadLink = document.createElement('a')
      downloadLink.href = objectUrl
      downloadLink.download = originalFile.name || 'original-document'
      document.body.appendChild(downloadLink)
      downloadLink.click()
      downloadLink.remove()
    }

    // Keep the object URL alive long enough for the new tab/download to load.
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60000)
  }

  const clearHistory = async () => {
    if (!window.confirm('Permanently delete all cloud investigations belonging to your account? This cannot be undone.')) return
    try {
      await investigationStore.clear(user.id)
      setHistory([])
      setError('')
    } catch (deleteError) {
      setError(`Could not clear cloud history: ${deleteError.message}`)
    }
  }

  const setAppLanguage = (value) => { setLanguage(value); localStorage.setItem('scamscan.language', value) }
  const pageTitle = page === 'overview' ? 'Overview' : page === 'new-scan' ? 'New investigation' : page === 'history' ? 'Scan history' : 'Analysis report'

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? 'mobile-open' : ''}`}>
        <div className="brand-lockup">
          <div className="brand-mark"><Fingerprint size={23} /></div>
          <div><div className="brand-name">SCAM<span>SCAN</span></div><div className="brand-caption">DIGITAL TRUST INTELLIGENCE</div></div>
          <button className="mobile-close icon-button" onClick={() => setMobileNav(false)} aria-label="Close menu"><X size={18} /></button>
        </div>
        <div className="workspace-switch"><div className="workspace-avatar">SS</div><div><strong>Investigation desk</strong><small>Local workspace</small></div><ChevronDown size={15} /></div>
        <div className="nav-label">{NAV[0].group}</div>
        <nav className="side-nav">
          {NAV.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${page === id ? 'active' : ''}`} onClick={() => { setPage(id); setMobileNav(false); setError('') }}><Icon size={17} /><span>{label}</span>{id === 'history' && history.length > 0 && <i>{history.length}</i>}</button>)}
        </nav>
        <div className="nav-label system-label">SYSTEM</div>
        <div className="system-card">
          <div className="system-card-top"><span className={`status-dot ${health ? 'online' : 'offline'}`} /> <span>API CONNECTION</span><span className="system-state">{health ? 'ONLINE' : 'OFFLINE'}</span></div>
          <div className="system-card-bottom"><span>{health ? `v${health.version}` : 'Waiting for backend'}</span><button onClick={refreshSystem} title="Refresh connection"><RefreshCw size={13} /></button></div>
          {backendError && <p className="system-error">{backendError}</p>}
        </div>
        <div className="sidebar-bottom"><div className="secure-line"><LockKeyhole size={13} /> Local analysis workspace</div><div className="version-line">SCAMSCAN 2.0 <span>BUILD 01</span></div></div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left"><button className="mobile-menu icon-button" onClick={() => setMobileNav(true)} aria-label="Open menu"><Menu size={19} /></button><div className="breadcrumb">Workspace <ChevronRight size={13} /> <strong>{pageTitle}</strong></div></div>
          <div className="topbar-right"><select className="language-select" aria-label="Select language" value={language} onChange={e => setAppLanguage(e.target.value)}><option value="en">English</option><option value="hi">हिंदी</option><option value="gu">ગુજરાતી</option></select><button className="help-trigger" onClick={() => setHelpOpen(true)}><CircleHelp size={15}/> Help & manual</button><div className="live-indicator"><span className={`status-dot ${health ? 'online' : 'offline'}`} />{health ? 'SYSTEM OPERATIONAL' : 'API DISCONNECTED'}</div><div className="account-menu-wrap">
            <button className={`account-trigger ${accountMenuOpen ? 'is-open' : ''}`} onClick={() => setAccountMenuOpen(v => !v)} aria-expanded={accountMenuOpen} aria-haspopup="menu" title="Account options">
              <span className="avatar">{(user?.email || 'U').slice(0,1).toUpperCase()}</span>
              <span className="account-trigger-copy"><strong>Account</strong><small>{user?.email}</small></span>
              <ChevronDown size={15} className="account-chevron" />
            </button>
            {accountMenuOpen && <>
              <button className="account-menu-dismiss" aria-label="Close account menu" onClick={() => setAccountMenuOpen(false)} />
              <div className="account-dropdown" role="menu">
                <div className="account-dropdown-head"><span className="avatar">{(user?.email || 'U').slice(0,1).toUpperCase()}</span><div><strong>Signed in</strong><small>{user?.email}</small></div></div>
                <div className="account-dropdown-divider" />
                <button className="account-signout-action" role="menuitem" onClick={() => { setAccountMenuOpen(false); onSignOut() }}><LogOut size={16}/><span>Sign out</span><small>End this secure session</small></button>
              </div>
            </>}
          </div></div>
        </header>

        <div className="page-content">
          <AnimatePresence mode="wait">
            {page === 'overview' && <motion.div key="overview" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: .2 }}><Overview health={health} system={system} history={history} onNew={() => { setPage('new-scan'); setError('') }} onHistory={() => setPage('history')} /></motion.div>}
            {page === 'new-scan' && <motion.div key="new" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: .2 }}><NewScan file={file} setSelectedFile={setSelectedFile} dragging={dragging} setDragging={setDragging} inputRef={inputRef} busy={busy} stage={stage} error={error} onAnalyze={runAnalysis} onClear={() => { setFile(null); setError(''); if (inputRef.current) inputRef.current.value = '' }} /></motion.div>}
            {page === 'results' && result && <motion.div key="results" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: .2 }}><Results result={result} ocr={ocr} activeTab={activeTab} setActiveTab={setActiveTab} onBack={() => setPage('history')} originalFile={originalFile} onOpenOriginal={openOriginalDocument} /></motion.div>}
            {page === 'history' && <motion.div key="history" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: .2 }}><HistoryPage history={history} loading={historyLoading} onNew={() => setPage('new-scan')} onClear={clearHistory} onOpen={openHistoryItem} error={error} /></motion.div>}
          </AnimatePresence>
        </div>
        <footer className="footer"><span>SCAMSCAN INTELLIGENCE ENGINE <i>•</i> RULE-BASED ANALYSIS</span><span>Built by the ScamScan team · <button className="footer-link" onClick={() => setHelpOpen(true)}>Help / Credits</button></span></footer>
      </main>
      {helpOpen && <HelpCentre onClose={() => setHelpOpen(false)} /> }
      {showGuide && <GuideModal onClose={() => { setShowGuide(false); localStorage.setItem('scamscan.guide.seen','yes') }} /> }
    </div>
  )
}

function GuideModal({ onClose }) {
  return <div className="scam-modal-backdrop" role="presentation"><section className="scam-modal guide-modal" role="dialog" aria-modal="true" aria-labelledby="guide-title"><button className="modal-x" onClick={onClose} aria-label="Close guide"><X size={18}/></button><div className="eyebrow">WELCOME / QUICK START</div><h2 id="guide-title">Your first investigation</h2><p className="modal-intro">A short guide to using ScamScan responsibly.</p><div className="guide-steps"><article><b>01</b><div><strong>Upload a document</strong><p>Open New investigation and select a JPG, JPEG, PNG, WEBP or PDF file (up to 15 MB).</p></div></article><article><b>02</b><div><strong>Run the inspection</strong><p>ScamScan extracts available text and checks supported image or PDF technical indicators.</p></div></article><article><b>03</b><div><strong>Review the evidence</strong><p>Read findings, limitations and extracted information. A score is review priority, not a fraud probability.</p></div></article><article><b>04</b><div><strong>Export and verify</strong><p>Export the report and independently confirm important documents with the issuing organization.</p></div></article></div><button className="primary-button modal-primary" onClick={onClose}>Start using ScamScan <ArrowRight size={15}/></button></section></div>
}

function HelpCentre({ onClose }) {
  const [issue, setIssue] = useState('');
  const [details, setDetails] = useState('');
  const [tab, setTab] = useState('manual');
  const sendReport = (e) => { e.preventDefault(); const subject = encodeURIComponent(`[ScamScan bug] ${issue || 'Issue report'}`); const body = encodeURIComponent(`Issue: ${issue}\n\nDetails:\n${details}\n\nBrowser: ${navigator.userAgent}`); window.location.href = `mailto:aryaniiitnr@gmail.com?subject=${subject}&body=${body}`; };
  return <div className="scam-modal-backdrop" role="presentation"><section className="scam-modal help-modal" role="dialog" aria-modal="true" aria-labelledby="help-title"><button className="modal-x" onClick={onClose} aria-label="Close help"><X size={18}/></button><div className="eyebrow">SCAMSCAN / SUPPORT</div><h2 id="help-title">Help centre</h2><div className="help-tabs"><button className={tab==='manual'?'active':''} onClick={()=>setTab('manual')}>User manual</button><button className={tab==='faq'?'active':''} onClick={()=>setTab('faq')}>FAQ & limitations</button><button className={tab==='bug'?'active':''} onClick={()=>setTab('bug')}>Report a bug</button><button className={tab==='team'?'active':''} onClick={()=>setTab('team')}>Team credits</button></div>
  {tab==='manual' && <div className="help-content"><h3>How to investigate a document</h3><ol><li>Choose <b>New investigation</b> from the left navigation.</li><li>Upload a supported image or PDF file and check the filename before analysis.</li><li>Select <b>Run analysis</b>. Keep the page open while OCR and forensic checks run.</li><li>Use Summary, Extracted data, Forensic evidence and Findings tabs to review output.</li><li>Use <b>Export PDF</b> to save a report. Scan history is stored in this browser only.</li></ol><h3>Privacy reminder</h3><p>Do not upload documents unless you are authorized to process them. Avoid sharing sensitive personal, financial or identity information.</p></div>}
  {tab==='faq' && <div className="help-content"><h3>What files are supported?</h3><p>JPG, JPEG, PNG, WEBP and PDF. Current upload limit is 15 MB.</p><h3>Does a low score prove a document is genuine?</h3><p>No. The score is a rule-based review-priority indicator, not a probability of fraud or an authenticity verdict.</p><h3>Are my reports stored online?</h3><p>No cloud report storage is configured. Complete reports and originals are stored in this browser's IndexedDB.</p><h3>Does OCR work on scanned PDFs?</h3><p>The current backend does not implement OCR for scanned/image-only PDFs.</p></div>}
  {tab==='bug' && <form className="bug-form" onSubmit={sendReport}><label>Issue type<input value={issue} onChange={e=>setIssue(e.target.value)} placeholder="e.g. Upload failed" required/></label><label>What happened?<textarea value={details} onChange={e=>setDetails(e.target.value)} rows="4" placeholder="Steps to reproduce and any error message…" required/></label><p className="muted-copy">This opens your email application with a prefilled report; it does not silently upload data.</p><button className="primary-button" type="submit">Prepare bug report <ArrowUpRight size={15}/></button></form>}
  {tab==='team' && <div className="help-content"><h3>Built for evidence-led investigation</h3><p><b>Project lead:</b> Aryan Gupta</p><p><b>Team:</b> ScamScan development team</p><h3>Contact</h3><p><a href="mailto:aryaniiitnr@gmail.com">aryaniiitnr@gmail.com</a></p><p><a href="tel:+919978025098">+91 99780 25098</a></p></div>}
  <div className="help-modal-foot"><span>SCAMSCAN 2.0 · IIIT NAYA RAIPUR</span><button className="secondary-button small" onClick={onClose}>Close</button></div></section></div>
}

function Overview({ health, system, history, onNew, onHistory }) {
  const recent = history.slice(0, 4)
  const modules = [
    ['Document upload', 'document_upload', CloudUpload], ['OCR extraction', 'ocr_extraction', FileText],
    ['PDF forensics', 'pdf_forensics', FileSearch], ['Image forensics', 'image_forensics', FileImage],
    ['Document intelligence', 'document_intelligence', Binary], ['Risk assessment', 'risk_assessment', ShieldCheck],
  ]
  return <>
    <div className="hero-panel">
      <div className="hero-grid" />
      <div className="hero-copy"><div className="eyebrow hero-eyebrow"><span className="eyebrow-pulse" /> DIGITAL TRUST / FORENSIC WORKSPACE</div><h1>See beyond the<br /><span>document.</span></h1><p>Investigate document signals, extract structured intelligence, and review forensic indicators — all in one workspace.</p><div className="hero-actions"><button className="primary-button" onClick={onNew}><ScanLine size={16} /> Start investigation <ArrowRight size={15} /></button><div className="hero-note"><Shield size={15} /> Evidence-led. Explainable. No authenticity claims.</div></div></div>
      <div className="hero-visual" aria-hidden="true"><div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="scan-core"><div className="core-ring"><Fingerprint size={48} strokeWidth={1.1} /></div><span className="core-line" /><span className="core-dot dot-a" /><span className="core-dot dot-b" /><span className="core-dot dot-c" /></div><div className="visual-tag tag-top"><span /> EVIDENCE ENGINE <b>ACTIVE</b></div><div className="visual-tag tag-bottom"><Activity size={12} /> SIGNAL ANALYSIS <b>READY</b></div></div>
    </div>
    <div className="section-heading-row"><div><div className="eyebrow">LIVE WORKSPACE</div><h2>System overview</h2></div><div className="updated-label"><span className={`status-dot ${health ? 'online' : 'offline'}`} /> {health ? 'Connected to local API' : 'Backend connection required'}</div></div>
    <div className="metric-grid">
      <Metric icon={FileCheck2} label="Total investigations" value={history.length} detail="Saved in this browser" tone="blue" />
      <Metric icon={ShieldAlert} label="Indicators found" value={history.reduce((sum, item) => sum + (item.finding_count || 0), 0)} detail="Across saved scan summaries" tone="amber" />
      <Metric icon={Cpu} label="Analysis modules" value={system ? Object.values(system.modules || {}).filter(v => v === 'available').length : '—'} detail="Reported by backend" tone="violet" />
      <Metric icon={Activity} label="API status" value={health ? 'Online' : 'Offline'} detail={health ? `Version ${health.version}` : 'Start FastAPI to connect'} tone={health ? 'green' : 'red'} compact />
    </div>
    <div className="overview-columns">
      <section className="panel module-panel"><div className="panel-heading"><div><div className="eyebrow">ENGINE CAPABILITIES</div><h3>Analysis modules</h3></div><span className="panel-count">{modules.filter(([, key]) => system?.modules?.[key] === 'available').length || 0}/{modules.length} READY</span></div><div className="module-list">{modules.map(([label, key, Icon]) => { const ready = system?.modules?.[key] === 'available'; return <div className="module-row" key={key}><IconBox icon={Icon} tone={ready ? 'blue' : 'muted'} /><div className="module-info"><strong>{label}</strong><small>{ready ? 'Available in current backend' : 'Not confirmed by backend'}</small></div><span className={`module-status ${ready ? 'ready' : 'unavailable'}`}><i />{ready ? 'READY' : 'UNAVAILABLE'}</span></div> })}</div></section>
      <section className="panel recent-panel"><div className="panel-heading"><div><div className="eyebrow">ACTIVITY LOG</div><h3>Recent investigations</h3></div><button className="text-button" onClick={onHistory}>View all <ArrowRight size={14} /></button></div>{recent.length ? <div className="recent-list">{recent.map((item) => <RecentRow key={item.scan_id} item={item} />)}</div> : <EmptyState icon={FileSearch} title="No investigations yet" detail="Your completed scans will appear here." action={<button className="secondary-button small" onClick={onNew}>Run first scan</button>} />}</section>
    </div>
    <div className="disclaimer-strip"><Info size={15} /><span><strong>Important:</strong> ScamScan reports technical indicators and review priorities. Automated analysis cannot prove a document genuine or forged. Verify important documents with the issuing authority.</span></div>
  </>
}

function Metric({ icon: Icon, label, value, detail, tone, compact }) {
  return <div className="metric-card"><div className="metric-top"><span>{label}</span><IconBox icon={Icon} tone={tone} /></div><div className={`metric-value ${compact ? 'compact' : ''}`}>{value}</div><div className="metric-detail">{detail}</div></div>
}
function RecentRow({ item }) {
  return <div className="recent-row"><div className="file-mini"><FileText size={17} /></div><div className="recent-main"><strong>{item.filename}</strong><small>{dateLabel(item.created_at)} <span>·</span> {formatBytes(item.file_size_bytes)}</small></div><div className={`mini-risk ${riskTone(item.risk_level)}`}>{item.risk_level === 'no_flagged_indicators' ? 'NO FLAGS' : titleCase(item.risk_level)}</div></div>
}

function NewScan({ file, setSelectedFile, dragging, setDragging, inputRef, busy, stage, error, onAnalyze, onClear }) {
  const handleDrop = (event) => { event.preventDefault(); setDragging(false); setSelectedFile(event.dataTransfer.files?.[0]) }
  return <>
    <SectionTitle eyebrow="NEW INVESTIGATION / 01" title="Inspect a document." detail="Upload a document to run OCR, document intelligence, and forensic analysis." right={<div className="step-indicator"><span className="step-active">01</span><i /><span>02</span><i /><span>03</span></div>} />
    <div className="scan-layout">
      <div className="scan-main-column">
        <section className="panel upload-panel"><div className="panel-heading"><div><div className="eyebrow">SOURCE DOCUMENT</div><h3>Upload evidence</h3></div><span className="secure-chip"><LockKeyhole size={12} /> LOCAL API</span></div>
          <input ref={inputRef} type="file" accept=".jpg,.jpeg,.png,.webp,.pdf,application/pdf,image/jpeg,image/png,image/webp" hidden onChange={(e) => setSelectedFile(e.target.files?.[0])} />
          {!file ? <div className={`dropzone ${dragging ? 'dragging' : ''}`} onDragOver={(e) => { e.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={handleDrop} onClick={() => inputRef.current?.click()} role="button" tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && inputRef.current?.click()}><div className="upload-symbol"><CloudUpload size={27} /></div><h3>Drop your document here</h3><p>or <button type="button" className="inline-link" onClick={(e) => { e.stopPropagation(); inputRef.current?.click() }}>browse files</button> from your device</p><div className="drop-meta"><span>PDF</span><span>JPG / JPEG</span><span>PNG</span><span>WEBP</span><i>MAX 15 MB</i></div></div> : <div className="selected-file"><div className="selected-file-icon">{file.name.toLowerCase().endsWith('.pdf') ? <FileText size={24} /> : <ImageIcon size={24} />}</div><div className="selected-file-info"><strong>{file.name}</strong><span>{formatBytes(file.size)} <i>·</i> {file.type || 'Document file'}</span><div className="file-ready"><CheckCircle2 size={12} /> Ready for analysis</div></div><button className="icon-button remove-file" onClick={onClear} aria-label="Remove selected file"><X size={17} /></button></div>}
          {error && <div className="error-banner"><AlertCircle size={16} /><span>{error}</span></div>}
          {busy && <div className="processing-box"><div className="processing-head"><span className="spinner" /><strong>Analysis in progress</strong><span className="processing-live">LIVE</span></div><p>{stage}</p><div className="progress-track"><motion.div className="progress-fill" initial={{ width: '8%' }} animate={{ width: '92%' }} transition={{ duration: 14, ease: 'easeInOut' }} /></div><small>Keep this tab open while the backend processes your file.</small></div>}
          <div className="upload-actions"><button className="primary-button" disabled={!file || busy} onClick={onAnalyze}>{busy ? <><span className="spinner light" /> Analyzing…</> : <><ScanLine size={16} /> Analyze document <ArrowRight size={15} /></>}</button>{file && !busy && <button className="secondary-button" onClick={onClear}>Remove file</button>}</div>
        </section>
        <section className="panel pipeline-panel"><div className="panel-heading"><div><div className="eyebrow">ANALYSIS PIPELINE</div><h3>What happens next</h3></div><span className="pipeline-tag">AUTOMATED WORKFLOW</span></div><div className="pipeline-steps"><PipelineStep number="01" icon={FileText} title="Text extraction" text="OCR and readable PDF text" /><div className="pipeline-connector" /><PipelineStep number="02" icon={Binary} title="Document intelligence" text="Classification and field extraction" /><div className="pipeline-connector" /><PipelineStep number="03" icon={Fingerprint} title="Forensic inspection" text="Image or PDF metadata and signals" /><div className="pipeline-connector" /><PipelineStep number="04" icon={ShieldCheck} title="Risk assessment" text="Explainable review indicators" /></div></section>
      </div>
      <aside className="scan-side-column"><section className="panel side-info-panel"><div className="side-info-icon"><ShieldCheck size={21} /></div><h3>Evidence-first analysis</h3><p>Every reported indicator is paired with an explanation and a recommendation for manual review.</p><div className="side-divider" /><div className="side-feature"><Check size={14} /><span>No fabricated findings</span></div><div className="side-feature"><Check size={14} /><span>Transparent limitations</span></div><div className="side-feature"><Check size={14} /><span>Original file remains your source of truth</span></div></section><section className="panel format-panel"><div className="eyebrow">SUPPORTED INPUT</div><h3>File requirements</h3><div className="format-row"><span>Formats</span><strong>PDF, JPG, PNG, WEBP</strong></div><div className="format-row"><span>Maximum size</span><strong>15 MB</strong></div><div className="format-row"><span>PDF page limit</span><strong>50 pages</strong></div><div className="format-row"><span>OCR language</span><strong>English</strong></div><p className="format-note">Scanned/image-only PDFs are not yet supported by the current backend OCR route.</p></section></aside>
    </div>
  </>
}
function PipelineStep({ number, icon: Icon, title, text }) { return <div className="pipeline-step"><span className="pipeline-number">{number}</span><Icon size={18} /><div><strong>{title}</strong><small>{text}</small></div></div> }


function escapeReportHtml(value) {
  return String(value ?? 'Not available')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;').replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function compactReportValue(value, depth = 0) {
  if (value === null || value === undefined || value === '') return 'Not available'
  if (typeof value === 'string') return value.length > 700 ? `${value.slice(0, 700)}… [truncated]` : value
  if (typeof value !== 'object') return String(value)
  if (Array.isArray(value)) {
    if (!value.length) return 'None reported'
    const preview = value.slice(0, 8).map((item) => compactReportValue(item, depth + 1))
    return `${preview.join(' · ')}${value.length > 8 ? ` · +${value.length - 8} more` : ''}`
  }
  if (depth >= 2) return '[Structured data omitted from concise report]'
  const safe = Object.fromEntries(Object.entries(value)
    .filter(([key]) => !['visualization', 'data', 'base64', 'raw_image', 'image_base64'].includes(key.toLowerCase()))
    .slice(0, 16))
  return Object.entries(safe).map(([key, item]) => `${titleCase(key)}: ${compactReportValue(item, depth + 1)}`).join('\n') || 'Not available'
}

function reportRows(object = {}) {
  return Object.entries(object)
    .filter(([key]) => !['visualization', 'data', 'base64', 'raw_image', 'image_base64'].includes(key.toLowerCase()))
    .map(([key, value]) => `<tr><th>${escapeReportHtml(titleCase(key))}</th><td>${escapeReportHtml(compactReportValue(value))}</td></tr>`)
    .join('')
}


function downloadInvestigationReport(result, ocr) {
  const intel = result.intelligence_analysis || {}
  const extracted = intel.extracted_information || {}
  const risk = result.risk_assessment || {}
  const findings = risk.findings || []
  const image = result.image_forensics || null
  const pdf = result.pdf_forensics || null
  const esc = escapeReportHtml

  const fullOcr = String(
    ocr?.extracted_text || intel.extracted_text || ''
  )

  // Keep the default PDF compact.
  const OCR_LIMIT = 2800
  const ocrText = fullOcr
    ? fullOcr.slice(0, OCR_LIMIT)
    : 'No OCR text returned.'

  const ocrNotice = fullOcr.length > OCR_LIMIT
    ? `<p class="note">Showing ${OCR_LIMIT} of ${fullOcr.length} characters. Open ScamScan for complete OCR text.</p>`
    : ''

  const fieldRows = Object.entries(extracted)
    .map(([key, value]) => `
      <tr>
        <th>${esc(titleCase(key))}</th>
        <td>${esc(compactReportValue(value))}</td>
      </tr>
    `).join('')

  const findingBlocks = findings.length
    ? findings.map((finding, index) => `
      <article class="finding">
        <div class="finding-head">
          <strong>${index + 1}. ${esc(finding.title || titleCase(finding.code))}</strong>
          <span>${esc(finding.severity || 'info')}</span>
        </div>
        <p>${esc(finding.explanation || 'No explanation provided.')}</p>
        <p><b>Evidence:</b> ${esc(compactReportValue(finding.evidence || 'Not provided'))}</p>
        <p><b>Recommended action:</b> ${esc(finding.recommendation || 'Verify with the issuing organization.')}</p>
      </article>
    `).join('')
    : '<p class="muted">No actionable findings were reported.</p>'

  const limitations = (risk.limitations || [])
    .slice(0, 5)
    .map(item => `<li>${esc(item)}</li>`)
    .join('')

  // IMAGE FORENSICS
  let forensicSection = ''

  if (image) {
    const props = image.image_properties || {}
    const exif = image.exif_analysis || {}
    const ela = image.ela_analysis || {}
    const png = image.png_analysis || {}

    const vizObject = ela.visualization || png.visualization || null

    const vizData = typeof vizObject === 'string'
      ? vizObject
      : vizObject?.data

    const vizMime = vizObject?.mime_type || 'image/png'

    const metrics = ela.available
      ? [
          ['Mean difference', ela.mean_difference],
          ['Maximum difference', ela.max_difference]
        ]
      : [
          ['Mean residual', png.metrics?.mean_residual],
          ['P95 residual', png.metrics?.p95_residual],
          ['P99 residual', png.metrics?.p99_residual],
          ['Maximum residual', png.metrics?.max_residual]
        ]

    const metricCards = metrics.map(([label, value]) => `
      <div class="metric">
        <small>${esc(label)}</small>
        <strong>${esc(value ?? '—')}</strong>
      </div>
    `).join('')

    // Base64 is embedded as an image, never printed as text.
    const visualization = vizData
      ? `
        <figure class="visual">
          <img
            src="data:${esc(vizMime)};base64,${vizData}"
            alt="Forensic visualization"
          />
          <figcaption>
            ${ela.available ? 'JPEG ELA visualization' : 'PNG residual visualization'}
            · Visual signal only, not proof of manipulation.
          </figcaption>
        </figure>
      `
      : '<p class="muted">Visualization unavailable.</p>'

    forensicSection = `
      <h2>Image properties</h2>

      <div class="facts">
        <div><small>Format</small><b>${esc(props.format || '—')}</b></div>
        <div><small>Dimensions</small><b>${esc(
          props.width && props.height
            ? `${props.width} × ${props.height}`
            : '—'
        )}</b></div>
        <div><small>Color mode</small><b>${esc(props.color_mode || '—')}</b></div>
        <div><small>EXIF metadata</small><b>${exif.metadata_present ? 'Present' : 'Not detected'}</b></div>
        <div><small>Camera</small><b>${esc(
          [exif.camera_make, exif.camera_model]
            .filter(Boolean).join(' ') || 'Not available'
        )}</b></div>
        <div><small>SHA-256</small><b class="hash">${esc(
          image.file?.sha256 || image.sha256 || 'Not available'
        )}</b></div>
      </div>

      <h2>${ela.available ? 'JPEG error-level analysis' : 'PNG residual analysis'}</h2>
      <div class="metrics">${metricCards}</div>

      ${visualization}

      <p class="note">
        ${esc(
          ela.analysis_note ||
          png.analysis_note ||
          'Pixel residuals can be caused by edges, text, texture or noise. They do not independently establish manipulation.'
        )}
      </p>
    `
  }

  // PDF FORENSICS
  else if (pdf) {
    const structure = pdf.structure || {}
    const metadata = pdf.metadata || {}

    forensicSection = `
      <h2>PDF structure and metadata</h2>

      <div class="facts">
        <div><small>Pages</small><b>${esc(structure.page_count ?? '—')}</b></div>
        <div><small>PDF version</small><b>${esc(structure.pdf_version || '—')}</b></div>
        <div><small>Encrypted</small><b>${structure.is_encrypted ? 'Yes' : 'No'}</b></div>
        <div><small>Repaired during parsing</small><b>${structure.is_repaired ? 'Yes' : 'No'}</b></div>
        <div><small>Title</small><b>${esc(metadata.title || 'Not available')}</b></div>
        <div><small>Author</small><b>${esc(metadata.author || 'Not available')}</b></div>
        <div><small>Creator</small><b>${esc(metadata.creator || 'Not available')}</b></div>
        <div><small>Producer</small><b>${esc(metadata.producer || 'Not available')}</b></div>
      </div>
    `
  }

  const html = `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8">
    <title>ScamScan Investigation Report</title>

    <style>
      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        background: #edf2f7;
        color: #172b43;
        font: 10pt/1.5 Arial, sans-serif;
      }

      .sheet {
        max-width: 900px;
        margin: 25px auto;
        padding: 35px 42px;
        background: white;
      }

      .page {
        position: relative;
      }

      /* Previous section inserts the page break; avoid a duplicate. */


      .page + .page {


        break-before: auto;


        page-break-before: auto;


        padding-top: 0;


      }

      .brand {
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 3px solid #168bb5;
        padding-bottom: 12px;
        margin-bottom: 22px;
      }

      .brand-name {
        font-size: 15pt;
        font-weight: 900;
        letter-spacing: 2px;
        color: #102d49;
      }

      .brand-name span {
        color: #168bb5;
      }

      .tag {
        font-size: 8pt;
        letter-spacing: 1.5px;
        color: #71859a;
      }

      .eyebrow {
        font-size: 8pt;
        font-weight: bold;
        letter-spacing: 1.5px;
        color: #1682a8;
        text-transform: uppercase;
      }

      h1 {
        font-size: 27pt;
        line-height: 1.15;
        color: #102d49;
        margin: 10px 0 5px;
      }

      h2 {
        font-size: 14pt;
        color: #126b8d;
        margin: 20px 0 10px;
        padding-bottom: 7px;
        border-bottom: 1px solid #dbe5ed;
        break-after: avoid;
      }

      p {
        margin: 6px 0;
      }

      .subtitle {
        color: #718196;
        margin-bottom: 18px;
      }

      .meta-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 9px;
        margin: 15px 0;
      }

      .meta-card {
        padding: 11px;
        border: 1px solid #dfe7ee;
        border-radius: 7px;
        background: #f6f9fb;
        break-inside: avoid;
      }

      .meta-card small,
      .facts small,
      .metric small {
        display: block;
        font-size: 7pt;
        color: #74869a;
        text-transform: uppercase;
        letter-spacing: .6px;
      }

      .meta-card strong {
        display: block;
        margin-top: 5px;
        font-size: 9pt;
        overflow-wrap: anywhere;
      }

      .score {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 20px;
        padding: 16px 19px;
        margin: 16px 0;
        border-radius: 8px;
        background: linear-gradient(110deg, #102d49, #176182);
        color: white;
        break-inside: avoid;
      }

      .score small {
        color: #c1d9e9;
      }

      .score strong {
        display: block;
        font-size: 28pt;
      }

      .score-copy {
        max-width: 65%;
        font-size: 9pt;
      }

      table {
        width: 100%;
        border-collapse: collapse;
        margin: 10px 0;
      }

      th, td {
        border: 1px solid #e0e7ed;
        padding: 8px 10px;
        text-align: left;
        vertical-align: top;
        font-size: 9pt;
        overflow-wrap: anywhere;
        white-space: pre-wrap;
      }

      th {
        width: 28%;
        background: #f3f7fa;
        color: #465b70;
      }

      .facts {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 8px;
      }

      .facts > div,
      .metric {
        min-width: 0;
        padding: 9px;
        border: 1px solid #e1e8ee;
        border-radius: 6px;
        background: #fbfcfd;
        break-inside: avoid;
      }

      .facts b {
        display: block;
        margin-top: 5px;
        font-size: 9pt;
        overflow-wrap: anywhere;
      }

      .hash {
        font: 7pt monospace;
        word-break: break-all;
      }

      .metrics {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 8px;
        margin: 10px 0;
      }

      .metric strong {
        display: block;
        margin-top: 5px;
        font-size: 16pt;
        color: #176b8c;
      }

      .visual {
        margin: 8px 0;
        padding: 8px;
        border: 1px solid #dce6ed;
        border-radius: 7px;
        background: #f7fafc;
        break-inside: avoid;
      }

      .visual img {
        display: block;
        max-width: 100%;
        max-height: 65mm;
        object-fit: contain;
        margin: auto;
      }

      .visual figcaption {
        text-align: center;
        font-size: 8pt;
        color: #657b8f;
        margin-top: 4px;
      }

      .ocr {
        white-space: pre-wrap;
        overflow-wrap: anywhere;
        background: #f6f9fb;
        border: 1px solid #e0e8ef;
        border-radius: 7px;
        padding: 13px;
        font: 8pt/1.5 Consolas, monospace;
      }

      .finding {
        padding: 11px 13px;
        margin: 9px 0;
        border: 1px solid #dce5ed;
        border-left: 3px solid #278bb1;
        border-radius: 6px;
        break-inside: avoid;
      }

      .finding-head {
        display: flex;
        justify-content: space-between;
        gap: 10px;
      }

      .finding-head span {
        color: #95611f;
        font-size: 8pt;
        text-transform: uppercase;
      }

      .finding p {
        font-size: 9pt;
        color: #455b70;
      }

      .note,
      .muted {
        font-size: 8pt;
        color: #687d91;
      }

      .notice {
        padding: 11px 13px;
        margin-top: 14px;
        border: 1px solid #efdfbd;
        border-left: 4px solid #d49b38;
        border-radius: 5px;
        background: #fff8e9;
        color: #5d4b2d;
        font-size: 8.5pt;
      }

      .footer {
        position: absolute;
        bottom: 0;
        left: 0;
        right: 0;
        display: flex;
        justify-content: space-between;
        border-top: 1px solid #dce5ed;
        padding-top: 9px;
        color: #78899a;
        font-size: 7pt;
      }

      @page {
        size: A4;
        margin: 12mm;
      }

      @media print {
        body {
          background: white;
        }

        .sheet {
          max-width: none;
          margin: 0;
          padding: 0;
        }

        /* Let each report section use only the height its content needs.
           Fixed page heights caused small overflows and nearly blank extra pages. */
        .page {
          min-height: 0;
          height: auto;
          break-after: page;
          page-break-after: always;
        }

        /* .page break-after is sufficient; a second break creates blank sheets. */


        .page + .page {


          break-before: auto;


          page-break-before: auto;


        }

        .page:last-child {
          break-after: auto;
          page-break-after: auto;
        }

        /* A static footer contributes to content flow instead of being
           anchored to an artificial full-page height. */
        .footer {
          position: static;
          margin-top: 7mm;
        }

        .visual,
        .finding,
        .meta-card,
        .score,
        table {
          break-inside: avoid;
        }
      }
    </style>
  </head>

  <body>
    <main class="sheet">

      <!-- PAGE 1: EXECUTIVE SUMMARY -->
      <section class="page">
        <div class="brand">
          <div class="brand-name">SCAM<span>SCAN</span> 2.0</div>
          <div class="tag">DIGITAL TRUST INTELLIGENCE</div>
        </div>

        <div class="eyebrow">Evidence-led document analysis</div>
        <h1>Investigation Report</h1>
        <p class="subtitle">Generated ${esc(new Date().toLocaleString())}</p>

        <div class="meta-grid">
          <div class="meta-card">
            <small>Document</small>
            <strong>${esc(result.filename || 'Unknown')}</strong>
          </div>
          <div class="meta-card">
            <small>File type / size</small>
            <strong>${esc(result.file_type || 'Unknown')} · ${esc(formatBytes(result.file_size_bytes))}</strong>
          </div>
          <div class="meta-card">
            <small>Document category</small>
            <strong>${esc(intel.document_type || 'Unavailable')}</strong>
          </div>
          <div class="meta-card">
            <small>Scan reference</small>
            <strong>${esc(result.scan_id || 'Not provided')}</strong>
          </div>
          <div class="meta-card">
            <small>Analysis status</small>
            <strong>${esc(result.status || 'Completed')}</strong>
          </div>
          <div class="meta-card">
            <small>Extracted words</small>
            <strong>${esc(intel.text_statistics?.word_count ?? fullOcr.trim().split(/\s+/).filter(Boolean).length)}</strong>
          </div>
        </div>

        <div class="score">
          <div>
            <small>REVIEW PRIORITY SCORE</small>
            <strong>${esc(risk.risk_score ?? 0)} / 100</strong>
          </div>
          <div class="score-copy">
            <b>${esc(titleCase(risk.risk_level || 'Unknown'))} review priority · ${findings.length} finding(s)</b>
            ${esc(risk.score_explanation || 'Rule-based review indicator. Not a fraud probability.')}
          </div>
        </div>

        <h2>Extracted information</h2>
        <table>
          ${fieldRows || '<tr><td>No structured fields returned.</td></tr>'}
        </table>

        <div class="notice">
          <b>Interpretation:</b> This is a review-priority indicator, not a fraud probability.
          A low score does not prove authenticity.
        </div>

        <div class="footer">
          <span>SCAMSCAN 2.0 · SCAN. INVESTIGATE. VERIFY.</span>
          <span>Confidential analysis · 1</span>
        </div>
      </section>

      <!-- PAGE 2: FORENSIC EVIDENCE -->
      <section class="page">
        <div class="brand">
          <div class="brand-name">SCAM<span>SCAN</span> 2.0</div>
          <div class="tag">TECHNICAL EVIDENCE</div>
        </div>

        <div class="eyebrow">Forensic review</div>
        <h1>Forensic Evidence</h1>
        <p class="subtitle">Technical properties and pixel-level signals.</p>

        ${forensicSection || '<p class="muted">No forensic module data was returned.</p>'}

        <div class="notice">
          Metadata absence or residual patterns alone do not establish tampering.
          Review the original document and its context.
        </div>

        <div class="footer">
          <span>SCAMSCAN 2.0 · SCAN. INVESTIGATE. VERIFY.</span>
          <span>Confidential analysis · 2</span>
        </div>
      </section>

      <!-- PAGE 3: OCR & FINDINGS -->
      <section class="page">
        <div class="brand">
          <div class="brand-name">SCAM<span>SCAN</span> 2.0</div>
          <div class="tag">EXTRACTION & REVIEW</div>
        </div>

        <div class="eyebrow">Text intelligence</div>
        <h1>OCR & Findings</h1>
        <p class="subtitle">Extracted text preview and review recommendations.</p>

        <h2>OCR / extracted text</h2>
        <pre class="ocr">${esc(ocrText)}</pre>
        ${ocrNotice}

        <h2>Findings and recommended actions</h2>
        ${findingBlocks}

        <h2>Analysis limitations</h2>
        <ul>
          ${limitations || '<li>Automated analysis cannot establish document authenticity.</li>'}
        </ul>

        <div class="notice">
          <b>Important:</b> This report does not establish whether a document is genuine,
          forged, or fraudulent. Verify important documents with the issuing organization.
        </div>

        <div class="footer">
          <span>SCAMSCAN 2.0 · SCAN. INVESTIGATE. VERIFY.</span>
          <span>Confidential analysis · 3</span>
        </div>
      </section>
    </main>

    <script>
      window.onload = () => {
        window.focus()
        window.print()
      }
    </script>
  </body>
  </html>
  `

  const reportWindow = window.open('', '_blank')

  if (!reportWindow) {
    window.alert('Pop-up blocked. Allow pop-ups for ScamScan and try again.')
    return
  }

  reportWindow.document.open()
  reportWindow.document.write(html)
  reportWindow.document.close()
}


function Results({ result, ocr, activeTab, setActiveTab, onBack, originalFile, onOpenOriginal }) {
  const risk = result.risk_assessment || {}
  const intel = result.intelligence_analysis || {}
  const extracted = intel.extracted_information || {}
  const image = result.image_forensics
  const pdf = result.pdf_forensics
  const findings = risk.findings || []
  const tabs = [{ id: 'summary', label: 'Summary' }, { id: 'extracted', label: 'Extracted data' }, { id: 'forensics', label: 'Forensic evidence' }, { id: 'findings', label: `Findings (${findings.length})` }]
  const score = Number(risk.risk_score || 0)
  const scoreColor = riskTone(risk.risk_level)
  return <>
    <div className="results-header"><div><button className="back-link" onClick={onBack}><ArrowLeft size={14} /> Back to new scan</button><div className="eyebrow">INVESTIGATION COMPLETE / REPORT</div><h1>Analysis report</h1><p>Review the extracted information and technical indicators from this document.</p></div><div className="results-header-actions"><div className="report-file-chip"><div className="file-mini"><FileText size={17} /></div><div><strong>{result.filename}</strong><small>{result.file_type?.toUpperCase()} <i>·</i> {formatBytes(result.file_size_bytes)}</small></div></div><button className="secondary-button" onClick={onOpenOriginal} disabled={!originalFile} title={originalFile ? 'Open the original uploaded document' : 'Original document is unavailable for this entry'}><File size={15} /> Open original</button><button className="primary-button" onClick={() => downloadInvestigationReport(result, ocr)}><ArrowDownToLine size={15} /> Export PDF</button></div></div>
    <div className="report-meta"><span><Fingerprint size={13} /> SCAN ID <b>{result.scan_id || 'Not provided'}</b></span><span><Clock3 size={13} /> STATUS <b>{titleCase(result.status || 'completed')}</b></span><span><Layers3 size={13} /> DOCUMENT TYPE <b>{titleCase(intel.document_type || 'Unavailable')}</b></span></div>
    <div className="risk-overview-grid">
      <section className={`panel risk-score-panel ${scoreColor}`}><div className="risk-panel-label"><ShieldAlert size={16} /> REVIEW PRIORITY SCORE</div><div className="score-row"><div className="score-number">{score}<small>/100</small></div><div className={`risk-level-pill ${scoreColor}`}>{titleCase(risk.risk_level || 'unknown')}</div></div><div className="score-meter"><div className={`score-meter-fill ${scoreColor}`} style={{ width: `${Math.min(100, Math.max(0, score))}%` }} /></div><p>{risk.score_explanation || 'Score is calculated from the listed rule-based review indicators.'}</p><div className="score-footnote"><Info size={13} /> Review priority only — not a fraud probability.</div></section>
      <section className="panel report-stat"><div className="report-stat-icon amber"><AlertCircle size={18} /></div><span>Reported findings</span><strong>{risk.finding_count ?? findings.length}</strong><small>Items requiring interpretation</small></section>
      <section className="panel report-stat"><div className="report-stat-icon blue"><FileText size={18} /></div><span>Extracted words</span><strong>{intel.text_statistics?.word_count ?? ocr?.extracted_text?.trim().split(/\s+/).filter(Boolean).length ?? '—'}</strong><small>From available OCR/text</small></section>
      <section className="panel report-stat"><div className="report-stat-icon violet"><Database size={18} /></div><span>Pages analyzed</span><strong>{result.document_extraction?.total_pages ?? '—'}</strong><small>{result.document_extraction?.document_type || 'Document'} extraction</small></section>
    </div>
    <div className="tabs-bar">{tabs.map((tab) => <button key={tab.id} className={activeTab === tab.id ? 'active' : ''} onClick={() => setActiveTab(tab.id)}>{tab.label}</button>)}</div>
    <div className="results-content">
      {activeTab === 'summary' && <SummaryTab result={result} intel={intel} risk={risk} findings={findings} image={image} pdf={pdf} />}
      {activeTab === 'extracted' && <ExtractedTab intel={intel} ocr={ocr} />}
      {activeTab === 'forensics' && <ForensicsTab image={image} pdf={pdf} />}
      {activeTab === 'findings' && <FindingsTab findings={findings} limitations={risk.limitations || []} />}
    </div>
    <div className="disclaimer-strip"><Info size={15} /><span><strong>Interpretation note:</strong> A forensic indicator is not proof of tampering. A clean result is not proof of authenticity. Confirm important documents with the issuing organization.</span></div>
  </>
}

function SummaryTab({ result, intel, risk, findings, image, pdf }) {
  const fields = intel.extracted_information || {}
  const values = [['Names', fields.names], ['Dates', fields.dates], ['Amounts', fields.amounts], ['Reference numbers', fields.reference_numbers], ['Roll numbers', fields.roll_numbers]]
  return <div className="result-grid-two"><section className="panel result-panel"><div className="panel-heading"><div><div className="eyebrow">DOCUMENT INTELLIGENCE</div><h3>Extracted overview</h3></div><span className="method-chip">RULE-BASED</span></div><div className="classification-box"><span className="classification-icon"><FileSearch size={19} /></span><div><small>CLASSIFIED DOCUMENT TYPE</small><strong>{titleCase(intel.document_type || 'Not available')}</strong><span>{intel.classification?.classification_method || 'Classification unavailable'}</span></div></div><div className="field-summary-list">{values.map(([label, items]) => <div className="field-summary" key={label}><span>{label}</span><strong>{Array.isArray(items) ? (items.length ? items.join(', ') : 'None extracted') : 'Unavailable'}</strong></div>)}</div></section>
    <section className="panel result-panel"><div className="panel-heading"><div><div className="eyebrow">FORENSIC COVERAGE</div><h3>Inspection status</h3></div><BadgeCheck size={18} className="muted-icon" /></div><div className="coverage-list"><CoverageRow label="OCR / text extraction" status={result.document_extraction?.text_available ? 'Text available' : 'No readable text'} /><CoverageRow label="Image forensics" status={image ? 'Completed' : 'Not applicable'} /><CoverageRow label="PDF forensics" status={pdf ? (pdf.status || 'Completed') : 'Not applicable'} /><CoverageRow label="Risk assessment" status={risk.assessment_status || 'Unknown'} /></div><div className="finding-preview"><div><strong>{findings.length} review indicators</strong><small>See evidence and recommendations in Findings.</small></div><span className={`mini-risk ${riskTone(risk.risk_level)}`}>{titleCase(risk.risk_level || 'Unknown')}</span></div></section>
    <section className="panel result-panel span-two"><div className="panel-heading"><div><div className="eyebrow">ASSESSMENT INTERPRETATION</div><h3>What this result means</h3></div><Info size={18} className="muted-icon" /></div><p className="interpretation-copy">{risk.verdict || 'No authenticity or fraud verdict is made by this engine.'} The score summarizes the review indicators listed in this report. It should guide manual inspection, not replace verification by an issuing authority.</p><div className="interpretation-points"><div><ShieldCheck size={15} /><span>Evidence and findings are shown separately from conclusions.</span></div><div><Search size={15} /><span>Review original document details before making a decision.</span></div></div></section>
  </div>
}
function CoverageRow({ label, status }) { return <div className="coverage-row"><span>{label}</span><strong>{status}</strong></div> }

function ExtractedTab({ intel, ocr }) {
  const info = intel.extracted_information || {}
  const fields = [['Names', info.names], ['Dates', info.dates], ['Amounts', info.amounts], ['Reference numbers', info.reference_numbers], ['Roll numbers', info.roll_numbers]]
  return <div className="result-grid-two"><section className="panel result-panel"><div className="panel-heading"><div><div className="eyebrow">STRUCTURED EXTRACTION</div><h3>Detected information</h3></div><span className="method-chip">{intel.analysis_method || 'OCR'}</span></div>{intel.status === 'completed' ? <div className="extracted-fields">{fields.map(([label, values]) => <div className="extracted-field" key={label}><div className="extracted-field-label">{label}</div><div className="extracted-values">{Array.isArray(values) && values.length ? values.map((v, i) => <span className="value-chip" key={`${label}-${i}`}>{String(v)}</span>) : <span className="not-found">No value extracted</span>}</div></div>)}</div> : <EmptyState icon={FileText} title="Text intelligence unavailable" detail="The backend did not return structured text analysis for this document." />}</section>
    <section className="panel result-panel"><div className="panel-heading"><div><div className="eyebrow">TEXT STATISTICS</div><h3>OCR output</h3></div><FileText size={18} className="muted-icon" /></div><div className="ocr-stat-grid"><div><span>Characters</span><strong>{ocr?.character_count ?? intel.text_statistics?.character_count ?? '—'}</strong></div><div><span>Words</span><strong>{intel.text_statistics?.word_count ?? '—'}</strong></div><div><span>OCR status</span><strong>{ocr?.status || 'Not returned'}</strong></div></div><div className="ocr-text-box">{ocr?.extracted_text ? ocr.extracted_text : 'No OCR text was returned by the API. For scanned PDFs, the current backend reports that OCR is not implemented.'}</div></section>
    {intel.financial_analysis && <section className="panel result-panel span-two"><div className="panel-heading"><div><div className="eyebrow">FINANCIAL CONSISTENCY</div><h3>Arithmetic check</h3></div><span className={`mini-risk ${intel.financial_analysis.status === 'consistent' ? 'safe' : intel.financial_analysis.status === 'requires_verification' ? 'danger' : 'caution'}`}>{titleCase(intel.financial_analysis.status || 'unknown')}</span></div><p className="interpretation-copy">{intel.financial_analysis.comparison || intel.financial_analysis.message || 'No financial consistency comparison was provided.'}</p>{intel.financial_analysis.checks?.map((check, i) => <div className="coverage-row" key={i}><span>{titleCase(check.name)}</span><strong>{check.passed ? 'Passed' : 'Not passed'}</strong></div>)}</section>}
  </div>
}

function ForensicsTab({ image, pdf }) {
  if (!image && !pdf) return <EmptyState icon={Fingerprint} title="No forensic module for this file" detail="The API did not return image or PDF forensic data for this document." />
  return <div className="result-grid-two">{image && <ImageForensics data={image} />}{pdf && <PdfForensics data={pdf} />}</div>
}
function ImageForensics({ data }) {
  const props = data.image_properties || {}
  const exif = data.exif_analysis || {}
  const ela = data.ela_analysis || {}
  const png = data.png_analysis || {}
  const visualization = ela.visualization || png.visualization || null
  const viz = typeof visualization === 'string' ? visualization : visualization?.data
  const vizMime = visualization?.mime_type || 'image/png'
  const vizType = ela.available ? 'JPEG ELA visualization' : png.available ? 'PNG residual visualization' : 'No visualization available'
  return <>
    <section className="panel result-panel"><div className="panel-heading"><div><div className="eyebrow">IMAGE PROPERTIES</div><h3>File characteristics</h3></div><ImageIcon size={18} className="muted-icon" /></div><div className="data-pairs"><DataPair label="Format" value={props.format} /><DataPair label="Dimensions" value={props.width && props.height ? `${props.width} × ${props.height}` : null} /><DataPair label="Color mode" value={props.color_mode} /><DataPair label="Aspect ratio" value={props.aspect_ratio} /><DataPair label="File size" value={formatBytes(props.file_size_bytes)} /></div><div className="subsection-title">EXIF METADATA</div><div className="data-pairs"><DataPair label="Metadata present" value={exif.metadata_present ? 'Yes' : 'No'} /><DataPair label="Software" value={exif.software} /><DataPair label="Date taken" value={exif.date_taken} /><DataPair label="Camera" value={[exif.camera_make, exif.camera_model].filter(Boolean).join(' ') || null} /></div></section>
    <section className="panel result-panel"><div className="panel-heading"><div><div className="eyebrow">PIXEL-LEVEL INSPECTION</div><h3>{ela.available ? 'Error level analysis' : 'PNG residual analysis'}</h3></div><span className="method-chip">{ela.available ? 'JPEG ELA' : png.available ? 'PNG RESIDUAL' : 'UNAVAILABLE'}</span></div><div className="forensic-metrics">{ela.available ? <><DataPair label="Mean difference" value={ela.mean_difference} /><DataPair label="Maximum difference" value={ela.max_difference} /></> : png.available ? <><DataPair label="Mean residual" value={png.metrics?.mean_residual} /><DataPair label="95th percentile" value={png.metrics?.p95_residual} /><DataPair label="99th percentile" value={png.metrics?.p99_residual} /><DataPair label="Maximum residual" value={png.metrics?.max_residual} /></> : <p className="muted-copy">{ela.reason || png.reason || 'Pixel analysis unavailable for this file.'}</p>}</div>{viz && <div className="visualization-wrap"><div className="subsection-title">{vizType.toUpperCase()}</div><img src={`data:${vizMime};base64,${viz}`} alt={vizType} /></div>}<p className="technical-note">{ela.analysis_note || png.analysis_note || 'This analysis is an investigative signal, not proof of image manipulation.'}</p></section>
    <section className="panel result-panel span-two"><div className="panel-heading"><div><div className="eyebrow">FORENSIC FINDINGS</div><h3>Reported image indicators</h3></div><span className="panel-count">{data.findings?.length || 0} ITEMS</span></div>{data.findings?.length ? data.findings.map((f, i) => <FindingCard key={i} finding={f} />) : <div className="no-findings"><CheckCircle2 size={16} /> No actionable image forensic findings were reported by the current module.</div>}<Limitations items={data.limitations || []} /></section>
  </>
}
function PdfForensics({ data }) {
  const s = data.structure || {}; const m = data.metadata || {}
  return <>
    <section className="panel result-panel"><div className="panel-heading"><div><div className="eyebrow">PDF STRUCTURE</div><h3>Document properties</h3></div><FileText size={18} className="muted-icon" /></div><div className="data-pairs"><DataPair label="Analysis status" value={data.status} /><DataPair label="Page count" value={s.page_count} /><DataPair label="PDF version" value={s.pdf_version} /><DataPair label="Encrypted" value={s.is_encrypted === undefined ? null : s.is_encrypted ? 'Yes' : 'No'} /><DataPair label="Repaired during parsing" value={s.is_repaired === undefined ? null : s.is_repaired ? 'Yes' : 'No'} /><DataPair label="XRef objects" value={s.xref_object_count} /><DataPair label="Image references" value={s.total_image_references} /><DataPair label="Annotations" value={s.total_annotations} /></div><div className="subsection-title">PDF METADATA</div><div className="data-pairs"><DataPair label="Title" value={m.title} /><DataPair label="Author" value={m.author} /><DataPair label="Creator" value={m.creator} /><DataPair label="Producer" value={m.producer} /><DataPair label="Created" value={m.creation_date} /><DataPair label="Modified" value={m.modification_date} /></div></section>
    <section className="panel result-panel"><div className="panel-heading"><div><div className="eyebrow">PAGE BREAKDOWN</div><h3>Page structure</h3></div><Layers3 size={18} className="muted-icon" /></div>{s.pages?.length ? s.pages.map((p) => <div className="page-breakdown" key={p.page_number}><div className="page-number">{String(p.page_number).padStart(2, '0')}</div><div><strong>Page {p.page_number}</strong><small>{p.text_character_count} text chars · {p.image_count} images · {p.link_count} links · {p.annotation_count} annotations</small></div></div>) : <p className="muted-copy">No page-level data was returned.</p>}<div className="subsection-title">EMBEDDED FILES</div>{s.embedded_files?.length ? s.embedded_files.map((f, i) => <div className="coverage-row" key={i}><span>{f.name}</span><strong>{f.size_bytes == null ? 'Size unknown' : formatBytes(f.size_bytes)}</strong></div>) : <p className="muted-copy">No embedded files were reported.</p>}</section>
    <section className="panel result-panel span-two"><div className="panel-heading"><div><div className="eyebrow">PDF FORENSIC FINDINGS</div><h3>Reported PDF indicators</h3></div><span className="panel-count">{data.findings?.length || 0} ITEMS</span></div>{data.findings?.length ? data.findings.map((f, i) => <FindingCard key={i} finding={f} />) : <div className="no-findings"><CheckCircle2 size={16} /> No PDF forensic findings were reported by the current module.</div>}<Limitations items={data.limitations || []} /></section>
  </>
}
function DataPair({ label, value }) { return <div className="data-pair"><span>{label}</span><strong>{value === null || value === undefined || value === '' ? 'Not available' : String(value)}</strong></div> }

function FindingsTab({ findings, limitations }) {
  return <div className="findings-layout"><section className="panel result-panel"><div className="panel-heading"><div><div className="eyebrow">EVIDENCE REVIEW</div><h3>Findings and recommendations</h3></div><span className="panel-count">{findings.length} REPORTED</span></div>{findings.length ? findings.map((finding, i) => <FindingCard key={`${finding.code}-${i}`} finding={finding} />) : <EmptyState icon={ShieldCheck} title="No flagged indicators" detail="The current rule-based engine did not report actionable findings. This does not establish authenticity." />}</section><section className="panel result-panel limitations-panel"><div className="panel-heading"><div><div className="eyebrow">SCOPE & LIMITATIONS</div><h3>Read before deciding</h3></div><CircleHelp size={18} className="muted-icon" /></div><Limitations items={limitations} /></section></div>
}
function FindingCard({ finding }) {
  const [open, setOpen] = useState(false)
  const severity = String(finding.severity || 'info').toLowerCase()
  return <div className={`finding-card ${severity}`}><button className="finding-head" onClick={() => setOpen(!open)}><span className={`severity-icon ${severity}`}><AlertCircle size={15} /></span><span className="finding-title"><strong>{finding.title || titleCase(finding.code)}</strong><small>{finding.code || 'FORENSIC_INDICATOR'}</small></span><span className={`severity-label ${severity}`}>{titleCase(severity)}</span>{open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</button>{open && <div className="finding-detail"><p>{finding.explanation || 'No explanation was provided.'}</p>{finding.evidence && <div className="evidence-json"><span>EVIDENCE</span><pre>{JSON.stringify(finding.evidence, null, 2)}</pre></div>}<div className="recommendation"><Sparkles size={14} /><span><strong>Recommended next step</strong>{finding.recommendation || 'Review the original document and verify with the issuing organization.'}</span></div></div>}</div>
}
function Limitations({ items }) { return items.length ? <div className="limitations-list"><div className="subsection-title">MODULE LIMITATIONS</div>{items.map((item, i) => <div className="limitation-item" key={i}><Info size={13} /><span>{item}</span></div>)}</div> : null }

function HistoryPage({ history, loading, onNew, onClear, onOpen, error }) {
  const [query, setQuery] = useState('')
  const filtered = useMemo(() => history.filter((item) => item.filename?.toLowerCase().includes(query.toLowerCase())), [history, query])
  return <><SectionTitle eyebrow="WORKSPACE / ARCHIVE" title="Scan history" detail="Your private cloud archive. Only your authenticated account can access these reports." right={<div className="history-actions">{history.length > 0 && <button className="secondary-button" onClick={onClear}>Clear history</button>}<button className="primary-button" onClick={onNew}><ScanLine size={15} /> New investigation</button></div>} />
    {error && <div className="info-banner"><Info size={15} />{error}</div>}
    <section className="panel history-panel"><div className="history-toolbar"><div className="history-count">{history.length} <span>saved scans</span></div><div className="search-box"><Search size={15} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search by filename…" /></div></div>{loading ? <div className="empty-state"><span className="empty-icon"><RefreshCw size={22}/></span><h3>Loading secure archive</h3><p>Retrieving your private investigations…</p></div> : filtered.length ? <div className="history-table-wrap"><table className="history-table"><thead><tr><th>DOCUMENT</th><th>DATE</th><th>FILE SIZE</th><th>REVIEW PRIORITY</th><th>FINDINGS</th><th /></tr></thead><tbody>{filtered.map((item) => <tr key={item.scan_id}><td><div className="history-file"><FileText size={17} /><span><strong>{item.filename}</strong><small>{item.file_type?.toUpperCase() || 'FILE'} · {item.has_report === true ? 'FULL REPORT SAVED' : 'METADATA ONLY'}</small></span></div></td><td>{dateLabel(item.created_at)}</td><td>{formatBytes(item.file_size_bytes)}</td><td><span className={`mini-risk ${riskTone(item.risk_level)}`}>{titleCase(item.risk_level)}</span></td><td>{item.finding_count ?? '—'}</td><td><button className="icon-button" onClick={() => onOpen(item)} title={item.has_report === false ? "Full report was not saved" : "Open full saved report"}><ArrowRight size={16} /></button></td></tr>)}</tbody></table></div> : <EmptyState icon={History} title={query ? 'No matching scans' : 'Your archive is empty'} detail={query ? 'Try another filename.' : 'Completed investigation reports will appear here after your first cloud save.'} action={!query && <button className="secondary-button small" onClick={onNew}>Start an investigation</button>} />}</section>
    <div className="disclaimer-strip"><Info size={15} /><span>Full analysis and OCR reports are stored in your private Supabase account and protected by Row Level Security. Original uploaded documents remain local to this browser and are not uploaded.</span></div>
  </>
}


function GoogleMark() {
  return <svg className="brand-logo google-logo" viewBox="0 0 48 48" aria-hidden="true">
    <path fill="#4285F4" d="M43.6 24.5c0-1.4-.1-2.8-.4-4.1H24v7.8h11a9.4 9.4 0 0 1-4.1 6.2v5.1h6.7c3.9-3.6 6-8.8 6-15Z"/>
    <path fill="#34A853" d="M24 44c5.5 0 10.1-1.8 13.5-4.9l-6.7-5.1c-1.9 1.3-4.1 2.1-6.8 2.1-5.2 0-9.6-3.5-11.2-8.2H5.9v5.2A20 20 0 0 0 24 44Z"/>
    <path fill="#FBBC05" d="M12.8 27.9a12 12 0 0 1 0-7.8v-5.2H5.9a20 20 0 0 0 0 18.2l6.9-5.2Z"/>
    <path fill="#EA4335" d="M24 11.9c3 0 5.7 1 7.8 3.1l5.9-5.9C34.1 5.8 29.5 4 24 4A20 20 0 0 0 5.9 14.9l6.9 5.2c1.6-4.7 6-8.2 11.2-8.2Z"/>
  </svg>
}
function GitHubMark() {
  return <svg className="brand-logo github-logo" viewBox="0 0 24 24" aria-hidden="true">
    <path fill="currentColor" d="M12 .9a11.1 11.1 0 0 0-3.5 21.6c.6.1.8-.2.8-.6v-2.1c-3.2.7-3.9-1.4-3.9-1.4-.5-1.3-1.3-1.7-1.3-1.7-1-.7.1-.7.1-.7 1.1.1 1.7 1.1 1.7 1.1 1 .1.7 2.2 3.8 1.5.1-.7.4-1.2.7-1.5-2.6-.3-5.3-1.3-5.3-5.8 0-1.3.5-2.3 1.2-3.1-.1-.3-.5-1.5.1-3.1 0 0 1-.3 3.2 1.2a11 11 0 0 1 5.8 0c2.2-1.5 3.2-1.2 3.2-1.2.6 1.6.2 2.8.1 3.1.8.8 1.2 1.8 1.2 3.1 0 4.5-2.7 5.5-5.3 5.8.4.3.8 1 .8 2v3c0 .4.2.7.8.6A11.1 11.1 0 0 0 12 .9Z"/>
  </svg>
}
function AppleMark() {
  return <svg className="brand-logo apple-logo" viewBox="0 0 24 24" aria-hidden="true">
    <path fill="currentColor" d="M16.7 12.8c0-2.2 1.8-3.3 1.9-3.4a4.1 4.1 0 0 0-3.2-1.7c-1.4-.2-2.7.8-3.4.8-.7 0-1.8-.8-3-.8a4.5 4.5 0 0 0-3.8 2.3c-1.6 2.8-.4 6.9 1.1 9.1.7 1.1 1.6 2.3 2.7 2.2 1.1 0 1.5-.7 2.9-.7 1.3 0 1.7.7 2.9.7 1.2 0 1.9-1.1 2.6-2.2a10 10 0 0 0 1.2-2.5 3.9 3.9 0 0 1-1.9-3.8ZM14.5 6.3a4 4 0 0 0 .9-2.9 4.2 4.2 0 0 0-2.7 1.4 3.8 3.8 0 0 0-.9 2.8 3.5 3.5 0 0 0 2.7-1.3Z"/>
  </svg>
}
function MicrosoftMark() {
  return <svg className="brand-logo microsoft-logo" viewBox="0 0 24 24" aria-hidden="true">
    <path fill="#F25022" d="M1 1h10v10H1z"/><path fill="#7FBA00" d="M13 1h10v10H13z"/>
    <path fill="#00A4EF" d="M1 13h10v10H1z"/><path fill="#FFB900" d="M13 13h10v10H13z"/>
  </svg>
}


function AuthScreen() {
  const [mode, setMode] = useState('signin')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [devNotice, setDevNotice] = useState('')

  const changeMode = (next) => { setMode(next); setError(''); setMessage('') }
  const run = async (action) => {
    setBusy(true); setError(''); setMessage('')
    try { await action() }
    catch (e) { setError(e.message || 'Authentication failed. Please try again.') }
    finally { setBusy(false) }
  }

  const submitEmail = (event) => {
    event.preventDefault()
    if (!email.trim()) return setError('Enter your email address.')
    if (mode !== 'reset' && password.length < 8) return setError('Use a password with at least 8 characters.')
    run(async () => {
      if (mode === 'signup') {
        const { error: authError } = await supabase.auth.signUp({
          email: email.trim(), password,
          options: { emailRedirectTo: window.location.origin }
        })
        if (authError) throw authError
        setMessage('Account created. Check your email for a verification link before signing in.')
      } else if (mode === 'reset') {
        const { error: authError } = await supabase.auth.resetPasswordForEmail(email.trim(), {
          redirectTo: `${window.location.origin}/`
        })
        if (authError) throw authError
        setMessage('If an account exists for this email, a password-reset link has been sent.')
      } else {
        const { error: authError } = await supabase.auth.signInWithPassword({ email: email.trim(), password })
        if (authError) throw authError
      }
    })
  }

  const oauth = (provider) => {
    // Apple and Microsoft are intentionally marked as in development.
    // Google and GitHub continue using the configured Supabase OAuth flow.
    if (provider === 'apple' || provider === 'azure') {
      setDevNotice(provider)
      return
    }

    run(async () => {
      const { error: authError } = await supabase.auth.signInWithOAuth({
        provider,
        options: { redirectTo: window.location.origin }
      })
      if (authError) throw authError
    })
  }

  const isReset = mode === 'reset'
  const isSignup = mode === 'signup'

  return <main className="auth-shell">
    <div className="auth-noise" aria-hidden="true" />
    <div className="auth-ambient auth-ambient-one" /><div className="auth-ambient auth-ambient-two" />
    <div className="auth-topline"><div className="auth-brand">
      <div className="auth-brand-mark"><Fingerprint size={25}/><span className="brand-mark-sweep"/></div>
      <div><strong>SCAM<span>SCAN</span></strong><small>DIGITAL TRUST INTELLIGENCE</small></div>
    </div><div className="auth-top-status"><span className="auth-live-dot"/> FORENSIC ENVIRONMENT <b>SECURE</b></div></div>

    <div className="auth-layout">
      <section className="auth-card">
        <div className="auth-card-top"><span className="auth-step">{isReset ? 'ACCOUNT RECOVERY' : isSignup ? 'NEW INVESTIGATION ID' : 'IDENTITY VERIFICATION'}</span><span className="auth-encryption"><LockKeyhole size={12}/> 256-BIT ENCRYPTION</span></div>
        <div className="auth-eyebrow"><span/> SECURE FORENSIC WORKSPACE</div>
        <h1>{isSignup ? <>Build your<br/><em>secure workspace.</em></> : isReset ? <>Regain your<br/><em>access.</em></> : <>Welcome to<br/><em>the investigation.</em></>}</h1>
        <p className="auth-subtitle">{isSignup ? 'Create your identity to start examining documents with confidence.' : isReset ? 'A secure recovery link will be sent to your registered email.' : 'Sign in to access your digital evidence and forensic workspace.'}</p>

        {!isReset && <>
          <div className="auth-social-heading"><span>CONTINUE WITH YOUR IDENTITY PROVIDER</span><i/></div>
          <div className="oauth-grid">
            <button type="button" className="oauth-button" onClick={() => oauth('google')} disabled={busy || !supabaseConfigured}><GoogleMark/><span>Continue with Google</span><ArrowUpRightIcon/></button>
            <button type="button" className="oauth-button" onClick={() => oauth('github')} disabled={busy || !supabaseConfigured}><GitHubMark/><span>Continue with GitHub</span><ArrowUpRightIcon/></button>
            <button type="button" className="oauth-button" onClick={() => oauth('apple')} disabled={busy || !supabaseConfigured}><AppleMark/><span>Continue with Apple</span><ArrowUpRightIcon/></button>
            <button type="button" className="oauth-button" onClick={() => oauth('azure')} disabled={busy || !supabaseConfigured}><MicrosoftMark/><span>Continue with Microsoft</span><ArrowUpRightIcon/></button>
          </div>
        </>}
        <div className="auth-divider"><span/>{isReset ? 'EMAIL RECOVERY' : 'OR USE EMAIL CREDENTIALS'}<span/></div>
        {!supabaseConfigured && <div className="auth-alert error"><AlertCircle size={15}/><span>Supabase is not connected yet. Add your project URL and publishable/anon key to <code>.env</code>, then restart Vite.</span></div>}
        <form className="auth-form" onSubmit={submitEmail}>
          <label>Email address<div className="auth-input-wrap"><span className="auth-input-icon"><AtSignIcon/></span><input type="email" autoComplete="email" placeholder="name@company.com" value={email} onChange={e=>setEmail(e.target.value)} required/></div></label>
          {!isReset && <label>Password<div className="auth-input-wrap"><span className="auth-input-icon"><LockKeyhole size={16}/></span><input type="password" autoComplete={isSignup ? 'new-password' : 'current-password'} placeholder="Minimum 8 characters" value={password} onChange={e=>setPassword(e.target.value)} minLength={8} required/></div></label>}
          {mode === 'signin' && <button className="auth-forgot" type="button" onClick={()=>changeMode('reset')}>Forgot password? <ArrowUpRightIcon/></button>}
          {error && <div className="auth-alert error"><AlertCircle size={15}/><span>{error}</span></div>}
          {message && <div className="auth-alert success"><CheckCircle2 size={15}/><span>{message}</span></div>}
          <button className="auth-submit" type="submit" disabled={busy || !supabaseConfigured}>
            <span>{busy ? <><span className="auth-button-spinner"/> Securing your session…</> : isSignup ? 'Create secure account' : isReset ? 'Send recovery link' : 'Enter secure workspace'}</span>
            {!busy && <ArrowRight size={17}/>}
          </button>
        </form>
        <div className="auth-switch">
          {isReset ? <button onClick={()=>changeMode('signin')}><ArrowLeft size={14}/> Return to sign in</button> : isSignup ? <>Already have an identity? <button onClick={()=>changeMode('signin')}>Sign in <ArrowRight size={13}/></button></> : <>New to ScamScan? <button onClick={()=>changeMode('signup')}>Create an account <ArrowRight size={13}/></button></>}
        </div>
        <div className="auth-foot"><ShieldCheck size={14}/><span>Identity secured by Supabase <i/> Your documents stay in your local workspace.</span></div>
      </section>

      <section className="auth-showcase">
        <div className="showcase-grid" aria-hidden="true"/>
        <div className="showcase-kicker"><span className="kicker-line"/> THE SCIENCE OF DIGITAL TRUST <span className="kicker-index">01 / 04</span></div>
        <div className="forensic-visual" aria-label="Animated forensic fingerprint visualization">
          <div className="visual-halo halo-a"/><div className="visual-halo halo-b"/><div className="visual-orbit orbit-a"/><div className="visual-orbit orbit-b"/><div className="visual-orbit orbit-c"/>
          <div className="visual-crosshair crosshair-x"/><div className="visual-crosshair crosshair-y"/>
          <div className="visual-fingerprint"><Fingerprint size={112} strokeWidth={1.15}/></div>
          <div className="visual-scan-beam"/>
          <span className="visual-particle particle-a"/><span className="visual-particle particle-b"/><span className="visual-particle particle-c"/><span className="visual-particle particle-d"/>
          <div className="visual-coordinate coord-a">LAT 04.812 / SIG 98.2</div><div className="visual-coordinate coord-b">TRACE / 0x7A91</div>
          <div className="visual-readout"><span>BIOMETRIC PATTERN</span><strong>ANALYSIS READY</strong><i/></div>
        </div>
        <div className="showcase-copy"><div className="showcase-overline">DOCUMENT FORENSICS <span>×</span> DIGITAL INTELLIGENCE</div>
          <h2>See what the<br/>document <em>doesn't say.</em></h2>
          <p>Go beyond the visible. Extract information, inspect technical signals, and make better-informed evidence reviews.</p>
          <div className="showcase-capabilities"><div><Fingerprint size={16}/><span>PIXEL-LEVEL<br/><b>IMAGE SIGNALS</b></span></div><div><Binary size={16}/><span>TEXT & DATA<br/><b>INTELLIGENCE</b></span></div><div><ShieldCheck size={16}/><span>EXPLAINABLE<br/><b>RISK REVIEW</b></span></div></div>
        </div>
        <div className="showcase-footer"><span>SCAMSCAN INTELLIGENCE ENGINE</span><span>SCAN. INVESTIGATE. VERIFY.</span></div>
      </section>
    </div>
    <AnimatePresence>
      {devNotice && (
        <motion.div
          className="auth-dev-notice"
          style={{
            position: 'fixed', bottom: '30px', left: '50%',
            transform: 'translateX(-50%)', zIndex: 9999,
            display: 'flex', alignItems: 'center', gap: '14px',
            width: 'min(420px, calc(100vw - 32px))', boxSizing: 'border-box',
            padding: '15px 18px', borderRadius: '15px',
            border: '1px solid rgba(167,139,250,0.38)',
            background: 'rgba(18, 17, 29, 0.96)',
            backdropFilter: 'blur(18px)',
            boxShadow: '0 16px 50px rgba(0,0,0,0.48)', color: '#fff'
          }}
          role="status"
          aria-live="polite"
          initial={{ opacity: 0, y: 28, scale: 0.94 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 20, scale: 0.96 }}
          transition={{ type: 'spring', stiffness: 260, damping: 22 }}
        >
          <motion.span
            className="auth-dev-notice-icon"
            style={{ color: '#b7a0ff', fontSize: '27px', lineHeight: 1, flexShrink: 0 }}
            animate={{ rotate: 360 }}
            transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
            aria-hidden="true"
          >
            ◈
          </motion.span>
          <span className="auth-dev-notice-copy" style={{ display: 'grid', gap: '5px', flex: 1, minWidth: 0 }}>
            <strong style={{ color: '#c4b5fd', fontSize: '12px', letterSpacing: '1.1px' }}>DEVELOPMENT IN PROCESS</strong>
            <small style={{ color: '#aaa6b8', fontSize: '12px' }}>{devNotice === 'apple' ? 'Apple' : 'Microsoft'} authentication is coming soon.</small>
          </span>
          <button
            type="button"
            className="auth-dev-notice-close"
            style={{ background: 'transparent', border: 0, color: '#aaa6b8', cursor: 'pointer', fontSize: '23px', lineHeight: 1, padding: '2px 5px' }}
            onClick={() => setDevNotice('')}
            aria-label="Dismiss notification"
          >
            ×
          </button>
        </motion.div>
      )}
    </AnimatePresence>

    <div className="auth-bottomline"><span>© SCAMSCAN 2.0</span><span>DESIGNED FOR EVIDENCE-LED INVESTIGATION</span><span>BUILD 02.11 <i/></span></div>
  </main>
}

function ArrowUpRightIcon() { return <svg className="oauth-arrow" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M4 12 12 4M5 4h7v7" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg> }
function AtSignIcon() { return <svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><circle cx="10" cy="10" r="7.2" stroke="currentColor" strokeWidth="1.4"/><path d="M13.2 10.1c0 1.7-.8 2.6-2 2.6-1.5 0-2.6-1.1-2.6-2.8 0-1.8 1.1-3 2.6-3 1.1 0 2 .8 2 2.2v1.6c0 1.3.6 2 1.5 2 1.1 0 1.9-1.1 1.9-2.8A6.6 6.6 0 1 0 10 16.6" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/></svg> }

function App() {
  const [session, setSession] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    supabase.auth.getSession().then(({ data, error }) => {
      if (!alive) return
      if (error) console.error('Supabase session:', error.message)
      setSession(data?.session ?? null)
      setLoading(false)
    })
    const { data: listener } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession)
      setLoading(false)
    })
    return () => { alive = false; listener.subscription.unsubscribe() }
  }, [])

  const signOut = async () => {
    const { error } = await supabase.auth.signOut()
    if (error) window.alert(error.message)
  }

  if (loading) return <div className="auth-loading"><div className="auth-loader"><Fingerprint size={34}/></div><span>INITIALIZING SECURE SESSION</span></div>
  if (!session) return <AuthScreen/>
  return <DashboardApp user={session.user} onSignOut={signOut}/>
}

export default App
