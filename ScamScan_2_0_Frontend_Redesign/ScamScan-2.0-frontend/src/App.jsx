import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import {
  Activity, AlertCircle, ArrowDownToLine, ArrowLeft, ArrowRight, BadgeCheck,
  Binary, Check, CheckCircle2, ChevronDown, ChevronRight, CircleHelp,
  Clock3, CloudUpload, Cpu, Database, File, FileCheck2, FileImage,
  FileSearch, FileText, Fingerprint, Gauge, HardDrive, History, Image as ImageIcon,
  Info, Layers3, LockKeyhole, Menu, Network, RefreshCw, ScanLine, Search,
  Shield, ShieldAlert, ShieldCheck, Sparkles, Upload, X, Zap,
} from 'lucide-react'
import { api } from './api'

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

export default function App() {
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
  const [history, setHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('scamscan.history') || '[]') }
    catch { return [] }
  })
  const [mobileNav, setMobileNav] = useState(false)
  const inputRef = useRef(null)

  const refreshSystem = useCallback(async () => {
    try {
      const [h, s] = await Promise.all([api.health(), api.systemInfo()])
      setHealth(h); setSystem(s); setBackendError('')
    } catch (e) { setHealth(null); setSystem(null); setBackendError(e.message) }
  }, [])

  useEffect(() => { refreshSystem() }, [refreshSystem])
  useEffect(() => { localStorage.setItem('scamscan.history', JSON.stringify(history.slice(0, 30))) }, [history])

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
          result: savedResult,
          ocr: ocrData,
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
      setHistory((items) => [entry, ...items.filter((item) => item.scan_id !== entry.scan_id)].slice(0, 30))
    } catch (e) {
      setError(e.message || 'Analysis failed. Please try again.')
    } finally { setBusy(false); setStage('') }
  }

  const openHistoryItem = async (item) => {
    setError('')
    try {
      const archived = await readArchivedReport(item.scan_id)
      if (!archived?.result) {
        setError(`“${item.filename}” is an older history entry. Its original report was not saved, so it cannot be reconstructed without running a new scan.`)
        setPage('history')
        return
      }
      setResult(archived.result)
      setOcr(archived.ocr || null)
      if (archived.original_blob) {
        try {
          const restoredFile = new File(
            [archived.original_blob],
            archived.original_file_name || item.filename || 'original-document',
            {
              type: archived.original_file_type || archived.original_blob.type || 'application/octet-stream',
              lastModified: archived.original_last_modified || Date.now(),
            }
          )
          setOriginalFile(restoredFile)
        } catch {
          setOriginalFile(archived.original_blob)
        }
      } else {
        setOriginalFile(null)
      }
      setActiveTab('summary')
      setPage('results')
    } catch (storageError) {
      setError(`Could not open this saved report: ${storageError.message}`)
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
    if (!window.confirm('Clear all locally saved scan history and full reports from this browser?')) return
    try { await clearArchivedReports() }
    catch (storageError) { console.error('ScamScan archive clear:', storageError) }
    setHistory([])
  }

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
          <div className="topbar-right"><div className="live-indicator"><span className={`status-dot ${health ? 'online' : 'offline'}`} />{health ? 'SYSTEM OPERATIONAL' : 'API DISCONNECTED'}</div><div className="avatar">S</div></div>
        </header>

        <div className="page-content">
          <AnimatePresence mode="wait">
            {page === 'overview' && <motion.div key="overview" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: .2 }}><Overview health={health} system={system} history={history} onNew={() => { setPage('new-scan'); setError('') }} onHistory={() => setPage('history')} /></motion.div>}
            {page === 'new-scan' && <motion.div key="new" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: .2 }}><NewScan file={file} setSelectedFile={setSelectedFile} dragging={dragging} setDragging={setDragging} inputRef={inputRef} busy={busy} stage={stage} error={error} onAnalyze={runAnalysis} onClear={() => { setFile(null); setError(''); if (inputRef.current) inputRef.current.value = '' }} /></motion.div>}
            {page === 'results' && result && <motion.div key="results" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: .2 }}><Results result={result} ocr={ocr} activeTab={activeTab} setActiveTab={setActiveTab} onBack={() => setPage('history')} originalFile={originalFile} onOpenOriginal={openOriginalDocument} /></motion.div>}
            {page === 'history' && <motion.div key="history" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: .2 }}><HistoryPage history={history} onNew={() => setPage('new-scan')} onClear={clearHistory} onOpen={openHistoryItem} error={error} /></motion.div>}
          </AnimatePresence>
        </div>
        <footer className="footer"><span>SCAMSCAN INTELLIGENCE ENGINE <i>•</i> RULE-BASED ANALYSIS</span><span>SCAN. INVESTIGATE. VERIFY.</span></footer>
      </main>
    </div>
  )
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

function HistoryPage({ history, onNew, onClear, onOpen, error }) {
  const [query, setQuery] = useState('')
  const filtered = useMemo(() => history.filter((item) => item.filename?.toLowerCase().includes(query.toLowerCase())), [history, query])
  return <><SectionTitle eyebrow="WORKSPACE / ARCHIVE" title="Scan history" detail="A local record of completed investigations in this browser." right={<div className="history-actions">{history.length > 0 && <button className="secondary-button" onClick={onClear}>Clear history</button>}<button className="primary-button" onClick={onNew}><ScanLine size={15} /> New investigation</button></div>} />
    {error && <div className="info-banner"><Info size={15} />{error}</div>}
    <section className="panel history-panel"><div className="history-toolbar"><div className="history-count">{history.length} <span>saved scans</span></div><div className="search-box"><Search size={15} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search by filename…" /></div></div>{filtered.length ? <div className="history-table-wrap"><table className="history-table"><thead><tr><th>DOCUMENT</th><th>DATE</th><th>FILE SIZE</th><th>REVIEW PRIORITY</th><th>FINDINGS</th><th /></tr></thead><tbody>{filtered.map((item) => <tr key={item.scan_id}><td><div className="history-file"><FileText size={17} /><span><strong>{item.filename}</strong><small>{item.file_type?.toUpperCase() || 'FILE'} · {item.has_report === true ? 'FULL REPORT SAVED' : 'METADATA ONLY'}</small></span></div></td><td>{dateLabel(item.created_at)}</td><td>{formatBytes(item.file_size_bytes)}</td><td><span className={`mini-risk ${riskTone(item.risk_level)}`}>{titleCase(item.risk_level)}</span></td><td>{item.finding_count ?? '—'}</td><td><button className="icon-button" onClick={() => onOpen(item)} title={item.has_report === false ? "Full report was not saved" : "Open full saved report"}><ArrowRight size={16} /></button></td></tr>)}</tbody></table></div> : <EmptyState icon={History} title={query ? 'No matching scans' : 'Your archive is empty'} detail={query ? 'Try another filename.' : 'Completed analysis summaries will be saved here on this device.'} action={!query && <button className="secondary-button small" onClick={onNew}>Start an investigation</button>} />}</section>
    <div className="disclaimer-strip"><Info size={15} /><span>History summaries, complete OCR and forensic reports, and original uploaded files are saved locally in this browser's IndexedDB. You can reopen saved reports and original documents from this device. Older entries created before original-file archiving may contain report data only.</span></div>
  </>
}
