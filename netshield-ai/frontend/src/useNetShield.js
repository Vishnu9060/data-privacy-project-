import { useState } from 'react'
import axios from 'axios'

const API = 'http://127.0.0.1:8000'

// Central hook holding all shared state and backend calls for the app.
// Kept as one hook (rather than split per-page) because several pages need
// to read/react to state owned by other pages (e.g. the sidebar's Current
// Identity card shows the MAC from the Privacy Lab page; Security Analysis
// reuses whatever packets were already captured).
export default function useNetShield() {
  const [devices, setDevices] = useState(null)
  const [scanNote, setScanNote] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  // Per-host deep scan (OS + ports + services), keyed by IP, run on demand
  // from the Network Discovery table rather than automatically for every
  // discovered host (nmap OS detection is slow per host).
  const [hostScans, setHostScans] = useState({}) // ip -> { loading, error, data }

  const [packets, setPackets] = useState(null)
  const [packetSummary, setPacketSummary] = useState(null)
  const [packetsLoading, setPacketsLoading] = useState(false)
  const [packetsError, setPacketsError] = useState(null)
  const [protocolFilter, setProtocolFilter] = useState('ALL')
  const [selectedDeviceIp, setSelectedDeviceIp] = useState(null)

  const [adapters, setAdapters] = useState(null)
  const [adaptersLoading, setAdaptersLoading] = useState(false)
  const [adaptersError, setAdaptersError] = useState(null)

  const [selectedInterface, setSelectedInterface] = useState('')
  const [macChangeLoading, setMacChangeLoading] = useState(false)
  const [macChangeError, setMacChangeError] = useState(null)
  const [macChangeResult, setMacChangeResult] = useState(null)
  const [macLog, setMacLog] = useState([])

  const [analysisTarget, setAnalysisTarget] = useState('127.0.0.1')
  const [analysisResults, setAnalysisResults] = useState(null)
  const [analysisError, setAnalysisError] = useState(null)

  const [reportData, setReportData] = useState(null)
  const [reportLoading, setReportLoading] = useState(false)
  const [reportError, setReportError] = useState(null)

  const [footfallData, setFootfallData] = useState(null)
  const [footfallLoading, setFootfallLoading] = useState(false)
  const [footfallError, setFootfallError] = useState(null)

  const handleLoadFootfall = async () => {
    setFootfallLoading(true)
    setFootfallError(null)
    try {
      const response = await axios.get(`${API}/footfall/dashboard`)
      if (response.data.error) {
        setFootfallError(response.data.error)
      } else {
        setFootfallData(response.data)
      }
    } catch (err) {
      setFootfallError('Failed to reach backend: ' + err.message)
    } finally {
      setFootfallLoading(false)
    }
  }

  const handleScan = async () => {
    setLoading(true)
    setError(null)
    setDevices(null)
    setScanNote(null)

    try {
      const response = await axios.get(`${API}/scan`)
      if (response.data.error) {
        setError(response.data.error)
      } else {
        setDevices(response.data.devices)
        setScanNote(response.data.note || null)
      }
    } catch (err) {
      setError('Failed to reach backend: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  // Deep scan of one discovered host: OS detection, TCP ports, services,
  // and versions. Triggered per-row on the Network Discovery page, so a
  // host you don't care about is never scanned.
  const handleHostScan = async (ip) => {
    setHostScans((prev) => ({ ...prev, [ip]: { loading: true, error: null, data: null } }))
    try {
      const response = await axios.get(`${API}/host-scan`, { params: { target: ip } })
      if (response.data.error) {
        setHostScans((prev) => ({ ...prev, [ip]: { loading: false, error: response.data.error, data: null } }))
      } else {
        setHostScans((prev) => ({ ...prev, [ip]: { loading: false, error: null, data: response.data } }))
      }
    } catch (err) {
      setHostScans((prev) => ({
        ...prev,
        [ip]: { loading: false, error: 'Failed to reach backend: ' + err.message, data: null },
      }))
    }
  }

  const handleCapture = async () => {
    setPacketsLoading(true)
    setPacketsError(null)
    setPackets(null)
    setPacketSummary(null)
    setProtocolFilter('ALL')

    try {
      // Always capture everything unfiltered — filtering happens after the
      // fact via the protocol chips in the table, so nothing is missed.
      const response = await axios.get(`${API}/capture-live`)
      if (response.data.error) {
        setPacketsError(response.data.error)
      } else {
        setPackets(response.data.packets)
        setPacketSummary(response.data.summary)
      }
    } catch (err) {
      setPacketsError('Failed to reach backend: ' + err.message)
    } finally {
      setPacketsLoading(false)
    }
  }

  const handleShowAdapters = async () => {
    setAdaptersLoading(true)
    setAdaptersError(null)
    setAdapters(null)

    try {
      const response = await axios.get(`${API}/network-adapter-info`)
      if (response.data.error) {
        setAdaptersError(response.data.error)
      } else {
        setAdapters(response.data.adapters)
        if (response.data.adapters.length > 0 && !selectedInterface) {
          setSelectedInterface(response.data.adapters[0].name)
        }
      }
    } catch (err) {
      setAdaptersError('Failed to reach backend: ' + err.message)
    } finally {
      setAdaptersLoading(false)
    }
  }

  const handleRandomizeMac = async () => {
    setMacChangeLoading(true)
    setMacChangeError(null)
    setMacChangeResult(null)

    try {
      // Allow calling this before the adapter list has ever been fetched
      // (e.g. from the sidebar's quick-action button) by resolving an
      // interface to target on the fly.
      let iface = selectedInterface
      if (!iface) {
        const adaptersResp = await axios.get(`${API}/network-adapter-info`)
        if (adaptersResp.data.error) {
          setMacChangeError(adaptersResp.data.error)
          setMacChangeLoading(false)
          return
        }
        setAdapters(adaptersResp.data.adapters)
        iface = adaptersResp.data.adapters[0] && adaptersResp.data.adapters[0].name
        if (!iface) {
          setMacChangeError('No network adapters found.')
          setMacChangeLoading(false)
          return
        }
        setSelectedInterface(iface)
      }

      const response = await axios.post(`${API}/privacy-lab/change-mac`, {
        interface: iface,
      })
      if (response.data.error) {
        setMacChangeError(response.data.error)
      } else {
        setMacChangeResult(response.data)
        setMacLog((prev) => [
          ...prev,
          {
            time: new Date().toLocaleTimeString(),
            action: 'Randomized',
            interface: response.data.interface,
            before: response.data.before_mac,
            after: response.data.after_mac,
          },
        ])
        handleShowAdapters()
      }
    } catch (err) {
      setMacChangeError('Failed to reach backend: ' + err.message)
    } finally {
      setMacChangeLoading(false)
    }
  }

  const handleRestoreMac = async () => {
    if (!selectedInterface) return
    setMacChangeLoading(true)
    setMacChangeError(null)
    setMacChangeResult(null)

    try {
      const response = await axios.post(`${API}/privacy-lab/restore-mac`, {
        interface: selectedInterface,
      })
      if (response.data.error) {
        setMacChangeError(response.data.error)
      } else {
        setMacChangeResult(response.data)
        setMacLog((prev) => [
          ...prev,
          {
            time: new Date().toLocaleTimeString(),
            action: 'Restored',
            interface: response.data.interface,
            before: response.data.before_mac,
            after: response.data.after_mac,
          },
        ])
        handleShowAdapters()
      }
    } catch (err) {
      setMacChangeError('Failed to reach backend: ' + err.message)
    } finally {
      setMacChangeLoading(false)
    }
  }

  const generateReportFrom = async (payload) => {
    const response = await axios.post(`${API}/generate-report`, payload)
    setReportData({ ...response.data, timestamp: new Date().toLocaleString() })
  }

  // Runs every scan itself (independent of whether those pages were visited),
  // then builds the report. Uses fresh values from the responses directly,
  // since React state updates asynchronously and wouldn't be visible within
  // this same function.
  const handleRunFullAssessment = async () => {
    setReportLoading(true)
    setReportError(null)
    setAnalysisError(null)
    setAnalysisResults(null)
    setReportData(null)
    try {
      const results = { devices: null, adapters: null, security: null }

      try {
        const scan = await axios.get(`${API}/scan`)
        if (!scan.data.error) {
          results.devices = scan.data.devices
          setDevices(scan.data.devices)
        }
      } catch { /* leave devices null */ }

      try {
        const adaptersResp = await axios.get(`${API}/network-adapter-info`)
        if (!adaptersResp.data.error) {
          results.adapters = adaptersResp.data.adapters
          setAdapters(adaptersResp.data.adapters)
        }
      } catch { /* leave adapters null */ }

      try {
        const sec = await axios.get(`${API}/security-analysis`, {
          params: { target: analysisTarget },
        })
        if (sec.data.error) {
          setAnalysisError(sec.data.error)
        } else {
          results.security = sec.data
          setAnalysisResults(sec.data)
        }
      } catch { /* leave security null */ }

      await generateReportFrom({
        devices: results.devices,
        packets: packets || null,
        packet_summary: packetSummary || null,
        adapters: results.adapters,
        security: results.security,
      })
    } catch (err) {
      setReportError('Failed to reach backend: ' + err.message)
    } finally {
      setReportLoading(false)
    }
  }

  // Build a clean, self-contained HTML document and open the browser's print
  // dialog, where the user picks "Save as PDF". No external PDF library needed.
  const handleDownloadPdf = () => {
    if (!reportData) return
    const r = reportData
    const esc = (s) =>
      String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

    const sectionOrder = [
      ['network_discovery', 'Network Discovery'],
      ['packet_analysis', 'Packet Analysis'],
      ['privacy_lab', 'Privacy Lab'],
      ['security_analysis', 'Security Analysis'],
    ]

    const metricsRows = sectionOrder
      .map(([key, title]) => {
        const m = r.metrics[key]
        let detail = '—'
        if (m.ran && key === 'network_discovery') detail = `${m.devices_found} devices found`
        else if (m.ran && key === 'packet_analysis')
          detail =
            `${m.total_packets} packets, ${m.dns_queries} DNS lookups — ` +
            Object.entries(m.protocol_counts).map(([p, c]) => `${c} ${p}`).join(', ')
        else if (m.ran && key === 'privacy_lab') detail = `${m.adapters_found} adapters listed`
        else if (m.ran && key === 'security_analysis')
          detail = `Grade ${m.grade} (${m.score}/100) — ${m.open_ports} open, ${m.insecure_protocols} insecure, ${m.unnecessary_ports} unnecessary, ${m.high} high-risk`
        return `<tr><td>${esc(title)}</td><td>${m.ran ? 'Ran' : 'Skipped'}</td><td>${esc(detail)}</td></tr>`
      })
      .join('')

    const summaryBlocks = sectionOrder
      .map(([key, title]) => `<h3>${esc(title)}</h3><p>${esc(r.summary.sections[key])}</p>`)
      .join('')

    const findings = analysisResults && analysisResults.findings ? analysisResults.findings : []
    const findingsRows = findings
      .map(
        (f) =>
          `<tr><td>${f.port}</td><td>${esc(f.service)}</td><td>${f.risk}</td><td>${f.necessity}</td><td>${esc(f.recommendation)}</td></tr>`
      )
      .join('')
    const findingsTable = findings.length
      ? `<h2>Security Findings &amp; Firewall Recommendations</h2>
         <table><thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Necessity</th><th>Recommendation</th></tr></thead>
         <tbody>${findingsRows}</tbody></table>`
      : ''

    const html = `<!doctype html><html><head><meta charset="utf-8"><title>ShopRadar Report</title>
      <style>
        body { font-family: 'Courier New', monospace; color:#1e293b; margin:32px; line-height:1.5; }
        h1 { color:#7c3aed; margin-bottom:4px; }
        h2 { color:#0f172a; border-bottom:2px solid #e2e8f0; padding-bottom:4px; margin-top:28px; }
        h3 { color:#0f172a; margin-bottom:2px; }
        .meta { color:#64748b; font-size:13px; }
        .overall { background:#f1f5f9; border-left:4px solid #7c3aed; padding:12px 16px; margin:16px 0; }
        table { width:100%; border-collapse:collapse; margin:12px 0; font-size:13px; }
        th,td { border:1px solid #e2e8f0; padding:8px; text-align:left; vertical-align:top; }
        th { background:#f8fafc; }
      </style></head><body>
      <h1>ShopRadar — Security &amp; Footfall Report</h1>
      <p class="meta">Generated: ${esc(r.timestamp)} · Summary by: ${esc(r.summary_source === 'groq' ? 'Groq AI' : 'built-in analyzer')}</p>
      <div class="overall">${esc(r.summary.overall)}</div>
      <h2>Metrics</h2>
      <table><thead><tr><th>Section</th><th>Status</th><th>Key Metrics</th></tr></thead><tbody>${metricsRows}</tbody></table>
      <h2>Summary (Plain English)</h2>
      ${summaryBlocks}
      ${findingsTable}
      </body></html>`

    const w = window.open('', '_blank')
    if (!w) {
      alert('Please allow pop-ups to download the PDF.')
      return
    }
    w.document.write(html)
    w.document.close()
    w.focus()
    setTimeout(() => w.print(), 300)
  }

  return {
    devices, scanNote, loading, error, handleScan,
    hostScans, handleHostScan,
    packets, packetSummary, packetsLoading, packetsError,
    protocolFilter, setProtocolFilter,
    selectedDeviceIp, setSelectedDeviceIp,
    handleCapture,
    adapters, adaptersLoading, adaptersError, handleShowAdapters,
    selectedInterface, setSelectedInterface,
    macChangeLoading, macChangeError, macChangeResult, macLog,
    handleRandomizeMac, handleRestoreMac,
    analysisTarget, setAnalysisTarget, analysisResults, analysisError,
    reportData, reportLoading, reportError,
    handleRunFullAssessment, handleDownloadPdf,
    footfallData, footfallLoading, footfallError, handleLoadFootfall,
  }
}
