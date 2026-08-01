import { useState } from 'react'
import axios from 'axios'
import './App.css'

function App() {
  const [devices, setDevices] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const [packets, setPackets] = useState(null)
  const [packetsLoading, setPacketsLoading] = useState(false)
  const [packetsError, setPacketsError] = useState(null)

  const [adapters, setAdapters] = useState(null)
  const [adaptersLoading, setAdaptersLoading] = useState(false)
  const [adaptersError, setAdaptersError] = useState(null)
  const [newMacInput, setNewMacInput] = useState('')
  const [macLog, setMacLog] = useState([])

  const [analysisTarget, setAnalysisTarget] = useState('127.0.0.1')
  const [analysisResults, setAnalysisResults] = useState(null)
  const [analysisLoading, setAnalysisLoading] = useState(false)
  const [analysisError, setAnalysisError] = useState(null)

  const handleScan = async () => {
    setLoading(true)
    setError(null)
    setDevices(null)

    try {
      const response = await axios.get('http://127.0.0.1:8000/scan')
      if (response.data.error) {
        setError(response.data.error)
      } else {
        setDevices(response.data.devices)
      }
    } catch (err) {
      setError('Failed to reach backend: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleCapture = async () => {
    setPacketsLoading(true)
    setPacketsError(null)
    setPackets(null)

    try {
      const response = await axios.get('http://127.0.0.1:8000/capture-live')
      if (response.data.error) {
        setPacketsError(response.data.error)
      } else {
        setPackets(response.data.packets)
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
      const response = await axios.get('http://127.0.0.1:8000/network-adapter-info')
      if (response.data.error) {
        setAdaptersError(response.data.error)
      } else {
        setAdapters(response.data.adapters)
      }
    } catch (err) {
      setAdaptersError('Failed to reach backend: ' + err.message)
    } finally {
      setAdaptersLoading(false)
    }
  }

  const handleSaveMacLog = () => {
    if (!newMacInput.trim()) return
    setMacLog([...macLog, { value: newMacInput, time: new Date().toLocaleTimeString() }])
    setNewMacInput('')
  }

  const handleRunSecurityScan = async () => {
    setAnalysisLoading(true)
    setAnalysisError(null)
    setAnalysisResults(null)

    try {
      const response = await axios.get(
        `http://127.0.0.1:8000/security-analysis?target=${analysisTarget}`
      )
      if (response.data.error) {
        setAnalysisError(response.data.error)
      } else {
        setAnalysisResults(response.data)
      }
    } catch (err) {
      setAnalysisError('Failed to reach backend: ' + err.message)
    } finally {
      setAnalysisLoading(false)
    }
  }

  const riskBadgeClasses = {
    HIGH: 'risk-badge risk-high',
    MEDIUM: 'risk-badge risk-medium',
    LOW: 'risk-badge risk-low',
    INFO: 'risk-badge risk-info',
  }

  return (
    <>
      <header className="topbar">
        <div className="topbar-brand">
          <span className="shield-icon">🛡️</span> NetShield AI
        </div>
        <div className="topbar-status">
          <span className="status-dot"></span> System Active
        </div>
      </header>

      <div className="app-container">
        <div className="card">
          <div className="card-header">
            <div className="card-icon-badge">🛰️</div>
            <h2 className="card-heading">Scan Network</h2>
          </div>

          <button className="btn" onClick={handleScan} disabled={loading}>
            {loading && <span className="spinner" />}
            Scan Network
          </button>

          {loading && <p className="status-loading">Scanning network...</p>}
          {error && <p className="status-error">Error: {error}</p>}

          {devices && (
            <table className="table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Hostname</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((device) => (
                  <tr key={device.ip}>
                    <td className="mono">{device.ip}</td>
                    <td>{device.hostname}</td>
                    <td>{device.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-icon-badge">🔍</div>
            <h2 className="card-heading">Packet Analyzer</h2>
          </div>

          <button className="btn" onClick={handleCapture} disabled={packetsLoading}>
            {packetsLoading && <span className="radar-spinner" />}
            Capture Live Traffic (15s)
          </button>

          {packetsLoading && <p className="status-loading">Capturing traffic for 15 seconds...</p>}
          {packetsError && <p className="status-error">Error: {packetsError}</p>}

          {packets && (
            <>
              <p className="summary-line">
                {packets.length} packets captured —{' '}
                {packets.filter((p) => p.protocol === 'TCP').length} TCP,{' '}
                {packets.filter((p) => p.protocol === 'UDP').length} UDP,{' '}
                {packets.filter((p) => p.protocol !== 'TCP' && p.protocol !== 'UDP').length} other
              </p>
              <table className="table">
                <thead>
                  <tr>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Protocol</th>
                    <th>Length (bytes)</th>
                  </tr>
                </thead>
                <tbody>
                  {packets.slice(0, 50).map((packet, index) => (
                    <tr key={index}>
                      <td className="mono">{packet.source_ip}</td>
                      <td className="mono">{packet.destination_ip}</td>
                      <td>{packet.protocol}</td>
                      <td>{packet.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-icon-badge">🔒</div>
            <h2 className="card-heading">Privacy Lab (MAC Address Spoofing)</h2>
          </div>

          <button className="btn" onClick={handleShowAdapters} disabled={adaptersLoading}>
            {adaptersLoading && <span className="spinner" />}
            Show Current MAC Addresses
          </button>

          {adaptersLoading && <p className="status-loading">Loading adapters...</p>}
          {adaptersError && <p className="status-error">Error: {adaptersError}</p>}

          {adapters && (
            <>
              <table className="table">
                <thead>
                  <tr>
                    <th>Adapter Name</th>
                    <th>MAC Address</th>
                  </tr>
                </thead>
                <tbody>
                  {adapters.map((adapter, index) => (
                    <tr key={index}>
                      <td>{adapter.name}</td>
                      <td className="mono">{adapter.mac_address}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <pre className="instructions-block">
{`Manual Steps Using SMAC:
1. Open the SMAC application.
2. Select your Wi-Fi network adapter from the list.
3. Enter a new MAC address in SMAC's 'New Spoofed MAC Address' field (use a random value in the format XX:XX:XX:XX:XX:XX).
4. Click 'Update MAC' in SMAC, then restart the adapter when prompted.
5. Come back here and click 'Show Current MAC Addresses' again to verify the change.
6. When finished testing, use SMAC's 'Remove MAC' button to restore your original address, then verify again here.`}
              </pre>
            </>
          )}

          <div className="field-row">
            <label className="field-label">
              Log the new MAC you set (optional):
              <input
                className="input"
                type="text"
                value={newMacInput}
                onChange={(e) => setNewMacInput(e.target.value)}
              />
            </label>
            <button className="btn" onClick={handleSaveMacLog}>Save to Log</button>
          </div>

          {macLog.length > 0 && (
            <ul className="log-list">
              {macLog.map((entry, index) => (
                <li key={index}>
                  [{entry.time}] {entry.value}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-icon-badge">⚠️</div>
            <h2 className="card-heading">Security Analysis</h2>
          </div>

          <div className="field-row">
            <label className="field-label">
              Target IP:
              <input
                className="input"
                type="text"
                value={analysisTarget}
                onChange={(e) => setAnalysisTarget(e.target.value)}
              />
            </label>
            <button className="btn" onClick={handleRunSecurityScan} disabled={analysisLoading}>
              {analysisLoading && <span className="radar-spinner" />}
              Run Security Scan
            </button>
          </div>

          {analysisLoading && <p className="status-loading">Scanning for vulnerabilities...</p>}
          {analysisError && <p className="status-error">Error: {analysisError}</p>}

          {analysisResults && (
            <>
              <p className="summary-line">
                Found {analysisResults.findings.length} issues —{' '}
                {analysisResults.summary.high} High,{' '}
                {analysisResults.summary.medium} Medium,{' '}
                {analysisResults.summary.low} Low risk
              </p>
              <table className="table">
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Risk Level</th>
                    <th>Recommendation</th>
                  </tr>
                </thead>
                <tbody>
                  {analysisResults.findings.map((finding, index) => (
                    <tr key={index}>
                      <td className="mono">{finding.port}</td>
                      <td>{finding.service}</td>
                      <td>
                        <span className={riskBadgeClasses[finding.risk] || 'risk-badge'}>
                          {finding.risk}
                        </span>
                      </td>
                      <td>{finding.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      </div>
    </>
  )
}

export default App
