import { Fragment } from 'react'
import NetworkTopology from './NetworkTopology'

// nmap sometimes can't pull a version banner even from an open port — the
// service itself may refuse to reveal it before authentication (common for
// databases like MySQL), or the port may just run something nmap has no
// fingerprint script for. Explain that inline so it reads as expected
// behavior during a demo, not a broken scan.
function formatVersion(version, extrainfo) {
  const note = extrainfo && /unauthorized|filtered/i.test(extrainfo)
    ? 'service declined to share its version (requires authentication)'
    : version === 'unknown'
      ? 'no version fingerprint available for this service'
      : null

  return (
    <span>
      {version}
      {extrainfo ? ` (${extrainfo})` : ''}
      {note && <span className="version-note"> — {note}</span>}
    </span>
  )
}

function HostDetails({ scan }) {
  if (!scan) return null

  if (scan.loading) {
    return <p className="status-loading">Scanning host — OS detection, ports, and services (~10-30s)...</p>
  }
  if (scan.error) {
    return <p className="status-error">Error: {scan.error}</p>
  }
  const data = scan.data
  if (!data) return null

  // Defensive fallbacks: the backend should always send these arrays, but
  // never let a missing/renamed field crash the whole page — show a plain
  // "unavailable" message instead of a blank screen.
  const osMatches = data.os_matches || []
  const openPorts = data.open_ports || []

  return (
    <div className="host-detail">
      <div className="host-detail-section">
        <div className="host-detail-label">Operating System</div>
        {osMatches.length === 0 ? (
          <p className="empty-hint">Could not determine OS (host may block the probes nmap uses, or too few open ports to fingerprint).</p>
        ) : (
          <p className="os-primary">
            {osMatches[0].name} <span className="os-accuracy">({osMatches[0].accuracy}% confidence)</span>
          </p>
        )}
      </div>

      <div className="host-detail-section">
        <div className="host-detail-label">Open Ports &amp; Services ({openPorts.length})</div>
        {openPorts.length === 0 ? (
          <p className="status-success">No open TCP ports found in the scanned range.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Product</th>
                <th>Version</th>
              </tr>
            </thead>
            <tbody>
              {openPorts.map((p, i) => (
                <tr key={i}>
                  <td className="mono">{p.port}</td>
                  <td>{p.service}</td>
                  <td>{p.product || '—'}</td>
                  <td>{formatVersion(p.version, p.extrainfo)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

export default function NetworkDiscoveryPage({ net }) {
  const { devices, scanNote, loading, error, handleScan, hostScans, handleHostScan } = net

  const handleSelectHost = (ip) => {
    handleHostScan(ip)
    const row = document.getElementById(`host-row-${ip}`)
    if (row) {
      row.scrollIntoView({ behavior: 'smooth', block: 'center' })
      row.classList.add('host-row-flash')
      setTimeout(() => row.classList.remove('host-row-flash'), 1200)
    }
  }

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Network Discovery</h1>
        <p className="page-subtitle">
          Ping-sweep the local subnet to find active hosts, then scan any host for its OS, open TCP ports,
          and running services with versions.
        </p>
      </div>

      {devices && devices.length > 0 && (
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Network Map</span>
          </div>
          <NetworkTopology devices={devices} onSelectHost={handleSelectHost} />
        </div>
      )}

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Active Hosts</span>
          <button className="btn" onClick={handleScan} disabled={loading}>
            {loading && <span className="spinner" />}
            Scan Network
          </button>
        </div>

        {loading && <p className="status-loading">Scanning network...</p>}
        {error && <p className="status-error">Error: {error}</p>}
        {scanNote && <p className="status-note">ℹ {scanNote}</p>}

        {!devices && !loading && !error && (
          <p className="empty-hint">No scan run yet — click "Scan Network" to discover devices on your subnet.</p>
        )}

        {devices && (
          <table className="table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => {
                const scan = hostScans[device.ip]
                return (
                  <Fragment key={device.ip}>
                    <tr id={`host-row-${device.ip}`}>
                      <td className="mono">{device.ip}</td>
                      <td>{device.hostname}</td>
                      <td>
                        <span className={device.status === 'up' ? 'risk-badge risk-info' : 'risk-badge risk-low'}>
                          {device.status}
                        </span>
                      </td>
                      <td>
                        <button
                          className="chip-btn"
                          onClick={() => handleHostScan(device.ip)}
                          disabled={scan && scan.loading}
                        >
                          {scan && scan.loading ? 'Scanning…' : scan && scan.data ? 'Re-scan' : 'Scan Host'}
                        </button>
                      </td>
                    </tr>
                    {scan && (
                      <tr>
                        <td colSpan={4} className="host-detail-cell">
                          <HostDetails scan={scan} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
