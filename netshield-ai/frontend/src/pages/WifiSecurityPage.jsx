import { RiskDonut, BandBars } from './WifiCharts'

const riskBadgeClasses = {
  HIGH: 'risk-badge risk-high',
  MEDIUM: 'risk-badge risk-medium',
  LOW: 'risk-badge risk-low',
  INFO: 'risk-badge risk-info',
}

export default function WifiSecurityPage({ net }) {
  const { wifiNetworks, wifiSummary, wifiRogueAlerts, wifiLoading, wifiError, handleWifiScan } = net

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Wi-Fi Security Scanner</h1>
        <p className="page-subtitle">
          Scans for nearby Wi-Fi access points and analyzes their encryption strength — network-level only.
          This never identifies or tracks the people/devices connected to any network.
        </p>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Nearby Access Points</span>
          <button className="btn" onClick={handleWifiScan} disabled={wifiLoading}>
            {wifiLoading && <span className="radar-spinner" />}
            Scan Wi-Fi
          </button>
        </div>

        {wifiLoading && <p className="status-loading">Scanning for nearby access points...</p>}
        {wifiError && <p className="status-error">Error: {wifiError}</p>}

        {!wifiNetworks && !wifiLoading && !wifiError && (
          <p className="empty-hint">No scan yet — click "Scan Wi-Fi" to survey nearby access points.</p>
        )}

        {wifiNetworks && wifiNetworks.length === 0 && (
          <p className="empty-hint">No Wi-Fi access points found nearby.</p>
        )}
      </div>

      {wifiRogueAlerts && wifiRogueAlerts.length > 0 && (
        <div className="panel rogue-panel">
          <div className="panel-header">
            <span className="panel-title">⚠ Possible Rogue / Evil-Twin Access Points</span>
            <span className="panel-tag">{wifiRogueAlerts.length} SSID{wifiRogueAlerts.length === 1 ? '' : 's'} flagged</span>
          </div>
          <p className="empty-hint" style={{ marginBottom: '14px' }}>
            These SSIDs are broadcast under conditions that don't match a normal single-deployment access point.
            This does not confirm an attack — verify against your known building network layout.
          </p>
          <div className="rogue-alert-list">
            {wifiRogueAlerts.map((a) => (
              <div className="rogue-alert-card" key={a.ssid}>
                <div className="rogue-alert-head">
                  <span className={a.severity === 'HIGH' ? 'risk-badge risk-high' : 'risk-badge risk-medium'}>
                    {a.severity}
                  </span>
                  <span className="rogue-alert-ssid">{a.ssid}</span>
                  <span className="panel-tag">{a.bssids.length} BSSIDs</span>
                </div>
                <ul className="rogue-alert-reasons">
                  {a.reasons.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
                <div className="rogue-alert-bssids mono">{a.bssids.join('  ·  ')}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {wifiSummary && wifiNetworks && wifiNetworks.length > 0 && (
        <>
          <div className="panel wifi-chart-panel">
            <div className="wifi-chart-row">
              <div className="wifi-chart-col">
                <div className="panel-header">
                  <span className="panel-title">Security Risk</span>
                </div>
                <RiskDonut riskCounts={wifiSummary.risk_counts} />
              </div>
              <div className="wifi-chart-col">
                <div className="panel-header">
                  <span className="panel-title">Band Split</span>
                </div>
                <BandBars bandCounts={wifiSummary.band_counts} />
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Access Points ({wifiSummary.total_networks})</span>
              <span className="panel-tag">{wifiSummary.unique_ssids} unique SSID{wifiSummary.unique_ssids === 1 ? '' : 's'}</span>
            </div>

            <div className="table-scroll">
              <table className="table wifi-table">
                <thead>
                  <tr>
                    <th>SSID</th>
                    <th>BSSID</th>
                    <th>Signal</th>
                    <th>Security</th>
                    <th>Risk</th>
                    <th>Band</th>
                    <th>Note</th>
                  </tr>
                </thead>
                <tbody>
                  {wifiNetworks.map((n, i) => (
                    <tr key={`${n.bssid}-${i}`}>
                      <td>{n.ssid}</td>
                      <td className="mono mac-cell">{n.bssid}</td>
                      <td>
                        <div className="signal-bar-track">
                          <div className="signal-bar-fill" style={{ width: `${n.signal || 0}%` }} />
                        </div>
                        <span className="signal-value">{n.signal ?? '—'}%</span>
                      </td>
                      <td>{n.security}</td>
                      <td><span className={riskBadgeClasses[n.risk] || 'risk-badge'}>{n.risk}</span></td>
                      <td>{n.band}</td>
                      <td className="info-cell">{n.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </>
  )
}
