const riskBadgeClasses = {
  HIGH: 'risk-badge risk-high',
  MEDIUM: 'risk-badge risk-medium',
  LOW: 'risk-badge risk-low',
  INFO: 'risk-badge risk-info',
}

const necessityBadgeClasses = {
  UNNECESSARY: 'risk-badge risk-high',
  REVIEW: 'risk-badge risk-medium',
  EXPECTED: 'risk-badge risk-info',
}

export default function PortScannerPage({ net }) {
  const {
    analysisTarget, setAnalysisTarget, analysisResults, analysisError,
    reportLoading, handleRunFullAssessment, devices, handleScan, loading,
  } = net

  // Build the selectable target list from hosts already discovered on the
  // Network Discovery page, plus localhost (always available to demo
  // against). Avoids free-typing an IP, which invites typos.
  const targetOptions = [
    { ip: '127.0.0.1', label: '127.0.0.1 (this machine, localhost)' },
    ...(devices || [])
      .filter((d) => d.ip !== '127.0.0.1')
      .map((d) => ({
        ip: d.ip,
        label: d.hostname && d.hostname !== 'unknown' ? `${d.ip} (${d.hostname})` : d.ip,
      })),
  ]

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Port Scanner</h1>
        <p className="page-subtitle">Scan a target's open ports, classify risk, and get firewall recommendations.</p>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Port &amp; Security Scan</span>
        </div>

        <div className="field-row">
          <label className="field-label">
            Target:
            <select
              className="input"
              value={analysisTarget}
              onChange={(e) => setAnalysisTarget(e.target.value)}
            >
              {targetOptions.map((opt) => (
                <option key={opt.ip} value={opt.ip}>{opt.label}</option>
              ))}
            </select>
          </label>
          <button className="btn" onClick={handleRunFullAssessment} disabled={reportLoading}>
            {reportLoading && <span className="radar-spinner" />}
            Run Analysis
          </button>
          <button className="btn btn-secondary" onClick={handleScan} disabled={loading}>
            {loading && <span className="spinner" />}
            Refresh Host List
          </button>
        </div>

        {(!devices || devices.length === 0) && (
          <p className="status-note">
            ℹ Only localhost is available yet — run "Refresh Host List" (or visit Network Discovery) to find
            other devices on your network to scan.
          </p>
        )}

        {reportLoading && <p className="status-loading">Scanning ports — this can take ~15-20s...</p>}
        {analysisError && <p className="status-error">Error: {analysisError}</p>}

        {!analysisResults && !reportLoading && !analysisError && (
          <p className="empty-hint">Enter a target IP and click "Run Analysis" to scan for open ports.</p>
        )}

        {analysisResults && (
          <>
            <div className="sec-hero">
              <div className={`sec-grade grade-${analysisResults.grade}`}>
                <span className="sec-grade-letter">{analysisResults.grade}</span>
                <span className="sec-grade-score">{analysisResults.score}/100</span>
                <span className="sec-grade-label">Security Grade</span>
              </div>
              <div className="sec-stats">
                <div className="sec-stat">
                  <span className="sec-stat-num">{analysisResults.metrics.open_ports}</span>
                  <span className="sec-stat-label">Open Ports</span>
                </div>
                <div className="sec-stat">
                  <span className="sec-stat-num sec-stat-warn">{analysisResults.metrics.insecure_protocols}</span>
                  <span className="sec-stat-label">Insecure Protocols</span>
                </div>
                <div className="sec-stat">
                  <span className="sec-stat-num sec-stat-warn">{analysisResults.metrics.unnecessary_ports}</span>
                  <span className="sec-stat-label">Unnecessary Ports</span>
                </div>
                <div className="sec-stat">
                  <span className="sec-stat-num sec-stat-danger">{analysisResults.metrics.high}</span>
                  <span className="sec-stat-label">High Risk</span>
                </div>
              </div>
            </div>

            <h3 className="report-subheading">
              Findings for {analysisResults.target}
              {' '}
              <span className="source-badge">
                {analysisResults.recommendation_source === 'groq' ? '✦ AI-generated advice' : 'Built-in analyzer'}
              </span>
            </h3>
            {analysisResults.findings.length === 0 ? (
              <p className="status-success">No open ports found — nothing exposed to the network. Excellent.</p>
            ) : (
              <div className="findings-list">
                {analysisResults.findings.map((finding, index) => (
                  <div className="finding-card" key={index}>
                    <div className="finding-head">
                      <span className="finding-port mono">:{finding.port}</span>
                      <span className="finding-service">
                        {finding.service}
                        {finding.insecure_protocol && <span className="tag-insecure"> plaintext</span>}
                      </span>
                      <span className={riskBadgeClasses[finding.risk] || 'risk-badge'}>{finding.risk}</span>
                      <span className={necessityBadgeClasses[finding.necessity] || 'risk-badge'}>{finding.necessity}</span>
                    </div>
                    <p className="finding-reason">{finding.reason}</p>
                    <p className="finding-rec">✔ {finding.recommendation}</p>
                    {finding.cve_hint && <p className="cve-hint">⚠ {finding.cve_hint}</p>}
                    {finding.firewall_rules && (
                      <details className="fw-details">
                        <summary>Firewall rule ({finding.firewall_rules.action})</summary>
                        <p className="fw-explain">{finding.firewall_rules.explanation}</p>
                        {finding.firewall_rules.ai_command && (
                          <>
                            <pre className="fw-cmd fw-cmd-ai">{finding.firewall_rules.ai_command}</pre>
                            <p className="fw-alt">Verified reference commands:</p>
                          </>
                        )}
                        <pre className="fw-cmd">{finding.firewall_rules[finding.firewall_rules.primary]}</pre>
                        <p className="fw-alt">Other formats:</p>
                        <pre className="fw-cmd">{finding.firewall_rules.iptables}</pre>
                        {finding.firewall_rules.primary !== 'netsh' && (
                          <pre className="fw-cmd">{finding.firewall_rules.netsh}</pre>
                        )}
                      </details>
                    )}
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </>
  )
}
