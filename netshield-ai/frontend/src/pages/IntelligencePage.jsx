export default function IntelligencePage({ net }) {
  const {
    analysisResults, packetSummary, macChangeResult,
    reportData, reportLoading, reportError, handleRunFullAssessment, handleDownloadPdf,
  } = net

  const findings = analysisResults ? analysisResults.findings : []
  const highRisk = findings.filter((f) => f.risk === 'HIGH')
  const withCve = findings.filter((f) => f.cve_hint)
  const insecure = findings.filter((f) => f.insecure_protocol)

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Threat Analysis &amp; AI Reports</h1>
        <p className="page-subtitle">
          Run a full assessment to surface threat intelligence and generate a plain-English advisory report.
        </p>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Run Assessment</span>
        </div>

        <p className="report-description">
          Runs a full assessment (network scan, adapter check, port/security scan), surfaces threat intel below,
          and produces an AI advisory report with recommendations and firewall rules.
        </p>

        <div className="field-row">
          <button className="btn" onClick={handleRunFullAssessment} disabled={reportLoading}>
            {reportLoading && <span className="radar-spinner" />}
            Run Full Assessment
          </button>
          {reportData && (
            <button className="btn btn-secondary" onClick={handleDownloadPdf}>
              ⬇ Download PDF
            </button>
          )}
        </div>

        {reportLoading && <p className="status-loading">Running assessment — this can take ~20s...</p>}
        {reportError && <p className="status-error">Error: {reportError}</p>}

        {!analysisResults && !reportLoading && !reportError && (
          <p className="empty-hint">No scan data yet — click "Run Full Assessment" to populate threat intel and the report.</p>
        )}
      </div>

      {analysisResults && (
        <div className="page-grid">
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Vulnerability Detections</span>
              <span className="panel-tag">{analysisResults.target}</span>
            </div>

            {highRisk.length === 0 && withCve.length === 0 ? (
              <p className="status-success">No high-risk vulnerabilities detected on this target.</p>
            ) : (
              <>
                {withCve.map((f, i) => (
                  <div className="intel-card tone-danger" key={`cve-${i}`}>
                    <div className="intel-card-label">⚠ Known Exploit Pattern</div>
                    <div className="intel-card-body">
                      Port {f.port} ({f.service}): {f.cve_hint}
                    </div>
                  </div>
                ))}
                {highRisk.filter((f) => !f.cve_hint).map((f, i) => (
                  <div className="intel-card tone-danger" key={`hi-${i}`}>
                    <div className="intel-card-label">Vulnerability Detected</div>
                    <div className="intel-card-body">
                      Port {f.port} ({f.service}): {f.reason}
                    </div>
                  </div>
                ))}
              </>
            )}

            {insecure.length > 0 && (
              <div className="intel-card tone-warn">
                <div className="intel-card-label">Insecure Protocols</div>
                <div className="intel-card-body">
                  {insecure.length} service{insecure.length > 1 ? 's' : ''} transmitting data in plaintext:{' '}
                  {insecure.map((f) => `${f.service} (:${f.port})`).join(', ')}.
                </div>
              </div>
            )}

            {packetSummary && (
              <div className="intel-card tone-info">
                <div className="intel-card-label">Traffic Analysis</div>
                <div className="intel-card-body">
                  Last capture: {packetSummary.total_packets} packets,{' '}
                  {Object.entries(packetSummary.protocol_counts).map(([p, c]) => `${c} ${p}`).join(', ')}.
                  {' '}
                  {(packetSummary.protocol_counts['HTTPS'] || 0) + (packetSummary.protocol_counts['HTTPS/TLS'] || 0) > 0
                    ? ' Encryption patterns match standard TLS.'
                    : ' No encrypted traffic observed in this capture.'}
                </div>
              </div>
            )}

            {macChangeResult && (
              <div className="intel-card tone-ok">
                <div className="intel-card-label">Privacy Status</div>
                <div className="intel-card-body">
                  MAC address {macChangeResult.success ? 'successfully randomized' : 'change attempted'} on{' '}
                  {macChangeResult.interface} ({macChangeResult.after_mac}).
                </div>
              </div>
            )}
          </div>

          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Risk Overview</span>
            </div>
            <div className="stat-tile-row">
              <div className="stat-tile">
                <div className="stat-tile-num">{analysisResults.grade}</div>
                <div className="stat-tile-label">Grade</div>
              </div>
              <div className="stat-tile">
                <div className="stat-tile-num">{analysisResults.score}</div>
                <div className="stat-tile-label">Score /100</div>
              </div>
              <div className="stat-tile">
                <div className="stat-tile-num tone-danger">{highRisk.length}</div>
                <div className="stat-tile-label">High Risk</div>
              </div>
              <div className="stat-tile">
                <div className="stat-tile-num tone-warn">{insecure.length}</div>
                <div className="stat-tile-label">Insecure</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {reportData && (
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">AI Advisory Report</span>
          </div>

          <div className="advisory">
            <div className="advisory-header">
              <h3 className="advisory-title">Security &amp; Privacy Advisory Report</h3>
              <p className="advisory-crumb">
                <span className="crumb-target">{analysisResults ? analysisResults.target : 'Assessment'}</span>
                {analysisResults && (
                  <>
                    <span className="crumb-dot">•</span>
                    <span className="crumb-grade">Grade {analysisResults.grade}</span>
                  </>
                )}
                <span className="crumb-dot">•</span>
                <span className="crumb-src">
                  Summary by {reportData.summary_source === 'groq' ? 'Groq AI' : 'built-in analyzer'}
                </span>
              </p>
            </div>

            <div className="advisory-body">
              <div className="advisory-section">
                <div className="advisory-label label-purple">📄 Executive Summary</div>
                <p>{reportData.summary.overall}</p>
              </div>

              {[
                ['network_discovery', 'Network Discovery', 'label-blue', '🛰️'],
                ['packet_analysis', 'Packet Analysis', 'label-green', '🔍'],
                ['privacy_lab', 'Privacy Lab', 'label-orange', '🔒'],
                ['security_analysis', 'Security Analysis', 'label-red', '⚠️'],
              ].map(([key, title, cls, icon]) => (
                <div className="advisory-section" key={key}>
                  <div className={`advisory-label ${cls}`}>{icon} {title}</div>
                  <p>{reportData.summary.sections[key]}</p>
                </div>
              ))}

              {analysisResults && analysisResults.findings.length > 0 && (
                <div className="advisory-section">
                  <div className="advisory-label label-purple">🎯 Action Recommendations</div>
                  <div className="advisory-actions">
                    {analysisResults.findings.map((f, i) => (
                      <div className="advisory-action" key={i}>
                        <span className="action-num">{i + 1}</span>
                        <span className="action-text">
                          <strong>Port {f.port} ({f.service}) — {f.risk}:</strong> {f.recommendation}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <p className="advisory-footer">Generated: {reportData.timestamp}</p>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
