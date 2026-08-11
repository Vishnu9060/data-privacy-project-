function protoClass(protocol) {
  const known = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'HTTPS/TLS', 'QUIC']
  return known.includes(protocol) ? `feed-proto-${protocol}` : 'feed-proto-default'
}

const ACTIVITY_ICONS = {
  Browsing: '🌐',
  Downloading: '⬇️',
  'DNS Lookup': '🔎',
  Ping: '📶',
  Other: '•',
}

// Fixed set of protocol tiles shown in Live Statistics, in this order,
// regardless of which ones actually appeared in the capture (0 is still
// informative — e.g. "0 ICMP" tells you nobody pinged anything).
const STAT_PROTOCOLS = [
  { key: 'TCP', label: 'TCP' },
  { key: 'UDP', label: 'UDP' },
  { key: 'DNS', label: 'DNS' },
  { key: 'HTTPS/TLS', label: 'TLS' },
  { key: 'ICMP', label: 'ICMP' },
  { key: 'HTTP', label: 'HTTP' },
  { key: 'QUIC', label: 'QUIC' },
]

function formatTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts * 1000)
  return d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0')
}

function toCsv(packets) {
  const header = ['#', 'Time', 'Source IP', 'Src Port', 'Destination IP', 'Dst Port', 'Protocol', 'Length', 'Info']
  const rows = packets.map((p, i) => [
    i + 1,
    formatTime(p.timestamp),
    p.src_ip, p.src_port ?? '',
    p.dst_ip, p.dst_port ?? '',
    p.protocol, p.length,
    (p.info || '').replace(/"/g, '""'),
  ])
  const lines = [header, ...rows].map((r) => r.map((v) => `"${v}"`).join(','))
  return lines.join('\n')
}

function downloadFile(filename, content, mime) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export default function PacketSnifferPage({ net }) {
  const {
    packets, packetSummary, packetsLoading, packetsError,
    protocolFilter, setProtocolFilter,
    selectedDeviceIp, setSelectedDeviceIp,
    handleCapture,
  } = net

  const visiblePackets = (packets || []).filter((p) => {
    if (protocolFilter !== 'ALL' && p.protocol !== protocolFilter) return false
    if (selectedDeviceIp && p.src_ip !== selectedDeviceIp && p.dst_ip !== selectedDeviceIp) return false
    return true
  })

  const selectedDevice =
    selectedDeviceIp && packetSummary
      ? packetSummary.devices.find((d) => d.ip === selectedDeviceIp)
      : null

  const otherCount = packetSummary
    ? Object.entries(packetSummary.protocol_counts)
        .filter(([proto]) => !STAT_PROTOCOLS.some((s) => s.key === proto))
        .reduce((sum, [, c]) => sum + c, 0)
    : 0

  const exportJson = () => {
    if (!packets) return
    downloadFile('packet_capture.json', JSON.stringify({ packets, summary: packetSummary }, null, 2), 'application/json')
  }
  const exportCsv = () => {
    if (!packets) return
    downloadFile('packet_capture.csv', toCsv(packets), 'text/csv')
  }

  return (
    <>
      <div className="page-header packet-header">
        <div>
          <h1 className="page-title">Packet Sniffer &amp; Analysis</h1>
          <p className="page-subtitle">
            Live capture via Scapy — TCP 3-way handshake, DNS, HTTPS/TLS, ICMP, QUIC. Source/destination IP + MAC,
            protocol, packet length, and per-device activity.
          </p>
        </div>
        <div className="packet-export-btns">
          <button className="btn btn-ghost" onClick={exportJson} disabled={!packets}>⬇ JSON</button>
          <button className="btn btn-ghost" onClick={exportCsv} disabled={!packets}>⬇ CSV</button>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Live Capture</span>
        </div>

        <div className="field-row">
          <button className="btn" onClick={handleCapture} disabled={packetsLoading}>
            {packetsLoading && <span className="radar-spinner" />}
            ▶ Start Capture (15s)
          </button>
          {packetsLoading && <span className="status-pill-inline">● Capturing</span>}
        </div>

        {packetsLoading && <p className="status-loading">Capturing traffic for 15 seconds...</p>}
        {packetsError && <p className="status-error">Error: {packetsError}</p>}

        {!packets && !packetsLoading && !packetsError && (
          <p className="empty-hint">No capture yet — click "Start Capture" to sniff 15 seconds of packets.</p>
        )}
      </div>

      {packetSummary && (
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Live Statistics</span>
            <span className="panel-tag">{packetSummary.total_packets} Packets</span>
          </div>

          <div className="proto-stat-grid">
            {STAT_PROTOCOLS.map((s) => (
              <div className="proto-stat-tile" key={s.key}>
                <span className={`proto-stat-badge ${protoClass(s.key)}`}>{s.label}</span>
                <div className="proto-stat-num">{packetSummary.protocol_counts[s.key] || 0}</div>
              </div>
            ))}
            <div className="proto-stat-tile">
              <span className="proto-stat-badge feed-proto-default">OTHER</span>
              <div className="proto-stat-num">{otherCount}</div>
            </div>
          </div>

          <p className="summary-line">
            {packetSummary.total_packets} packets captured — {packetSummary.lan_packets} on your LAN,{' '}
            {packetSummary.total_packets - packetSummary.lan_packets} internet-bound — {packetSummary.total_bytes} bytes total
          </p>
          {packetSummary.dns_queries.length > 0 && (
            <p className="dns-line"><strong>DNS queries:</strong> {packetSummary.dns_queries.join(', ')}</p>
          )}
        </div>
      )}

      {packetSummary && packetSummary.port_scan_alerts && packetSummary.port_scan_alerts.length > 0 && (
        <div className="panel rogue-panel">
          <div className="panel-header">
            <span className="panel-title">⚠ Possible Port Scan Detected</span>
            <span className="panel-tag">{packetSummary.port_scan_alerts.length} source{packetSummary.port_scan_alerts.length === 1 ? '' : 's'} flagged</span>
          </div>
          <p className="empty-hint" style={{ marginBottom: '14px' }}>
            These sources contacted an unusually high number of distinct destination ports within this capture window
            (15+) — the classic signature of an nmap-style port scan. Verify this matches expected activity
            (e.g. your own Port Scanner tool) before treating it as an intrusion.
          </p>
          <div className="rogue-alert-list">
            {packetSummary.port_scan_alerts.map((a) => (
              <div className="rogue-alert-card" key={a.source}>
                <div className="rogue-alert-head">
                  <span className="risk-badge risk-high">HIGH</span>
                  <span className="rogue-alert-ssid mono">{a.source}</span>
                  <span className="panel-tag">{a.distinct_ports} distinct ports</span>
                </div>
                <div className="rogue-alert-bssids mono">{a.sample_ports.join(', ')}{a.distinct_ports > a.sample_ports.length ? ', …' : ''}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {packetSummary && packetSummary.devices.length > 0 && (
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Devices Seen ({packetSummary.devices.length})</span>
            {selectedDeviceIp && (
              <button className="chip-btn" onClick={() => setSelectedDeviceIp(null)}>Clear selection ✕</button>
            )}
          </div>

          <div className="device-grid">
            {packetSummary.devices.map((d) => (
              <button
                key={d.ip}
                className={selectedDeviceIp === d.ip ? 'device-card device-card-active' : 'device-card'}
                onClick={() => setSelectedDeviceIp(selectedDeviceIp === d.ip ? null : d.ip)}
              >
                <div className="device-ip mono">{d.ip}</div>
                <div className="device-mac mono">{d.mac || 'MAC unknown'}</div>
                <div className="device-activity">
                  {Object.entries(d.activity).map(([act, count]) => (
                    <span key={act} className="activity-chip">
                      {ACTIVITY_ICONS[act] || '•'} {act}: {count}
                    </span>
                  ))}
                </div>
              </button>
            ))}
          </div>

          {selectedDevice && (
            <p className="status-note">
              ℹ Showing only packets involving <strong>{selectedDevice.ip}</strong> ({selectedDevice.mac || 'MAC unknown'}) below.
            </p>
          )}
        </div>
      )}

      {packets && packets.length > 0 && (
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Live Packets</span>
            <span className="panel-tag">{visiblePackets.length} of {packets.length} shown</span>
          </div>

          <div className="protocol-filter-row">
            {['ALL', ...new Set(packets.map((p) => p.protocol))].map((proto) => (
              <button
                key={proto}
                className={protocolFilter === proto ? 'chip-btn chip-btn-active' : 'chip-btn'}
                onClick={() => setProtocolFilter(proto)}
              >
                {proto}
              </button>
            ))}
          </div>

          <div className="table-scroll">
            <table className="table table-wide packet-live-table">
              <thead>
                <tr>
                  <th style={{ width: '4%' }}>#</th>
                  <th style={{ width: '9%' }}>Time</th>
                  <th style={{ width: '12%' }}>Source IP</th>
                  <th style={{ width: '6%' }}>Src Port</th>
                  <th style={{ width: '12%' }}>Destination IP</th>
                  <th style={{ width: '6%' }}>Dst Port</th>
                  <th style={{ width: '8%' }}>Protocol</th>
                  <th style={{ width: '6%' }}>Length</th>
                  <th style={{ width: '8%' }}>Handshake</th>
                  <th>Info</th>
                </tr>
              </thead>
              <tbody>
                {visiblePackets.slice(0, 200).map((packet, index) => (
                  <tr key={index}>
                    <td className="mono">{index + 1}</td>
                    <td className="mono">{formatTime(packet.timestamp)}</td>
                    <td className="mono">{packet.src_ip}</td>
                    <td className="mono">{packet.src_port ?? '—'}</td>
                    <td className="mono">{packet.dst_ip}</td>
                    <td className="mono">{packet.dst_port ?? '—'}</td>
                    <td><span className={protoClass(packet.protocol)}>{packet.protocol}</span></td>
                    <td>{packet.length}</td>
                    <td>
                      {packet.handshake_step ? (
                        <span className="risk-badge risk-info">{packet.handshake_step}</span>
                      ) : '—'}
                    </td>
                    <td className="info-cell">{packet.info}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {packets && packets.length === 0 && (
        <div className="panel">
          <p className="status-loading">No packets captured in this window. Try generating traffic (browse a site, run a ping) and capture again.</p>
        </div>
      )}

      {packetSummary && (
        <div className="page-grid">
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">TCP Handshakes</span>
              <span className="panel-tag">{packetSummary.tcp_handshakes.length}</span>
            </div>
            {packetSummary.tcp_handshakes.length === 0 ? (
              <p className="empty-hint">No TCP connection attempts captured in this window.</p>
            ) : (
              <div className="table-scroll">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Client</th>
                      <th>Server</th>
                      <th>Port</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {packetSummary.tcp_handshakes.map((h, i) => (
                      <tr key={i}>
                        <td className="mono">{h.client}</td>
                        <td className="mono">{h.server}</td>
                        <td className="mono">{h.port}</td>
                        <td>
                          <span className={h.status === 'COMPLETE' ? 'risk-badge risk-info' : 'risk-badge risk-medium'}>
                            {h.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">DNS Queries</span>
              <span className="panel-tag">{packetSummary.dns_query_log.length}</span>
            </div>
            {packetSummary.dns_query_log.length === 0 ? (
              <p className="empty-hint">No DNS lookups captured in this window.</p>
            ) : (
              <div className="table-scroll">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Domain</th>
                      <th>Type</th>
                      <th>Source</th>
                      <th>DNS Server</th>
                    </tr>
                  </thead>
                  <tbody>
                    {packetSummary.dns_query_log.map((q, i) => (
                      <tr key={i}>
                        <td className="mono">{formatTime(q.time)}</td>
                        <td className="mono">{q.domain}</td>
                        <td><span className="risk-badge risk-info">{q.type}</span></td>
                        <td className="mono">{q.source}</td>
                        <td className="mono">{q.dns_server}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {packetSummary && (
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">ICMP Statistics</span>
            <span className="panel-tag">{packetSummary.icmp_stats.echo_request + packetSummary.icmp_stats.echo_reply + packetSummary.icmp_stats.other}</span>
          </div>
          <div className="proto-stat-grid icmp-stat-grid">
            <div className="proto-stat-tile">
              <span className="proto-stat-badge feed-proto-ICMP">Echo Request (ping)</span>
              <div className="proto-stat-num">{packetSummary.icmp_stats.echo_request}</div>
            </div>
            <div className="proto-stat-tile">
              <span className="proto-stat-badge feed-proto-ICMP">Echo Reply</span>
              <div className="proto-stat-num">{packetSummary.icmp_stats.echo_reply}</div>
            </div>
            <div className="proto-stat-tile">
              <span className="proto-stat-badge feed-proto-default">Other ICMP</span>
              <div className="proto-stat-num">{packetSummary.icmp_stats.other}</div>
            </div>
          </div>
        </div>
      )}

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">TCP 3-Way Handshake Reference</span>
        </div>
        <div className="handshake-ref-row">
          <div className="handshake-ref-step">
            <span className="handshake-ref-badge">Step 1</span>
            <div className="handshake-ref-title">SYN Sent</div>
            <div className="handshake-ref-detail mono">Client → Server [SYN] Seq=0</div>
          </div>
          <span className="handshake-ref-arrow">→</span>
          <div className="handshake-ref-step">
            <span className="handshake-ref-badge">Step 2</span>
            <div className="handshake-ref-title">SYN-ACK Received</div>
            <div className="handshake-ref-detail mono">Server → Client [SYN, ACK] Seq=0 Ack=1</div>
          </div>
          <span className="handshake-ref-arrow">→</span>
          <div className="handshake-ref-step">
            <span className="handshake-ref-badge">Step 3</span>
            <div className="handshake-ref-title">ACK Sent</div>
            <div className="handshake-ref-detail mono">Client → Server [ACK] Seq=1 Ack=1 (Established)</div>
          </div>
        </div>
      </div>
    </>
  )
}
