function protoClass(protocol) {
  const known = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'HTTPS/TLS']
  return known.includes(protocol) ? `feed-proto-${protocol}` : 'feed-proto-default'
}

const ACTIVITY_ICONS = {
  Browsing: '🌐',
  Downloading: '⬇️',
  'DNS Lookup': '🔎',
  Ping: '📶',
  Other: '•',
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

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Packet Sniffer</h1>
        <p className="page-subtitle">
          Capture and classify live traffic with Wireshark-grade dissection — source/destination IP + MAC,
          protocol, length, TCP handshakes, and DNS lookups.
        </p>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Live Capture</span>
        </div>

        <div className="field-row">
          <button className="btn" onClick={handleCapture} disabled={packetsLoading}>
            {packetsLoading && <span className="radar-spinner" />}
            Capture Live Traffic (15s)
          </button>
        </div>

        {packetsLoading && <p className="status-loading">Capturing traffic for 15 seconds...</p>}
        {packetsError && <p className="status-error">Error: {packetsError}</p>}

        {packetSummary && (
          <div className="capture-summary">
            <p className="summary-line">
              {packetSummary.total_packets} packets captured — {packetSummary.lan_packets} on your LAN,{' '}
              {packetSummary.total_packets - packetSummary.lan_packets} internet-bound — {packetSummary.total_bytes} bytes total
            </p>
            <div className="protocol-chips">
              {Object.entries(packetSummary.protocol_counts).map(([proto, count]) => (
                <span key={proto} className="protocol-chip">{proto}: {count}</span>
              ))}
            </div>
            {packetSummary.dns_queries.length > 0 && (
              <p className="dns-line"><strong>DNS queries:</strong> {packetSummary.dns_queries.join(', ')}</p>
            )}
          </div>
        )}

        {!packets && !packetsLoading && !packetsError && (
          <p className="empty-hint">No capture yet — click "Capture Live Traffic" to sniff 15 seconds of packets.</p>
        )}
      </div>

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
            <span className="panel-title">Packet Table ({visiblePackets.length})</span>
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
            <table className="table">
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Source MAC</th>
                  <th>Destination IP</th>
                  <th>Destination MAC</th>
                  <th>Protocol</th>
                  <th>Length</th>
                  <th>TCP Handshake</th>
                  <th>Activity</th>
                  <th>Info</th>
                </tr>
              </thead>
              <tbody>
                {visiblePackets.slice(0, 200).map((packet, index) => (
                  <tr key={index}>
                    <td className="mono">{packet.src_ip}</td>
                    <td className="mono mac-cell">{packet.src_mac || '—'}</td>
                    <td className="mono">{packet.dst_ip}</td>
                    <td className="mono mac-cell">{packet.dst_mac || '—'}</td>
                    <td><span className={protoClass(packet.protocol)}>{packet.protocol}</span></td>
                    <td>{packet.length}</td>
                    <td>
                      {packet.handshake_step ? (
                        <span className="risk-badge risk-info">{packet.handshake_step}</span>
                      ) : '—'}
                    </td>
                    <td>{ACTIVITY_ICONS[packet.activity] || '•'} {packet.activity}</td>
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
    </>
  )
}
