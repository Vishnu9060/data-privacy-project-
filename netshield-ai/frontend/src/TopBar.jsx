export default function TopBar({ gateway, activeNodes, isScanning }) {
  return (
    <header className="topbar">
      <div className="topbar-stat">
        <span className="topbar-stat-label">Gateway</span>
        <span className="topbar-stat-value">{gateway || '—'}</span>
      </div>
      <div className="topbar-divider" />
      <div className="topbar-stat">
        <span className="topbar-stat-label">Active Nodes</span>
        <span className="topbar-stat-value">{activeNodes} Devices</span>
      </div>

      <div className="topbar-spacer" />

      <span className="status-pill">
        <span className="status-pill-dot" />
        {isScanning ? 'Scanning Active' : 'System Ready'}
      </span>
      <div className="avatar-dot" />
    </header>
  )
}
