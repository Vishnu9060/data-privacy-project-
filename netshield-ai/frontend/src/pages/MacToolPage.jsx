export default function MacToolPage({ net }) {
  const {
    adapters, adaptersLoading, adaptersError, handleShowAdapters,
    selectedInterface, setSelectedInterface,
    macChangeLoading, macChangeError, macChangeResult,
    macLog, handleRandomizeMac, handleRestoreMac,
  } = net

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">MAC Address Tool</h1>
        <p className="page-subtitle">View and randomize your network adapters' hardware addresses to defeat MAC-based tracking.</p>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Network Adapters</span>
          <button className="btn" onClick={handleShowAdapters} disabled={adaptersLoading}>
            {adaptersLoading && <span className="spinner" />}
            Show Current MAC Addresses
          </button>
        </div>

        {adaptersLoading && <p className="status-loading">Loading adapters...</p>}
        {adaptersError && <p className="status-error">Error: {adaptersError}</p>}

        {!adapters && !adaptersLoading && !adaptersError && (
          <p className="empty-hint">Click "Show Current MAC Addresses" to list your network interfaces.</p>
        )}

        {adapters && (
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
        )}

        {adapters && (
          <div className="field-row" style={{ marginTop: 16 }}>
            <label className="field-label">
              Adapter to spoof:
              <select className="input" value={selectedInterface} onChange={(e) => setSelectedInterface(e.target.value)}>
                {adapters.map((adapter) => (
                  <option key={adapter.name} value={adapter.name}>{adapter.name}</option>
                ))}
              </select>
            </label>
            <button className="btn" onClick={handleRandomizeMac} disabled={macChangeLoading || !selectedInterface}>
              {macChangeLoading && <span className="spinner" />}
              Randomize MAC
            </button>
            <button className="btn btn-secondary" onClick={handleRestoreMac} disabled={macChangeLoading || !selectedInterface}>
              Restore Original MAC
            </button>
          </div>
        )}

        {macChangeLoading && <p className="status-loading">Changing MAC address (interface will briefly go down)...</p>}
        {macChangeError && <p className="status-error">Error: {macChangeError}</p>}

        {macChangeResult && (
          <p className={macChangeResult.success ? 'status-success' : 'status-error'}>
            {macChangeResult.interface}: {macChangeResult.before_mac} → {macChangeResult.after_mac}{' '}
            {macChangeResult.success ? '(verified)' : "(adapter didn't report the new address — its driver likely doesn't support MAC spoofing)"}
          </p>
        )}

        {macLog.length > 0 && (
          <ul className="log-list">
            {macLog.map((entry, index) => (
              <li key={index}>
                [{entry.time}] {entry.action} {entry.interface}: {entry.before} → {entry.after}
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  )
}
