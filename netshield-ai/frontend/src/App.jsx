import { useState } from 'react'
import axios from 'axios'

function App() {
  const [devices, setDevices] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const [packets, setPackets] = useState(null)
  const [packetsLoading, setPacketsLoading] = useState(false)
  const [packetsError, setPacketsError] = useState(null)

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

  return (
    <div>
      <h1>NetShield AI</h1>
      <button onClick={handleScan} disabled={loading}>
        Scan Network
      </button>

      {loading && <p>Scanning network...</p>}
      {error && <p>Error: {error}</p>}

      {devices && (
        <table border="1" cellPadding="8">
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
                <td>{device.ip}</td>
                <td>{device.hostname}</td>
                <td>{device.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h1>Packet Analyzer</h1>
      <button onClick={handleCapture} disabled={packetsLoading}>
        Capture Live Traffic (15s)
      </button>

      {packetsLoading && <p>Capturing traffic for 15 seconds...</p>}
      {packetsError && <p>Error: {packetsError}</p>}

      {packets && (
        <>
          <p>
            {packets.length} packets captured —{' '}
            {packets.filter((p) => p.protocol === 'TCP').length} TCP,{' '}
            {packets.filter((p) => p.protocol === 'UDP').length} UDP,{' '}
            {packets.filter((p) => p.protocol !== 'TCP' && p.protocol !== 'UDP').length} other
          </p>
          <table border="1" cellPadding="8">
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
                  <td>{packet.source_ip}</td>
                  <td>{packet.destination_ip}</td>
                  <td>{packet.protocol}</td>
                  <td>{packet.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}

export default App
