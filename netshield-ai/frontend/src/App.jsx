import { useState } from 'react'
import axios from 'axios'

function App() {
  const [devices, setDevices] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

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
    </div>
  )
}

export default App
