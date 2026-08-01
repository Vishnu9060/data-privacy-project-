import { useState } from 'react'
import axios from 'axios'

function App() {
  const [devices, setDevices] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const [packets, setPackets] = useState(null)
  const [packetsLoading, setPacketsLoading] = useState(false)
  const [packetsError, setPacketsError] = useState(null)

  const [adapters, setAdapters] = useState(null)
  const [adaptersLoading, setAdaptersLoading] = useState(false)
  const [adaptersError, setAdaptersError] = useState(null)
  const [newMacInput, setNewMacInput] = useState('')
  const [macLog, setMacLog] = useState([])

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

  const handleShowAdapters = async () => {
    setAdaptersLoading(true)
    setAdaptersError(null)
    setAdapters(null)

    try {
      const response = await axios.get('http://127.0.0.1:8000/network-adapter-info')
      if (response.data.error) {
        setAdaptersError(response.data.error)
      } else {
        setAdapters(response.data.adapters)
      }
    } catch (err) {
      setAdaptersError('Failed to reach backend: ' + err.message)
    } finally {
      setAdaptersLoading(false)
    }
  }

  const handleSaveMacLog = () => {
    if (!newMacInput.trim()) return
    setMacLog([...macLog, { value: newMacInput, time: new Date().toLocaleTimeString() }])
    setNewMacInput('')
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

      <h1>Privacy Lab (MAC Address Spoofing)</h1>
      <button onClick={handleShowAdapters} disabled={adaptersLoading}>
        Show Current MAC Addresses
      </button>

      {adaptersLoading && <p>Loading adapters...</p>}
      {adaptersError && <p>Error: {adaptersError}</p>}

      {adapters && (
        <>
          <table border="1" cellPadding="8">
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
                  <td>{adapter.mac_address}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <pre>
{`Manual Steps Using SMAC:
1. Open the SMAC application.
2. Select your Wi-Fi network adapter from the list.
3. Enter a new MAC address in SMAC's 'New Spoofed MAC Address' field (use a random value in the format XX:XX:XX:XX:XX:XX).
4. Click 'Update MAC' in SMAC, then restart the adapter when prompted.
5. Come back here and click 'Show Current MAC Addresses' again to verify the change.
6. When finished testing, use SMAC's 'Remove MAC' button to restore your original address, then verify again here.`}
          </pre>
        </>
      )}

      <div>
        <label>
          Log the new MAC you set (optional):{' '}
          <input
            type="text"
            value={newMacInput}
            onChange={(e) => setNewMacInput(e.target.value)}
          />
        </label>
        <button onClick={handleSaveMacLog}>Save to Log</button>
      </div>

      {macLog.length > 0 && (
        <ul>
          {macLog.map((entry, index) => (
            <li key={index}>
              [{entry.time}] {entry.value}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default App
