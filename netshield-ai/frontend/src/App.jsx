import { useState } from 'react'
import './App.css'
import useNetShield from './useNetShield'
import Sidebar from './Sidebar'
import TopBar from './TopBar'
import ErrorBoundary from './ErrorBoundary'
import NetworkDiscoveryPage from './pages/NetworkDiscoveryPage'
import PacketSnifferPage from './pages/PacketSnifferPage'
import MacToolPage from './pages/MacToolPage'
import PortScannerPage from './pages/PortScannerPage'
import IntelligencePage from './pages/IntelligencePage'

const PAGES = {
  network: NetworkDiscoveryPage,
  packets: PacketSnifferPage,
  mac: MacToolPage,
  ports: PortScannerPage,
  intelligence: IntelligencePage,
}

function App() {
  const [activePage, setActivePage] = useState('network')
  const net = useNetShield()

  const PageComponent = PAGES[activePage]

  const currentMac =
    net.adapters && net.selectedInterface
      ? (net.adapters.find((a) => a.name === net.selectedInterface) || {}).mac_address
      : net.adapters && net.adapters.length > 0
        ? net.adapters[0].mac_address
        : null

  const gateway =
    net.devices && net.devices.length > 0
      ? (net.devices.find((d) => d.hostname && d.hostname !== 'unknown') || net.devices[0]).ip
      : null

  const activeNodes = net.devices ? net.devices.length : 0

  const isBusy = net.loading || net.packetsLoading || net.reportLoading || net.macChangeLoading

  return (
    <div className="shell">
      <Sidebar
        activePage={activePage}
        onNavigate={setActivePage}
        currentMac={currentMac}
        onRandomize={net.handleRandomizeMac}
        macLoading={net.macChangeLoading}
      />
      <TopBar gateway={gateway} activeNodes={activeNodes} isScanning={isBusy} />
      <main className="main">
        <ErrorBoundary key={activePage}>
          <PageComponent net={net} />
        </ErrorBoundary>
      </main>
    </div>
  )
}

export default App
