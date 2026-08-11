import { useState } from 'react'
import './App.css'
import useNetShield from './useNetShield'
import Sidebar from './Sidebar'
import ErrorBoundary from './ErrorBoundary'
import NetworkDiscoveryPage from './pages/NetworkDiscoveryPage'
import PacketSnifferPage from './pages/PacketSnifferPage'
import MacToolPage from './pages/MacToolPage'
import PortScannerPage from './pages/PortScannerPage'
import WifiSecurityPage from './pages/WifiSecurityPage'
import IntelligencePage from './pages/IntelligencePage'

const PAGES = {
  network: NetworkDiscoveryPage,
  packets: PacketSnifferPage,
  mac: MacToolPage,
  ports: PortScannerPage,
  wifi: WifiSecurityPage,
  intelligence: IntelligencePage,
}

function App() {
  const [activePage, setActivePage] = useState('wifi')
  const net = useNetShield()

  const PageComponent = PAGES[activePage]

  const currentMac =
    net.adapters && net.selectedInterface
      ? (net.adapters.find((a) => a.name === net.selectedInterface) || {}).mac_address
      : net.adapters && net.adapters.length > 0
        ? net.adapters[0].mac_address
        : null

  return (
    <div className="shell">
      <Sidebar
        activePage={activePage}
        onNavigate={setActivePage}
        currentMac={currentMac}
        onRandomize={net.handleRandomizeMac}
        macLoading={net.macChangeLoading}
      />
      <main className="main">
        <ErrorBoundary key={activePage}>
          <PageComponent net={net} />
        </ErrorBoundary>
      </main>
    </div>
  )
}

export default App
