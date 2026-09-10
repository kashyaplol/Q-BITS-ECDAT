import { useEffect, useState } from 'react'
import './App.css'
import Sidebar from './components/Sidebar/Sidebar'
import Header from './components/Header/Header'
import Dashboard from './pages/Dashboard/Dashboard'
import {
  CbomPage,
  FindingsPage,
  MigrationPage,
  RiskPage,
  ScanPage,
} from './pages/Analysis/AnalysisPages'

const ROUTES = new Set(['dashboard', 'scan', 'findings', 'risk', 'cbom', 'migration'])

function routeFromHash() {
  const route = window.location.hash.slice(1)
  return ROUTES.has(route) ? route : 'dashboard'
}

function App() {
  const [activeItem, setActiveItem] = useState(routeFromHash)
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => {
    const handleHashChange = () => setActiveItem(routeFromHash())
    window.addEventListener('hashchange', handleHashChange)
    return () => window.removeEventListener('hashchange', handleHashChange)
  }, [])

  const handleNavigation = (item) => {
    if (ROUTES.has(item)) {
      window.location.hash = item
      setActiveItem(item)
    }
  }

  const handleRunScan = () => {
    handleNavigation('scan')
  }

  function renderPage() {
    switch (activeItem) {
      case 'findings':
        return <FindingsPage searchQuery={searchQuery} onSearchChange={setSearchQuery} />
      case 'risk':
        return <RiskPage searchQuery={searchQuery} />
      case 'cbom':
        return <CbomPage />
      case 'migration':
        return <MigrationPage searchQuery={searchQuery} />
      case 'scan':
        return <ScanPage />
      case 'dashboard':
      default:
        return <Dashboard searchQuery={searchQuery} onSearchChange={setSearchQuery} />
    }
  }

  return (
    <div className="app">
      <Sidebar activeItem={activeItem} onSelect={handleNavigation} />
      <div className="app__main">
        <Header
          onRunScan={handleRunScan}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
        />
        {renderPage()}
      </div>
    </div>
  )
}

export default App