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
import { runAnalysis } from './services/analysisApi'

const ROUTES = new Set(['dashboard', 'scan', 'findings', 'risk', 'cbom', 'migration'])

function routeFromHash() {
  const route = window.location.hash.slice(1)
  return ROUTES.has(route) ? route : 'dashboard'
}

function App() {
  const [activeItem, setActiveItem] = useState(routeFromHash)
  const [searchQuery, setSearchQuery] = useState('')
  const [analysis, setAnalysis] = useState(null)
  const [scanState, setScanState] = useState('idle')
  const [scanError, setScanError] = useState('')

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

  const handleScan = async (path) => {
    if (!path.trim()) {
      setScanError('Enter a repository path available to the backend.')
      return
    }
    setScanState('scanning')
    setScanError('')
    try {
      const response = await runAnalysis(path.trim())
      setAnalysis({ ...response, scannedAt: new Date().toISOString() })
      setScanState('completed')
      handleNavigation('dashboard')
    } catch (error) {
      setScanState('error')
      setScanError(error.message || 'The scan could not be completed.')
    }
  }

  function renderPage() {
    switch (activeItem) {
      case 'findings':
        return <FindingsPage analysis={analysis} searchQuery={searchQuery} onSearchChange={setSearchQuery} />
      case 'risk':
        return <RiskPage analysis={analysis} searchQuery={searchQuery} />
      case 'cbom':
        return <CbomPage analysis={analysis} />
      case 'migration':
        return <MigrationPage analysis={analysis} searchQuery={searchQuery} />
      case 'scan':
        return <ScanPage scanState={scanState} error={scanError} onScan={handleScan} />
      case 'dashboard':
      default:
        return <Dashboard analysis={analysis} searchQuery={searchQuery} onSearchChange={setSearchQuery} />
    }
  }

  return (
    <div className="app">
      <Sidebar activeItem={activeItem} onSelect={handleNavigation} findingCount={analysis?.finding_count} scanState={scanState} />
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
