import { useState } from 'react'
import './App.css'
import Sidebar from './components/Sidebar/Sidebar'
import Header from './components/Header/Header'
import Dashboard from './pages/Dashboard/Dashboard'

function App() {
  const [activeItem, setActiveItem] = useState('dashboard')

  const handleRunScan = () => {
    // TODO: wire up to backend scan endpoint once available
    setActiveItem('scan')
  }

  return (
    <div className="app">
      <Sidebar activeItem={activeItem} onSelect={setActiveItem} />
      <div className="app__main">
        <Header onRunScan={handleRunScan} />
        <Dashboard onRunScan={handleRunScan} />
      </div>
    </div>
  )
}

export default App