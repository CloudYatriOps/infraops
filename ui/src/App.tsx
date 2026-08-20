import { useState } from 'react'
import {
  Dashboard, Projects, TaskExecution, TaskDetail, Findings, Incidents,
  Approvals, RuntimeStatus, EvidenceBrowser, Providers,
} from './pages'

// Deliberately no router library - a handful of tab-switched views with
// plain useState is all this small a UI needs (ponytail: smallest correct
// change). Every page below is a thin view over one API response; none of
// them contain skill resolution, policy evaluation, or routing logic.
const TABS = [
  'Dashboard', 'Projects', 'Task Execution', 'Task Detail', 'Findings',
  'Incidents', 'Approvals', 'Runtime', 'Evidence', 'Providers',
] as const
type Tab = typeof TABS[number]

function App() {
  const [tab, setTab] = useState<Tab>('Dashboard')
  const [taskId, setTaskId] = useState('')

  const openTask = (id: string) => { setTaskId(id); setTab('Task Detail') }

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', maxWidth: 1000, margin: '0 auto', padding: 16 }}>
      <h1>AEP Platform</h1>
      <nav style={{ marginBottom: 16, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            style={{ fontWeight: t === tab ? 700 : 400 }}>{t}</button>
        ))}
      </nav>
      {tab === 'Dashboard' && <Dashboard />}
      {tab === 'Projects' && <Projects onOpen={() => { setTab('Incidents') }} />}
      {tab === 'Task Execution' && <TaskExecution onCreated={openTask} />}
      {tab === 'Task Detail' && (
        <div>
          <input placeholder="task id" value={taskId} onChange={(e) => setTaskId(e.target.value)} />
          {taskId && <TaskDetail taskId={taskId} />}
        </div>
      )}
      {tab === 'Findings' && <Findings />}
      {tab === 'Incidents' && <Incidents />}
      {tab === 'Approvals' && <Approvals />}
      {tab === 'Runtime' && <RuntimeStatus />}
      {tab === 'Evidence' && <EvidenceBrowser />}
      {tab === 'Providers' && <Providers />}
    </div>
  )
}

export default App
