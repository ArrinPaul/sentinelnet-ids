import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import Traffic from './pages/Traffic';
import Alerts from './pages/Alerts';
import Policies from './pages/Policies';
import './index.css';

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <Router>
      <div className="flex h-screen overflow-hidden" style={{ background: 'var(--color-midnight)' }}>
        <Sidebar open={sidebarOpen} setOpen={setSidebarOpen} />
        <div className="flex flex-col flex-1 overflow-hidden">
          <Header sidebarOpen={sidebarOpen} setSidebarOpen={setSidebarOpen} />
          <main className="flex-1 overflow-y-auto">
            <div className="p-6 max-w-[1600px] mx-auto">
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/traffic" element={<Traffic />} />
                <Route path="/alerts" element={<Alerts />} />
                <Route path="/policies" element={<Policies />} />
              </Routes>
            </div>
          </main>
        </div>
      </div>
    </Router>
  );
}

export default App;
