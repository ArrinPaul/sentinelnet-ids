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
      <div className="flex h-screen bg-gray-950 text-gray-100 overflow-hidden">
        <Sidebar open={sidebarOpen} setOpen={setSidebarOpen} />
        <div className="flex flex-col flex-1 overflow-hidden">
          <Header sidebarOpen={sidebarOpen} setSidebarOpen={setSidebarOpen} />
          <main className="flex-1 overflow-y-auto p-6 bg-gray-950">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/traffic" element={<Traffic />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/policies" element={<Policies />} />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
}

export default App;
