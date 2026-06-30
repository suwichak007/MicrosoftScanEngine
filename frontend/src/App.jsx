import React, { lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Home from './pages/Home';
import Scan from './pages/Scan';
import Register from './pages/Register';
import Result from './pages/Result';
import History from './pages/History';
import AdminUsers from './pages/Adminusers';
import AgentManagement from './pages/AgentManagement';
import ActivityLog from './pages/ActivityLog';
import ChangePassword from './pages/ChangePassword';  // ← ชื่อ import ต้องตรงกับชื่อไฟล์ (PascalCase)
import { ProtectedRoute } from './auth';

const Summary = lazy(() => import('./pages/Summary'));
const SubnetResult = lazy(() => import('./pages/SubnetResult'));

const protectedPage = (element, role) => (
  <ProtectedRoute role={role}>{element}</ProtectedRoute>
);

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/login" element={<Login />} />

        <Route path="/change-password" element={protectedPage(<ChangePassword />)} />
        <Route path="/register" element={<Register />} />

        <Route path="/home"      element={protectedPage(<Home />)} />
        <Route path="/Home"      element={protectedPage(<Home />)} />
        <Route path="/dashboard" element={protectedPage(<Home />)} />

        <Route path="/result"    element={protectedPage(<Result />)} />
        <Route path="/Result"    element={protectedPage(<Result />)} />

        <Route path="/history"   element={protectedPage(<History />)} />
        <Route path="/History"   element={protectedPage(<History />)} />

        <Route
          path="/summary"
          element={protectedPage(<Suspense fallback={<div>Loading report...</div>}><Summary /></Suspense>)}
        />
        <Route
          path="/Summary"
          element={protectedPage(<Suspense fallback={<div>Loading report...</div>}><Summary /></Suspense>)}
        />

        <Route path="/admin/users" element={protectedPage(<AdminUsers />, 'admin')} />
        <Route path="/admin/agents" element={protectedPage(<AgentManagement />, 'admin')} />
        <Route path="/admin/activity" element={protectedPage(<ActivityLog />, 'admin')} />

        {/* Requirement route aliases */}
        <Route path="/scan/new"          element={protectedPage(<Scan />)} />
        <Route path="/scan/:id/progress" element={protectedPage(<Result />)} />
        <Route path="/scan/:id/report"   element={protectedPage(<Result />)} />
        <Route
          path="/scan/:id/subnet"
          element={protectedPage(<Suspense fallback={<div>Loading fleet report...</div>}><SubnetResult /></Suspense>)}
        />


        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Router>
  );
}

export default App;
