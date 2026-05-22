import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Home from './pages/Home';
import Register from './pages/Register';
import Result from './pages/Result';
import History from './pages/History';
import Summary from './pages/Summary';
import AdminUsers from './pages/Adminusers';
import ChangePassword from './pages/ChangePassword';  // ← ชื่อ import ต้องตรงกับชื่อไฟล์ (PascalCase)
import { ProtectedRoute } from './auth';

const protectedPage = (element, role) => (
  <ProtectedRoute role={role}>{element}</ProtectedRoute>
);

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/login" element={<Login />} />

        {/* ไม่ต้อง protect — user ยังไม่ได้ login ก็เข้าได้ */}
        <Route path="/change-password" element={<ChangePassword />} />
        <Route path="/register" element={<Register />} />

        <Route path="/home"      element={protectedPage(<Home />)} />
        <Route path="/Home"      element={protectedPage(<Home />)} />
        <Route path="/dashboard" element={protectedPage(<Home />)} />

        <Route path="/result"    element={protectedPage(<Result />)} />
        <Route path="/Result"    element={protectedPage(<Result />)} />

        <Route path="/history"   element={protectedPage(<History />)} />
        <Route path="/History"   element={protectedPage(<History />)} />

        <Route path="/summary"   element={protectedPage(<Summary />)} />
        <Route path="/Summary"   element={protectedPage(<Summary />)} />

        <Route path="/admin/users" element={protectedPage(<AdminUsers />, 'admin')} />

        {/* Requirement route aliases */}
        <Route path="/scan/new"          element={protectedPage(<Home />)} />
        <Route path="/scan/:id/progress" element={protectedPage(<Result />)} />
        <Route path="/scan/:id/report"   element={protectedPage(<Result />)} />

        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Router>
  );
}

export default App;