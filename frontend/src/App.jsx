import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Home from './pages/Home';
import Register from './pages/Register';
import Result from './pages/Result';
import History from './pages/History';
import Summary from './pages/Summary';
import AdminUsers from './pages/Adminusers';
import { ProtectedRoute } from './auth';

const protectedPage = (element, role) => (
  <ProtectedRoute role={role}>{element}</ProtectedRoute>
);

function App() {
  return (
    <Router>
      <Routes>
        {/* หน้าแรกสุด ให้วิ่งไปหน้า Login */}
        <Route path="/" element={<Login />} />
        
        {/* หน้า Login */}
        <Route path="/login" element={<Login />} />
        <Route path="/Home" element={protectedPage(<Home />)} />
        <Route path="/home" element={protectedPage(<Home />)} />
        <Route path="/dashboard" element={protectedPage(<Result />)} />
        <Route path="/register" element={<Register />} />
        <Route path="/Result" element={protectedPage(<Result />)} />
        <Route path="/result" element={protectedPage(<Result />)} />
        <Route path="/History" element={protectedPage(<History />)} />
        <Route path="/history" element={protectedPage(<History />)} />
        <Route path="/Summary" element={protectedPage(<Summary />)} />
        <Route path="/summary" element={protectedPage(<Summary />)} />
        <Route path="/admin/users" element={protectedPage(<AdminUsers />, 'admin')} />

        {/* Requirement route aliases */}
        <Route path="/scan/new" element={protectedPage(<Home />)} />
        <Route path="/scan/:id/progress" element={protectedPage(<Result />)} />
        <Route path="/scan/:id/report" element={protectedPage(<Result />)} />
        
        
        {/* ถ้า User พิมพ์ URL มั่วๆ ให้ดีดกลับไปหน้า Login */}
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Router>
  );
}

export default App;
