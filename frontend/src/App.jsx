import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Home from './pages/Home';
import Dashboard from './pages/Dashboard';
import Register from './pages/Register';
import Result from './pages/Result';

function App() {
  return (
    <Router>
      <Routes>
        {/* หน้าแรกสุด ให้วิ่งไปหน้า Login */}
        <Route path="/" element={<Login />} />
        
        {/* หน้า Login */}
        <Route path="/login" element={<Login />} />
        <Route path="/Home" element={<Home />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/register" element={<Register />} />
        <Route path="/Result" element={<Result />} />
        
        
        {/* ถ้า User พิมพ์ URL มั่วๆ ให้ดีดกลับไปหน้า Login */}
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Router>
  );
}

export default App;