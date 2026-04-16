import React from 'react';
import { useNavigate } from 'react-router-dom';

function Home() {
  const navigate = useNavigate();

  return (
    <div className="container mt-4">
      {/* ส่วนหัวทักทาย */}
      <div className="p-5 mb-4 bg-light rounded-3 border">
        <div className="container-fluid py-5">
          <h1 className="display-5 fw-bold">Welcome, Admin</h1>
          <p className="col-md-8 fs-4">
            ยินดีต้อนรับเข้าสู่ระบบ Security Baseline Scanner 
            วันนี้ระบบพร้อมสำหรับการตรวจสอบความปลอดภัยเครื่องเป้าหมายแล้ว
          </p>
          <button 
            className="btn btn-primary btn-lg" 
            onClick={() => navigate('/dashboard')}
          >
            ไปหน้า Dashboard
          </button>
        </div>
      </div>

      {/* ส่วนสรุปสั้นๆ (ตัวอย่าง) */}
      <div className="row align-items-md-stretch">
        <div className="col-md-6">
          <div className="h-100 p-5 text-white bg-dark rounded-3">
            <h2>Last Scan</h2>
            <p>Windows 11 Baseline - 16/04/2026</p>
            <p className="text-warning">Status: Completed with 3 Critical</p>
          </div>
        </div>
        <div className="col-md-6">
          <div className="h-100 p-5 bg-light border rounded-3">
            <h2>System Status</h2>
            <p>Scan Engine: <span className="text-success">Ready</span></p>
            <p>Database: <span className="text-success">Connected</span></p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Home;