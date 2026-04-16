import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    // ในอนาคตจะเชื่อมต่อกับ API Backend (FastAPI) ที่นี่
    console.log('Logging in with:', username, password);
    
    // จำลองการ Login สำเร็จแล้วไปที่หน้า Dashboard
    navigate('/Home');
  };

  return (
    <div className="d-flex align-items-center justify-content-center vh-100 bg-light">
      <div className="card shadow-sm border-0" style={{ width: '400px', borderRadius: '15px' }}>
        <div className="card-body p-5">
          {/* Logo ส่วนหัว */}
          <div className="text-center mb-4">
            <div 
              className="d-inline-flex align-items-center justify-content-center bg-primary text-white fw-bold mb-3"
              style={{ width: '60px', height: '60px', borderRadius: '12px', fontSize: '32px' }}
            >
              S
            </div>
            <h4 className="fw-bold">Security Baseline Scanner</h4>
            <p className="text-muted">Please login to your account</p>
          </div>

          {/* Form Login */}
          <form onSubmit={handleLogin}>
            <div className="mb-3">
              <label className="form-label text-secondary small fw-bold">USERNAME</label>
              <input 
                type="text" 
                className="form-control form-control-lg bg-light border-0" 
                placeholder="Enter username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required 
              />
            </div>
            <div className="mb-4">
              <label className="form-label text-secondary small fw-bold">PASSWORD</label>
              <input 
                type="password" 
                className="form-control form-control-lg bg-light border-0" 
                placeholder="Enter password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required 
              />
            </div>
            <button type="submit" className="btn btn-primary btn-lg w-100 fw-bold shadow-sm" style={{ borderRadius: '10px' }}>
              Sign In
            </button>
          </form>

          <div className="text-center mt-4">
            <a href="#" className="text-decoration-none small text-muted">Forgot Password?</a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Login;