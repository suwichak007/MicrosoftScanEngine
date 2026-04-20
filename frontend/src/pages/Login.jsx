import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(''); // เอาไว้โชว์ถ้า Login พลาด
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');

    // เตรียมข้อมูลในรูปแบบ Form Data (ตามที่ OAuth2 ของ FastAPI ต้องการ)
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);

    try {
      const response = await fetch('http://127.0.0.1:8000/login', {
        method: 'POST',
        body: formData, // ส่งแบบ FormData
      });

      if (response.ok) {
        const data = await response.json();
        // 1. เก็บ Token ลงใน LocalStorage ของ Browser
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('username', data.username);
        
        console.log('Login Success!', data);
        // 2. ย้ายไปหน้า Dashboard
        navigate('/Home');
      } else {
        const errorData = await response.json();
        setError(errorData.detail || 'Login failed');
      }
    } catch (err) {
      setError('Cannot connect to server');
    }
  };

  return (
    <div className="d-flex align-items-center justify-content-center vh-100 bg-light">
      <div className="card shadow-sm border-0" style={{ width: '400px', borderRadius: '15px' }}>
        <div className="card-body p-5">
          <div className="text-center mb-4">
            <div className="bg-primary text-white d-inline-flex align-items-center justify-content-center mb-3" style={{ width: '60px', height: '60px', borderRadius: '12px', fontSize: '32px' }}>S</div>
            <h4 className="fw-bold">Security Scanner</h4>
          </div>

          {/* แสดงข้อความ Error ถ้ามี */}
          {error && <div className="alert alert-danger py-2 small">{error}</div>}

          <form onSubmit={handleLogin}>
            <div className="mb-3">
              <label className="form-label small fw-bold text-secondary">USERNAME</label>
              <input 
                type="text" className="form-control bg-light border-0" 
                value={username} onChange={(e) => setUsername(e.target.value)} required 
              />
            </div>
            <div className="mb-4">
              <label className="form-label small fw-bold text-secondary">PASSWORD</label>
              <input 
                type="password" className="form-control bg-light border-0" 
                value={password} onChange={(e) => setPassword(e.target.value)} required 
              />
            </div>
            <button type="submit" className="btn btn-primary w-100 fw-bold">Sign In</button>
          </form>
        </div>
      </div>
    </div>
  );
}

export default Login;