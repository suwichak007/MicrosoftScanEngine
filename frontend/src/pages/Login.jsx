import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Login.css'; // นำเข้า CSS สำหรับหน้า Login

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

    const hostname = window.location.hostname;
    const apiUrl = `http://${hostname}:8000/login`;
    

    try {
      const response = await fetch(apiUrl, {
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
    <div className="login-page d-flex align-items-center justify-content-center">
      <div className="Login_rectangle">
        <div className="Login_card-body">
          <div className="text-center mb-4">
            <div className="Login_Topic">Scanner</div>
          </div>

          {/* แสดงข้อความ Error ถ้ามี */}
          {error && <div className="alert alert-danger py-2 small">{error}</div>}

          <form onSubmit={handleLogin}>
            <div className="mb-3">
              <label className="Login_Username">Username / Email</label>
            </div>
              <input 
                type="text" 
                className="Login_Username_Input_Field" 
                value={username} 
                onChange={(e) => setUsername(e.target.value)} 
                required 
              />
            <div className="mb-4">
              <label className="Login_Password">Password</label>
            </div>
            <div>
              <input 
                type="password" className="Login_Password_Input_Field" 
                value={password} onChange={(e) => setPassword(e.target.value)} required 
              />
            </div>
            <button type="submit" className="Login_signin_button">Sign In</button>
            <div className='Register_link'>
              <span>Don't have an account? </span>
              <a href="/register">Register</a>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

export default Login;