import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import './Register.css';

function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();
  const hostname = window.location.hostname;
  const apiUrl = `http://${hostname}:8000/register`;

  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (password !== confirmPassword) {
      setError('Password และ Confirm Password ไม่ตรงกัน');
      return;
    }

    try {
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username,
          password,
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess('Register success! กำลังไปหน้า Login...');
        setTimeout(() => {
          navigate('/');
        }, 1500);
      } else {
        setError(data.detail || 'Register failed');
      }
    } catch (err) {
      setError('Cannot connect to server');
    }
  };

  return (
    <div className="Register-page d-flex align-items-center justify-content-center">
      <div className="Register_rectangle">
        <div className="Register_card-body">
          <div className="text-center mb-4">
            <div className="Register_Topic">Register</div>
          </div>

          {error && <div className="alert alert-danger py-2 small">{error}</div>}
          {success && <div className="alert alert-success py-2 small">{success}</div>}

          <form onSubmit={handleRegister}>
            <div className="mb-2">
              <label className="Register_Username">Username / Email</label>
            </div>
            <input
              type="text"
              className="Register_Username_Input_Field"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />

            <div className="mb-2">
              <label className="Register_Password">Password</label>
            </div>
            <input
              type="password"
              className="Register_Password_Input_Field"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />

            <div className="mb-2">
              <label className="Register_Confirm-Password">Confirm Password</label>
            </div>
            <input
              type="password"
              className="Register_Password_Input_Field"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
            <div>
                <button type="submit" className="Register_signin_button">Sign Up</button>
            </div>
            

            <div className="Register_Already">
              <span>Already have an account? </span>
              <Link to="/">Login</Link>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

export default Register;