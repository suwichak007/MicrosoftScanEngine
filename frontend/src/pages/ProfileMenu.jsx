import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { clearAuth, useCurrentUser } from '../auth';
import './ProfileMenu.css';

export default function ProfileMenu() {
  const navigate = useNavigate();
  const menuRef = useRef(null);
  const [open, setOpen] = useState(false);
  const { user } = useCurrentUser();
  const username = user?.username || localStorage.getItem('username') || 'User';
  const role = user?.role || 'viewer';
  const avatarChar = username.charAt(0).toUpperCase() || 'A';

  useEffect(() => {
    function handleClickOutside(event) {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setOpen(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleChangePassword = () => {
    setOpen(false);
    navigate('/change-password');
  };

  const handleLogout = () => {
    clearAuth();
    navigate('/login');
  };

  return (
    <div className="avatarWrap" ref={menuRef}>
      <button
        type="button"
        className="avatar profileAvatar"
        onClick={() => setOpen((value) => !value)}
        aria-haspopup="menu"
        aria-expanded={open}
        title="Account menu"
      >
        {avatarChar}
      </button>

      {open && (
        <div className="userMenu" role="menu">
          <div className="userMenuName">{username}</div>
          <div className="userMenuRole">{role}</div>
          <div className="userMenuDivider" />
          <button type="button" className="userMenuItem" onClick={handleChangePassword}>
            Change Password
          </button>
          <button type="button" className="userMenuItem userMenuItemDanger" onClick={handleLogout}>
            Log out
          </button>
        </div>
      )}
    </div>
  );
}

