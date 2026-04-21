import React from 'react';
import { useNavigate } from 'react-router-dom';
import './Home.css';

function Home() {
  const navigate = useNavigate();
  const status = 'error'; // ตัวอย่างสถานะการเชื่อมต่อ (success, error, หรืออื่นๆ)

  return (
    <div className="homePage">
      <header className="topBar">
        <div className="brand">Scanner</div>

        <div className="topBarRight">
          <div className="bellWrapper">
            <span className="bellIcon">🔔</span>
            <span className="notificationDot"></span>
          </div>
          <div className="profileCircle">👤</div>
        </div>
      </header>

      <div className="homeLayout">
        <aside className="sideBar">
          <div className="menuGroup">
            <button className="menuItem active">Home</button>
            <button className="menuItem" onClick={() => navigate('/history')}>
              History
            </button>
            <button className="menuItem" onClick={() => navigate('/guide')}>
              Guide
            </button>
          </div>

          <button className="logoutButton" onClick={() => navigate('/')}>
            <span className="logoutIcon">↪</span>
            <span>Log Out</span>
          </button>
        </aside>

        <main className="mainContent">
          <h1 className="pageTitle">Scanner</h1>

          <section className="scanCard">
            <div className="stepSection">
              <div className="stepHeader">
                <div className="stepNumber">1</div>
                <div className="stepTitleGroup">
                  <div className="stepTitle">choose version</div>
                  <div className="stepLine"></div>
                </div>
              </div>

              <div className="fieldGroup single">
                <label className="fieldLabel">version</label>
                <select className="fieldInput selectInput">
                  <option>Windows 11 v24H2</option>
                  <option>Windows 11 v25H2</option>
                </select>
              </div>
            </div>

            <div className="stepSection">
              <div className="stepHeader">
                <div className="stepNumber">2</div>
                <div className="stepTitleGroup">
                  <div className="stepTitle">IP Address And HostName</div>
                  <div className="stepLine"></div>
                </div>
              </div>

              <div className="fieldRow">
                <div className="fieldGroup">
                  <label className="fieldLabelIP">IP</label>
                  <input className="fieldInputIP" type="text" defaultValue="192.168.2.83" />
                </div>

                <div className="fieldGroup">
                  <label className="fieldLabelIP">Hostname</label>
                  <input className="fieldInputIP" type="text" />
                </div>

                <div className="fieldGroup">
                  <label className="fieldLabelIP">Password</label>
                  <input className="fieldInputIP" type="password" />
                </div>
              </div>

              <div className="actionRow">
                <button className="connectButton">Connect</button>

                <div className="statusConnected">
                    <span className={`statusDot ${status}`}>
                      {status === 'success' && '✔'}
                      {status === 'error' && '✖'}
                    </span>
                  <span>Connected</span>
                </div>
              </div>
            </div>

            <div className="scanButtonRow">
              <button 
              className="scanButton" onClick={() => {navigate('/Dashboard');}}>Start Scan</button>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}

export default Home;