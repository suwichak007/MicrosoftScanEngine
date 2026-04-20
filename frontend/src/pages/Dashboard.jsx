import React, { useEffect, useState, useCallback } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

function Dashboard() {
    const [stats, setStats] = useState(null);
    const [scanning, setScanning] = useState(false);

    // ฟังก์ชันดึงข้อมูลจาก Backend
    const fetchStats = useCallback(async () => {
        try {
            const res = await fetch('http://127.0.0.1:8000/api/dashboard/stats');
            
            if (!res.ok) {
                throw new Error("Cannot connect to server");
            }
            
            const data = await res.json();
            
            if (!data || data.total_scans === 0) {
                setStats({
                    total_scans: 0,
                    latest_score: 0,
                    target: "No Scan Result",
                    details: {}
                });
            } else {
                setStats(data);
            }
        } catch (err) {
            console.error("Fetch Error:", err);
            setStats({
                total_scans: 0,
                latest_score: 0,
                target: "Server Offline",
                details: { "Error": "Please check your backend server" }
            });
        }
    }, []);

    useEffect(() => {
        fetchStats();
    }, [fetchStats]);

    // ฟังก์ชันสั่ง Run Scan ใหม่
    const handleStartScan = async () => {
        setScanning(true);
        try {
            const response = await fetch('http://127.0.0.1:8000/api/scan/run', { method: 'POST' });
            if (response.ok) {
                await fetchStats(); 
            } else {
                const errorData = await response.json();
                alert(`Scan failed: ${errorData.detail || 'Unknown error'}`);
            }
        } catch (error) {
            alert("Scan failed: Cannot connect to server");
        } finally {
            setScanning(false);
        }
    };

    if (!stats) {
        return (
            <div className="d-flex justify-content-center align-items-center vh-100">
                <div className="spinner-border text-primary" role="status"></div>
                <span className="ms-3 fw-bold">Loading System Data...</span>
            </div>
        );
    }

    const chartData = [
        { name: 'Security Score', value: stats.latest_score },
        { name: 'Risk', value: 100 - stats.latest_score }
    ];
    const COLORS = ['#10b981', '#ef4444']; // Green and Red

    return (
        <div className="container-fluid p-4 bg-light min-vh-100">
            {/* Header Section */}
            <div className="d-flex justify-content-between align-items-center mb-4 bg-white p-4 rounded shadow-sm">
                <div>
                    <h2 className="fw-bold text-dark mb-0">Security Dashboard</h2>
                    <p className="text-muted small mb-0">Windows 11 v24H2 Security Baseline Monitoring</p>
                </div>
                <button 
                    className={`btn ${scanning ? 'btn-secondary' : 'btn-primary'} px-4 py-2 fw-bold shadow-sm`}
                    onClick={handleStartScan}
                    disabled={scanning}
                >
                    {scanning ? (
                        <><span className="spinner-border spinner-border-sm me-2"></span>Scanning...</>
                    ) : 'RUN NEW SCAN'}
                </button>
            </div>

            <div className="row g-4">
                {/* Left: Overall Score Chart */}
                <div className="col-lg-4">
                    <div className="card border-0 shadow-sm p-4 text-center h-100">
                        <h5 className="text-secondary fw-bold mb-3">Overall Health Score</h5>
                        <div style={{ width: '100%', height: 250 }}>
                            <ResponsiveContainer>
                                <PieChart>
                                    <Pie 
                                        data={chartData} 
                                        innerRadius={70} 
                                        outerRadius={95} 
                                        paddingAngle={5} 
                                        dataKey="value"
                                        animationDuration={1000}
                                    >
                                        {chartData.map((entry, index) => <Cell key={index} fill={COLORS[index]} />)}
                                    </Pie>
                                    <Tooltip />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                        <h1 className="fw-bold text-primary display-3">{stats.latest_score}%</h1>
                        <div className="mt-3">
                            <span className="badge bg-dark px-3 py-2">Target: {stats.target}</span>
                        </div>
                        <div className="mt-4 pt-3 border-top">
                            <p className="text-muted small">Total Scans Performed: <strong>{stats.total_scans}</strong></p>
                        </div>
                    </div>
                </div>

                {/* Right: Detailed Baseline Check */}
                <div className="col-lg-8">
                    <div className="card border-0 shadow-sm h-100">
                        <div className="card-header bg-white border-0 pt-4 px-4">
                            <div className="d-flex justify-content-between align-items-center">
                                <h5 className="text-secondary fw-bold mb-0">Detailed Baseline Check</h5>
                                <span className="badge bg-info text-white">{Object.keys(stats.details || {}).length} Items</span>
                            </div>
                        </div>
                        <div className="card-body px-4" style={{ maxHeight: '600px', overflowY: 'auto' }}>
                            <div className="list-group list-group-flush">
                                {stats.details && Object.keys(stats.details).length > 0 ? (
                                    Object.entries(stats.details).map(([policy, status]) => {
                                        // ตรวจสอบสถานะเพื่อกำหนดสี Badge
                                        const statusStr = String(status).toLowerCase();
                                        const isPass = statusStr.includes('pass');
                                        const isManual = statusStr.includes('manual');
                                        
                                        let badgeClass = "bg-danger-subtle text-danger border border-danger"; // Default: Fail
                                        if (isPass) badgeClass = "bg-success-subtle text-success border border-success";
                                        if (isManual) badgeClass = "bg-warning-subtle text-warning border border-warning";

                                        return (
                                            <div key={policy} className="list-group-item d-flex justify-content-between align-items-center px-0 py-3 border-bottom">
                                                <div className="me-3">
                                                    <div className="fw-bold text-dark" style={{ fontSize: '0.95rem' }}>{policy}</div>
                                                </div>
                                                <span className={`badge ${badgeClass} px-3 py-2`} style={{ minWidth: '100px' }}>
                                                    {status}
                                                </span>
                                            </div>
                                        );
                                    })
                                ) : (
                                    <div className="text-center py-5">
                                        <p className="text-muted">No scan data available. Click "Run New Scan" to start.</p>
                                    </div>
                                )}
                            </div>
                        </div>
                        <div className="card-footer bg-light border-0 py-3 text-center">
                            <small className="text-muted italic">Results are based on Microsoft Security Baseline v24H2</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Dashboard;