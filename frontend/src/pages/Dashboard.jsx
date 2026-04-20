import React, { useEffect, useState, useCallback } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

function Dashboard() {
    const [stats, setStats] = useState(null);
    const [scanning, setScanning] = useState(false);

    // ใช้ useCallback เพื่อป้องกันปัญหาการ Re-render และประกาศฟังก์ชันครั้งเดียว
    const fetchStats = useCallback(async () => {
        try {
            const res = await fetch('http://127.0.0.1:8000/api/dashboard/stats');
            
            if (!res.ok) {
                throw new Error("Cannot connect to server");
            }
            
            const data = await res.json();
            
            // ตรวจสอบว่ามีข้อมูลจริงไหม ถ้าไม่มีให้เซ็ตค่า Default
            if (!data || data.total_scans === 0) {
                setStats({
                    total_scans: 0,
                    latest_score: 0,
                    target: "No Scan Result",
                    details: { "System": "Ready to Scan" }
                });
            } else {
                setStats(data);
            }
        } catch (err) {
            console.error("Fetch Error:", err);
            // กรณี Server ล่ม ให้โชว์สถานะ Error แทนการ Loading ค้าง
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

    const handleStartScan = async () => {
        setScanning(true);
        try {
            const response = await fetch('http://127.0.0.1:8000/api/scan/run', { method: 'POST' });
            if (response.ok) {
                await fetchStats(); // โหลดข้อมูลใหม่ทันทีหลังสแกนเสร็จ
            }
        } catch (error) {
            alert("Scan failed: Cannot connect to server");
        } finally {
            setScanning(false);
        }
    };

    // ถ้า stats ยังเป็น null (ช่วงเสี้ยววินาทีแรกที่กำลัง Fetch)
    if (!stats) {
        return (
            <div className="d-flex justify-content-center align-items-center vh-100">
                <div className="spinner-border text-primary" role="status"></div>
                <span className="ms-2">Loading System Data...</span>
            </div>
        );
    }

    const chartData = [
        { name: 'Security Score', value: stats.latest_score },
        { name: 'Risk', value: 100 - stats.latest_score }
    ];
    const COLORS = ['#00C49F', '#FF8042'];

    return (
        <div className="container-fluid p-4 bg-light min-vh-100">
            <div className="d-flex justify-content-between align-items-center mb-4">
                <div>
                    <h2 className="fw-bold text-dark mb-0">Security Dashboard</h2>
                    <p className="text-muted small">Real-time Windows Security Baseline Monitoring</p>
                </div>
                <button 
                    className={`btn ${scanning ? 'btn-secondary' : 'btn-primary'} px-4 fw-bold shadow-sm`}
                    onClick={handleStartScan}
                    disabled={scanning}
                >
                    {scanning ? (
                        <><span className="spinner-border spinner-border-sm me-2"></span>Scanning...</>
                    ) : 'RUN NEW SCAN'}
                </button>
            </div>

            <div className="row g-4">
                {/* Score Chart */}
                <div className="col-md-4">
                    <div className="card border-0 shadow-sm p-4 text-center h-100">
                        <h5 className="text-secondary fw-bold mb-3">Overall Health</h5>
                        <div style={{ width: '100%', height: 220 }}>
                            <ResponsiveContainer>
                                <PieChart>
                                    <Pie data={chartData} innerRadius={70} outerRadius={90} paddingAngle={5} dataKey="value">
                                        {chartData.map((entry, index) => <Cell key={index} fill={COLORS[index]} />)}
                                    </Pie>
                                    <Tooltip />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                        <h1 className="fw-bold text-primary display-4">{stats.latest_score}%</h1>
                        <p className="badge bg-light text-dark border">Target: {stats.target}</p>
                    </div>
                </div>

                {/* Details List */}
                <div className="col-md-8">
                    <div className="card border-0 shadow-sm h-100">
                        <div className="card-header bg-white border-0 pt-4 px-4">
                            <h5 className="text-secondary fw-bold">Detailed Baseline Check</h5>
                        </div>
                        <div className="card-body px-4">
                            <div className="list-group list-group-flush">
                                {Object.entries(stats.details).map(([key, value]) => (
                                    <div key={key} className="list-group-item d-flex justify-content-between align-items-center px-0 py-3">
                                        <span className="text-capitalize fw-medium">{key.replace(/_/g, ' ')}</span>
                                        <span className={`badge ${
                                            ['Pass', 'Enabled', 'Disabled', 'Active'].includes(value) 
                                            ? 'bg-success-subtle text-success border border-success' 
                                            : 'bg-danger-subtle text-danger border border-danger'
                                        } px-3 py-2`}>
                                            {value}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>
                        <div className="card-footer bg-white border-0 pb-4 px-4">
                            <small className="text-muted">Total Scans Performed: <strong>{stats.total_scans}</strong></small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Dashboard;