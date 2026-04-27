import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

// ลบ StrictMode ออก เพราะทำให้ useEffect รัน 2 ครั้งใน dev mode
// ส่งผลให้ /api/scan/remote ถูกเรียก 2 ครั้งทุกครั้ง
createRoot(document.getElementById('root')).render(
  <App />
)