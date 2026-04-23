# 1. จัดการ Backend
cd backend
docker build -t scan-api .
docker rm -f scanner-backend

# รันพร้อมส่งค่า Secret และ Mount โฟลเดอร์ data จากเครื่องจริง
docker run -d `
  --name scanner-backend `
  -p 8000:8000 `
  -e WINRM_USER=$env:WINRM_USER `
  -e WINRM_PASS=$env:WINRM_PASS `
  -v "${PWD}/data:C:/MicrosoftScanEngine/backend/data" `
  --restart always `
  scan-api

# 2. จัดการ Frontend
cd ..
cd frontend
docker build -t scan-web .
docker rm -f scanner-frontend
docker run -d --name scanner-frontend -p 5173:5173 --restart always scan-web

# 3. ล้างขยะ
docker image prune -f