# 1. เข้าไปที่โฟลเดอร์ backend แล้ว Build/Run
cd backend
docker build -t scan-api .
docker rm -f scanner-backend

# เพิ่มการส่งค่า -e เพื่อรับ User/Pass จาก GitHub CI/CD เข้าไปใน Container
docker run -d `
  --name scanner-backend `
  -p 8000:8000 `
  -e WINRM_USER=$env:WINRM_USER `
  -e WINRM_PASS=$env:WINRM_PASS `
  --restart always `
  scan-api

# 2. กลับออกมาแล้วไปที่ frontend เพื่อ Build/Run
cd ..
cd frontend
docker build -t scan-web .
docker rm -f scanner-frontend
docker run -d --name scanner-frontend -p 5173:5173 --restart always scan-web

# 3. ล้าง Image เก่าๆ ที่ไม่ได้ใช้
docker image prune -f