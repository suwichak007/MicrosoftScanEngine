#!/bin/bash

# 1. Build และรัน Backend
cd backend
docker build -t scan-api .
docker rm -f scanner-backend || true
docker run -d --name scanner-backend -p 8000:8000 -v "/c/MicrosoftScanEngine/backend/data:/app/data" --restart always scan-api

# 2. Build และรัน Frontend
cd ../frontend
docker build -t scan-web .
docker rm -f scanner-frontend || true
docker run -d --name scanner-frontend -p 5173:5173 --restart always scan-web