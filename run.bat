@echo off
chcp 65001 > nul
echo ========================================================
echo   [과제 8] WebAuthn 패스키 백엔드 서버 (server.py) 실행
echo ========================================================
echo.
echo  * 포트: 3000
echo  * 서버 주소: http://localhost:3000
echo  * 종료하려면 창을 닫거나 Ctrl + C 를 누르세요.
echo.
python server.py
pause
