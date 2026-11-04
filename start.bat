@echo off
title Quantum Secure Messenger

echo ==================================
echo Quantum Secure Messenger
echo ==================================
echo.

echo Starting Relay Server...
start cmd /k "cargo run --bin server"

timeout /t 5 >nul

echo Starting Web Server...
start cmd /k "cd web && python -m http.server 8000"

timeout /t 2 >nul

echo Opening Browser...
start http://localhost:8000

echo.
echo ==================================
echo System Started Successfully
echo ==================================
echo.
echo Open another browser tab/window:
echo http://localhost:8000
echo.
echo Use different usernames in each tab.
echo.
pause
