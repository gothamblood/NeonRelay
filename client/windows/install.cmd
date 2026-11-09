@echo off
rem NeonRelay - installation du client (une seule fois, sans droits admin).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause
