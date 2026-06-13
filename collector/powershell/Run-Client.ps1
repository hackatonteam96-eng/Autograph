@echo off
REM AuthGraph lab — run on client
powershell -ExecutionPolicy Bypass -File "%~dp0Collect-ClientSnapshot.ps1" -OutputPath C:\AuthGraph\out\client-snapshot.json
"%~dp0..\forwarder\bin\Release\net8.0\AuthGraphForwarder.exe" C:\AuthGraph\out\client-snapshot.json http://YOUR_BACKEND_IP:8000
