@echo off
REM AuthGraph lab — run on DC (as Domain Admin)
powershell -ExecutionPolicy Bypass -File "%~dp0Collect-LabSnapshot.ps1" -OutputPath C:\AuthGraph\out\dc-snapshot.json -ClientHostname CLIENT01
"%~dp0..\forwarder\bin\Release\net8.0\AuthGraphForwarder.exe" C:\AuthGraph\out\dc-snapshot.json http://YOUR_BACKEND_IP:8000
