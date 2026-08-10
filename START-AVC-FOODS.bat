@echo off
cd /d "%~dp0"
set "AVC_NODE=C:\Users\admin\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
if exist "%AVC_NODE%" (
  "%AVC_NODE%" server.js
) else (
  node server.js
)
pause
