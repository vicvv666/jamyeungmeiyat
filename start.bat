@echo off
echo 🍺 今晚飲咗未 — 啟動中...
cd /d "%~dp0"
set PYTHONHOME=
set PYTHONPATH=
pip install flask -q
python app.py
pause