#!/bin/bash
echo "🍺 今晚飲咗未 — 啟動中..."
cd "$(dirname "$0")"
unset PYTHONHOME
unset PYTHONPATH
pip install flask -q
python app.py