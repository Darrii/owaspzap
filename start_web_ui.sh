#!/bin/bash

echo "🌐 Starting Vulnerability Chain Detection Web UI..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📡 Server will start on: http://localhost:8888"
echo ""
echo "⚠️  Prerequisites:"
echo "   - ZAP must be installed (brew install zaproxy)"
echo "   - Python 3.13+ with FastAPI, uvicorn, websockets"
echo ""
echo "🚀 Starting server..."
echo ""

python3 web_ui_app.py
