#!/usr/bin/env python3
"""
Launcher for Vulnerability Chain Detection Web UI.

This script starts the web interface for analyzing ZAP reports
and detecting vulnerability chains.
"""

import sys
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from vulnerability_chains.web.app import start_server


def main():
    parser = argparse.ArgumentParser(
        description='Vulnerability Chain Detection Web Interface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start server on default port (8000)
  python run_web_ui.py

  # Start on custom port
  python run_web_ui.py --port 8080

  # Start on specific host
  python run_web_ui.py --host 127.0.0.1 --port 9000

Features:
  - Upload ZAP JSON reports
  - Automatic chain detection and analysis
  - Interactive dashboard with statistics
  - View and download HTML/JSON reports
  - Browse chain rules
  - Manage previous analyses

Access Points:
  - Dashboard: http://localhost:8000/
  - API Docs: http://localhost:8000/docs
  - Interactive API: http://localhost:8000/redoc
        """
    )

    parser.add_argument(
        '--host',
        type=str,
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0)'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='Port to bind to (default: 8000)'
    )

    args = parser.parse_args()

    # Start server
    start_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
