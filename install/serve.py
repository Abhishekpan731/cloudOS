#!/usr/bin/env python3
"""
Simple HTTP server for testing install endpoint locally
Usage: python3 serve.py [port]
"""

import http.server
import socketserver
import sys
import os
from pathlib import Path

# Change to install directory
os.chdir(Path(__file__).parent)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

class InstallHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Route root to install.sh
        if self.path == '/':
            self.path = '/install.sh'
        elif self.path == '/latest':
            self.path = '/latest.sh'

        return super().do_GET()

with socketserver.TCPServer(("", PORT), InstallHandler) as httpd:
    print(f"Serving CloudOS install endpoint at http://localhost:{PORT}")
    print(f"Test with: curl -sSL http://localhost:{PORT} | bash")
    httpd.serve_forever()
