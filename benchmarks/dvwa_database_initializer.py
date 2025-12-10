#!/usr/bin/env python3
"""
DVWA Database Initializer
Automates DVWA database initialization to ensure vulnerabilities exist
Multiple approaches: HTTP POST, subprocess call to shell script
"""

import requests
from bs4 import BeautifulSoup
import subprocess
import time
import sys


class DVWADatabaseInitializer:
    """Handles DVWA database initialization"""

    def __init__(self, dvwa_url: str = "http://localhost:8080"):
        """
        Initialize DVWA database initializer

        Args:
            dvwa_url: DVWA base URL
        """
        self.dvwa_url = dvwa_url
        self.setup_url = f"{dvwa_url}/setup.php"
        self.session = requests.Session()

    def check_dvwa_accessible(self) -> bool:
        """
        Check if DVWA is accessible

        Returns:
            True if DVWA is reachable
        """
        try:
            response = self.session.get(self.dvwa_url, timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"  ✗ DVWA not accessible: {e}")
            return False

    def initialize_via_http(self) -> bool:
        """
        Initialize database via HTTP POST to setup.php

        Returns:
            True if successful
        """
        print("\n[Method 1] Initializing DVWA database via HTTP...")

        try:
            # Step 1: GET setup page
            print("  → Accessing setup page...")
            response = self.session.get(self.setup_url)

            if response.status_code != 200:
                print(f"  ✗ Setup page returned {response.status_code}")
                return False

            # Step 2: Parse page for CSRF token if present
            soup = BeautifulSoup(response.text, 'html.parser')
            user_token_input = soup.find('input', {'name': 'user_token'})

            data = {'create_db': 'Create / Reset Database'}
            if user_token_input and user_token_input.get('value'):
                user_token = user_token_input['value']
                data['user_token'] = user_token
                print(f"  → Found CSRF token: {user_token[:20]}...")

            # Step 3: POST to create database
            print("  → Submitting database creation request...")
            response = self.session.post(self.setup_url, data=data, allow_redirects=True)

            # Step 4: Check for success indicators
            success_patterns = [
                'database has been created',
                'setup successful',
                'database setup',
                'login.php'  # Redirects to login after successful setup
            ]

            response_lower = response.text.lower()
            if any(pattern in response_lower for pattern in success_patterns):
                print("  ✓ Database initialization successful (HTTP)")
                return True

            # Check if we're redirected to login (success)
            if 'login.php' in response.url:
                print("  ✓ Database initialization successful (redirected to login)")
                return True

            print(f"  ⚠ Unexpected response, checking database status...")
            return self.verify_database_initialized()

        except Exception as e:
            print(f"  ✗ HTTP initialization failed: {e}")
            return False

    def initialize_via_shell_script(self) -> bool:
        """
        Initialize database via existing shell script

        Returns:
            True if successful
        """
        print("\n[Method 2] Initializing DVWA database via shell script...")

        script_paths = [
            './init_dvwa_db.sh',
            './benchmarks/init_dvwa_database.py',
            './setup_dvwa_db.py',
            './setup_dvwa.sh'
        ]

        for script_path in script_paths:
            try:
                print(f"  → Trying {script_path}...")
                result = subprocess.run(
                    [script_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    print(f"  ✓ Database initialization successful via {script_path}")
                    return True
                else:
                    print(f"  ⚠ Script exited with code {result.returncode}")

            except FileNotFoundError:
                continue
            except Exception as e:
                print(f"  ✗ Script failed: {e}")
                continue

        print("  ✗ No working shell scripts found")
        return False

    def initialize_via_docker_exec(self) -> bool:
        """
        Initialize database via docker exec (direct MySQL commands)

        Returns:
            True if successful
        """
        print("\n[Method 3] Initializing DVWA database via Docker exec...")

        try:
            # Check if dvwa container exists
            result = subprocess.run(
                ['docker', 'ps', '--filter', 'name=dvwa', '--format', '{{.Names}}'],
                capture_output=True,
                text=True
            )

            if 'dvwa' not in result.stdout:
                print("  ✗ DVWA container not found")
                return False

            # Execute MySQL commands directly
            print("  → Executing MySQL setup via Docker...")

            # SQL commands to initialize DVWA
            sql_commands = """
            CREATE DATABASE IF NOT EXISTS dvwa;
            USE dvwa;
            CREATE TABLE IF NOT EXISTS users (
                user_id int NOT NULL AUTO_INCREMENT,
                first_name varchar(15),
                last_name varchar(15),
                user varchar(15),
                password varchar(32),
                avatar varchar(70),
                last_login timestamp,
                failed_login int,
                PRIMARY KEY (user_id)
            );
            INSERT IGNORE INTO users (user_id, first_name, last_name, user, password, avatar) VALUES
            (1, 'admin', 'admin', 'admin', '5f4dcc3b5aa765d61d8327deb882cf99', 'http://www.gravatar.com/avatar/'),
            (2, 'Gordon', 'Brown', 'gordonb', 'e99a18c428cb38d5f260853678922e03', 'http://www.gravatar.com/avatar/'),
            (3, 'Hack', 'Me', 'hackme', '0d107d09f5bbe40cade3de5c71e9e9b7', 'http://www.gravatar.com/avatar/'),
            (4, 'Pablo', 'Picasso', 'pablo', '0d107d09f5bbe40cade3de5c71e9e9b7', 'http://www.gravatar.com/avatar/'),
            (5, 'Bob', 'Smith', 'smithy', '5f4dcc3b5aa765d61d8327deb882cf99', 'http://www.gravatar.com/avatar/');
            """

            # Execute via docker exec
            result = subprocess.run(
                ['docker', 'exec', '-i', 'dvwa', 'mysql', '-uroot', '-pdvwa'],
                input=sql_commands,
                capture_output=True,
                text=True,
                timeout=15
            )

            if result.returncode == 0:
                print("  ✓ Database initialization successful (Docker exec)")
                return True
            else:
                print(f"  ✗ MySQL commands failed: {result.stderr}")
                return False

        except Exception as e:
            print(f"  ✗ Docker exec failed: {e}")
            return False

    def verify_database_initialized(self) -> bool:
        """
        Verify that DVWA database is properly initialized

        Returns:
            True if database is initialized
        """
        try:
            # Try to login (if login works, database is initialized)
            response = self.session.get(f"{self.dvwa_url}/login.php")

            # Check for login form presence
            if 'username' in response.text.lower() and 'password' in response.text.lower():
                print("  ✓ Database appears to be initialized (login page accessible)")
                return True

            # Try to access a vulnerable page (would redirect to setup if not initialized)
            response = self.session.get(f"{self.dvwa_url}/vulnerabilities/sqli/")
            if 'setup.php' in response.url:
                print("  ✗ Database not initialized (redirected to setup)")
                return False

            return True

        except Exception as e:
            print(f"  ⚠ Verification failed: {e}")
            return False

    def initialize(self, methods: list = None) -> bool:
        """
        Initialize DVWA database using multiple methods (fallback chain)

        Args:
            methods: List of method names to try (in order)
                     Default: ['http', 'shell', 'docker']

        Returns:
            True if any method succeeds
        """
        if methods is None:
            methods = ['http', 'shell', 'docker']

        print("="*80)
        print("DVWA DATABASE INITIALIZATION")
        print("="*80)

        # Check if DVWA is accessible
        if not self.check_dvwa_accessible():
            print("\n✗ DVWA is not accessible. Ensure containers are running:")
            print("  docker-compose up -d")
            return False

        # Try each method in order
        method_functions = {
            'http': self.initialize_via_http,
            'shell': self.initialize_via_shell_script,
            'docker': self.initialize_via_docker_exec
        }

        for method in methods:
            if method in method_functions:
                if method_functions[method]():
                    # Verify initialization
                    time.sleep(2)  # Give database time to settle
                    if self.verify_database_initialized():
                        print(f"\n{'='*80}")
                        print(f"✓ DVWA DATABASE READY")
                        print(f"{'='*80}\n")
                        return True

        # All methods failed
        print(f"\n{'='*80}")
        print("✗ ALL INITIALIZATION METHODS FAILED")
        print(f"{'='*80}")
        print("\nManual steps:")
        print("  1. Open browser to http://localhost:8080/setup.php")
        print("  2. Click 'Create / Reset Database'")
        print("  3. Wait for success message")
        print(f"{'='*80}\n")

        return False


def main():
    """Initialize DVWA database"""
    initializer = DVWADatabaseInitializer()

    # Try to initialize
    success = initializer.initialize()

    if success:
        print("\n✓ Database is ready for scanning")
        sys.exit(0)
    else:
        print("\n✗ Database initialization failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
