#!/usr/bin/env python3
"""
CA Lab Flask Application - SQL Injection Demonstration
WARNING: This application contains intentionally vulnerable code for educational purposes only.
DO NOT deploy this application in production or on any public network.

This application demonstrates:
- Vulnerable SQL injection endpoints (intentionally unsafe)
- Safe parameterized query endpoints (secure implementation)
- Database connection handling
- Error handling and logging

Author: CA Lab Environment
Purpose: Educational demonstration of SQL injection vulnerabilities and defenses
"""

import os
import mysql.connector
from flask import Flask, request, render_template_string, jsonify
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Database configuration from environment variables
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 3306)),
    "database": os.getenv("DB_NAME", "ca_vuln_db"),
    "user": os.getenv("DB_USER", "vuln_user"),
    "password": os.getenv("DB_PASS", "vuln_pass123"),
    "autocommit": True,
}


def get_db_connection():
    """Create and return a database connection"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except mysql.connector.Error as err:
        logger.error(f"Database connection error: {err}")
        return None


# HTML template for the main page
MAIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CA Lab - SQL Injection Demonstration</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .warning { background: #ffebee; border: 1px solid #f44336; padding: 15px; margin: 20px 0; }
        .safe { background: #e8f5e8; border: 1px solid #4caf50; padding: 15px; margin: 20px 0; }
        .vuln { background: #fff3e0; border: 1px solid #ff9800; padding: 15px; margin: 20px 0; }
        form { margin: 20px 0; }
        input, button { padding: 10px; margin: 5px; }
        pre { background: #f5f5f5; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>CA Lab - SQL Injection Demonstration</h1>
    
    <div class="warning">
        <h2>⚠️ SECURITY WARNING</h2>
        <p><strong>This application contains intentionally vulnerable code for educational purposes only.</strong></p>
        <p>DO NOT deploy this application in production or on any public network.</p>
        <p>Only run this lab in an isolated VM with no external network access.</p>
    </div>

    <h2>Available Endpoints</h2>
    
    <div class="vuln">
        <h3>🔴 Vulnerable Endpoints (Intentionally Unsafe)</h3>
        <p><strong>/vuln/login</strong> - Login form vulnerable to SQL injection</p>
        <p>This endpoint builds SQL queries using string concatenation, making it vulnerable to injection attacks.</p>
    </div>
    
    <div class="safe">
        <h3>🟢 Safe Endpoints (Secure Implementation)</h3>
        <p><strong>/safe/login</strong> - Login form using parameterized queries</p>
        <p>This endpoint uses prepared statements to prevent SQL injection attacks.</p>
    </div>
    
    <div>
        <h3>📊 Data Endpoints</h3>
        <p><strong>/users</strong> - List all users (for testing output-based injection)</p>
    </div>

    <h2>Test the Vulnerable Login</h2>
    <form action="/vuln/login" method="POST">
        <h3>Vulnerable Login Form</h3>
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login (Vulnerable)</button>
    </form>

    <h2>Test the Safe Login</h2>
    <form action="/safe/login" method="POST">
        <h3>Safe Login Form</h3>
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login (Safe)</button>
    </form>

    <h2>Sample Test Payloads</h2>
    <div class="vuln">
        <h3>SQL Injection Test Payloads (for vulnerable endpoint only):</h3>
        <pre>
Username: admin' OR '1'='1' --
Password: anything

Username: admin' OR '1'='1' OR ''='
Password: anything

Username: ' UNION SELECT 1,username,password,email,role,created_at FROM users WHERE '1'='1
Password: anything

Username: admin'; DROP TABLE users; --
Password: anything
        </pre>
    </div>
</body>
</html>
"""


@app.route("/")
def index():
    """Main page with links to vulnerable and safe endpoints"""
    return render_template_string(MAIN_TEMPLATE)


@app.route("/vuln/login", methods=["GET", "POST"])
def vulnerable_login():
    """
    VULNERABLE LOGIN ENDPOINT - Intentionally unsafe for demonstration

    This endpoint is vulnerable to SQL injection because it builds queries
    using string concatenation without proper sanitization.

    DO NOT use this pattern in production code!
    """
    if request.method == "GET":
        return render_template_string(
            """
        <h1>Vulnerable Login</h1>
        <div class="vuln">
            <p><strong>WARNING:</strong> This endpoint is intentionally vulnerable to SQL injection!</p>
        </div>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <a href="/">← Back to main page</a>
        """
        )

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username or not password:
        return "Username and password are required", 400

    connection = get_db_connection()
    if not connection:
        return "Database connection failed", 500

    try:
        cursor = connection.cursor()

        # VULNERABLE CODE: String concatenation - DO NOT USE IN PRODUCTION
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        logger.warning(f"Executing vulnerable query: {query}")

        cursor.execute(query)
        result = cursor.fetchone()

        if result:
            return f"""
            <h1>Login Successful (Vulnerable Endpoint)</h1>
            <div class="vuln">
                <p><strong>WARNING:</strong> This login was successful due to SQL injection vulnerability!</p>
                <p>User: {result[1]} (Role: {result[4]})</p>
                <p>Query executed: {query}</p>
            </div>
            <a href="/">← Back to main page</a>
            """
        else:
            return f"""
            <h1>Login Failed (Vulnerable Endpoint)</h1>
            <div>
                <p>Invalid credentials</p>
                <p>Query executed: {query}</p>
            </div>
            <a href="/">← Back to main page</a>
            """

    except mysql.connector.Error as err:
        logger.error(f"Database error: {err}")
        return f"Database error: {err}", 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()


@app.route("/safe/login", methods=["GET", "POST"])
def safe_login():
    """
    SAFE LOGIN ENDPOINT - Secure implementation using parameterized queries

    This endpoint uses prepared statements to prevent SQL injection attacks.
    This is the correct way to handle user input in database queries.
    """
    if request.method == "GET":
        return render_template_string(
            """
        <h1>Safe Login</h1>
        <div class="safe">
            <p><strong>SECURE:</strong> This endpoint uses parameterized queries to prevent SQL injection.</p>
        </div>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <a href="/">← Back to main page</a>
        """
        )

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username or not password:
        return "Username and password are required", 400

    connection = get_db_connection()
    if not connection:
        return "Database connection failed", 500

    try:
        cursor = connection.cursor()

        # SAFE CODE: Parameterized query - USE THIS IN PRODUCTION
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        logger.info(f"Executing safe parameterized query for user: {username}")

        cursor.execute(query, (username, password))
        result = cursor.fetchone()

        if result:
            return f"""
            <h1>Login Successful (Safe Endpoint)</h1>
            <div class="safe">
                <p><strong>SECURE:</strong> This login was successful using proper authentication.</p>
                <p>User: {result[1]} (Role: {result[4]})</p>
                <p>Query executed: {query} with parameters: ({username}, {password})</p>
            </div>
            <a href="/">← Back to main page</a>
            """
        else:
            return f"""
            <h1>Login Failed (Safe Endpoint)</h1>
            <div>
                <p>Invalid credentials</p>
                <p>Query executed: {query} with parameters: ({username}, {password})</p>
            </div>
            <a href="/">← Back to main page</a>
            """

    except mysql.connector.Error as err:
        logger.error(f"Database error: {err}")
        return f"Database error: {err}", 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()


@app.route("/users")
def list_users():
    """
    List all users - for testing output-based SQL injection

    This endpoint displays all users in the database and can be used
    to test UNION-based SQL injection attacks.
    """
    connection = get_db_connection()
    if not connection:
        return "Database connection failed", 500

    try:
        cursor = connection.cursor()
        cursor.execute("SELECT id, username, email, role, created_at FROM users")
        users = cursor.fetchall()

        html = """
        <h1>Users List</h1>
        <div>
            <p>This endpoint lists all users in the database.</p>
            <p>Can be used for testing UNION-based SQL injection attacks.</p>
        </div>
        <table border="1" style="border-collapse: collapse; width: 100%;">
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Created At</th>
            </tr>
        """

        for user in users:
            html += f"""
            <tr>
                <td>{user[0]}</td>
                <td>{user[1]}</td>
                <td>{user[2]}</td>
                <td>{user[3]}</td>
                <td>{user[4]}</td>
            </tr>
            """

        html += """
        </table>
        <br>
        <a href="/">← Back to main page</a>
        """

        return html

    except mysql.connector.Error as err:
        logger.error(f"Database error: {err}")
        return f"Database error: {err}", 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()


@app.route("/api/users")
def api_users():
    """API endpoint to return users as JSON"""
    connection = get_db_connection()
    if not connection:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, username, email, role, created_at FROM users")
        users = cursor.fetchall()
        return jsonify(users)

    except mysql.connector.Error as err:
        logger.error(f"Database error: {err}")
        return jsonify({"error": str(err)}), 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()


if __name__ == "__main__":
    logger.info("Starting CA Lab Flask application...")
    logger.info("WARNING: This application contains intentionally vulnerable code!")
    logger.info("Only run in isolated environments for educational purposes.")
    app.run(host="0.0.0.0", port=8080, debug=False)
