# CA Lab - SQL Injection Demonstration Environment

## ⚠️ CRITICAL SECURITY WARNING

**THIS LAB ENVIRONMENT CONTAINS INTENTIONALLY VULNERABLE CODE FOR EDUCATIONAL PURPOSES ONLY.**

- **DO NOT** deploy this application in production or on any public network
- **DO NOT** expose this environment to the internet
- **ONLY** run this lab in an isolated VM with no external network access
- **ONLY** test on systems you own or have explicit written permission to test

### Legal Disclaimer
This lab environment is provided for educational purposes only. Unauthorized testing of systems you do not own is illegal and may result in criminal charges. Only use this lab on systems you own or have explicit written permission to test.

## What This Lab Demonstrates

This Docker-based lab environment provides:

1. **MySQL 8.0 Database** with seed data containing intentionally weak passwords
2. **Flask Web Application** with both vulnerable and secure endpoints
3. **SQL Injection Vulnerabilities** for hands-on testing and learning
4. **Secure Countermeasures** showing proper parameterized query implementation

## Quick Start

### Prerequisites
- Docker and Docker Compose installed
- Isolated VM or host-only network environment
- No conflicting services on ports 3307 (MySQL) and 8080 (Web)

### Build and Run

```bash
# Clone or extract the lab files
cd ca_lab_db

# Build and start the lab environment
docker compose up --build -d

# Check if services are running
docker compose ps

# View logs to ensure everything started correctly
docker compose logs -f
```

### Access the Application

1. **Web Interface**: Open http://localhost:8080 in your browser
2. **Database**: Connect to localhost:3307 (username: vuln_user, password: vuln_pass123)

### Wait for Database Initialization

The MySQL container may take 30-60 seconds to fully initialize. Check logs:

```bash
# Watch database initialization
docker compose logs db

# Wait for "ready for connections" message
docker compose logs db | grep "ready for connections"
```

## Testing SQL Injection

### Vulnerable Endpoint: `/vuln/login`

This endpoint is intentionally vulnerable to SQL injection. Test with these payloads:

#### Classic Bypass
```
Username: admin' OR '1'='1' --
Password: anything
```

#### Boolean-based Injection
```
Username: admin' AND '1'='1' --
Password: anything
```

#### UNION-based Injection
```
Username: ' UNION SELECT 1,username,password,email,role,created_at FROM users WHERE '1'='1
Password: anything
```

#### Time-based Injection
```
Username: admin'; SELECT SLEEP(5); --
Password: anything
```

### Safe Endpoint: `/safe/login`

The same payloads should **FAIL** on the safe endpoint, which uses parameterized queries.

### Expected Results

- **Vulnerable endpoint**: Should allow login bypass with injection payloads
- **Safe endpoint**: Should reject all injection attempts and require valid credentials
- **Valid credentials**: 
  - admin/admin123
  - john/password
  - jane/123456

## Data Export Commands

### Export Database to CSV

```bash
# Export users table to CSV
docker exec ca_lab_mysql mysql -u vuln_user -pvuln_pass123 ca_vuln_db -e "SELECT * FROM users;" | sed 's/\t/,/g' > users_export.csv

# Export products table to CSV
docker exec ca_lab_mysql mysql -u vuln_user -pvuln_pass123 ca_vuln_db -e "SELECT * FROM products;" | sed 's/\t/,/g' > products_export.csv

# Export all tables
docker exec ca_lab_mysql mysqldump -u vuln_user -pvuln_pass123 ca_vuln_db > full_database_export.sql
```

### Export to JSON

```bash
# Create a Python script to export to JSON
docker exec ca_lab_web python -c "
import mysql.connector
import json
import os

config = {
    'host': 'db',
    'port': 3306,
    'database': 'ca_vuln_db',
    'user': 'vuln_user',
    'password': 'vuln_pass123'
}

conn = mysql.connector.connect(**config)
cursor = conn.cursor(dictionary=True)

cursor.execute('SELECT * FROM users')
users = cursor.fetchall()

cursor.execute('SELECT * FROM products')
products = cursor.fetchall()

cursor.execute('SELECT * FROM orders')
orders = cursor.fetchall()

data = {
    'users': users,
    'products': products,
    'orders': orders
}

with open('/tmp/export.json', 'w') as f:
    json.dump(data, f, indent=2, default=str)

print('JSON export completed')
"

# Copy JSON file from container to host
docker cp ca_lab_web:/tmp/export.json ./database_export.json
```

## Management Commands

### Stop the Lab
```bash
docker compose down
```

### Reset Database (Remove All Data)
```bash
docker compose down -v
docker compose up --build -d
```

### View Logs
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f web
docker compose logs -f db
```

### Access Database Directly
```bash
# Connect to MySQL
docker exec -it ca_lab_mysql mysql -u vuln_user -pvuln_pass123 ca_vuln_db

# Run SQL commands
docker exec ca_lab_mysql mysql -u vuln_user -pvuln_pass123 ca_vuln_db -e "SHOW TABLES;"
```

### Remove Everything
```bash
# Stop and remove containers, networks, and volumes
docker compose down -v --rmi all

# Remove any remaining images
docker rmi ca_lab_db-web
```

## Security Remediation Notes

### What Makes the Vulnerable Endpoint Unsafe

1. **String Concatenation**: Building SQL queries by concatenating user input
2. **No Input Validation**: Accepting any input without sanitization
3. **No Parameterization**: Not using prepared statements

### Secure Implementation (Safe Endpoint)

1. **Parameterized Queries**: Using `%s` placeholders with parameter binding
2. **Input Validation**: Validating required fields
3. **Proper Error Handling**: Not exposing database errors to users

### Additional Security Recommendations

1. **Least Privilege**: Create database user with minimal required permissions
2. **Input Validation**: Implement comprehensive input validation and sanitization
3. **Error Handling**: Don't expose internal errors to users
4. **Logging**: Log security events and failed authentication attempts
5. **Rate Limiting**: Implement rate limiting to prevent brute force attacks
6. **HTTPS**: Use HTTPS in production environments
7. **Regular Updates**: Keep all dependencies updated

## CA Report Checklist

Capture screenshots/evidence of:

- [ ] Lab environment startup and initialization
- [ ] Web interface showing vulnerable and safe endpoints
- [ ] Successful SQL injection on vulnerable endpoint
- [ ] Failed SQL injection on safe endpoint
- [ ] Database structure and seed data
- [ ] Exported CSV/JSON data
- [ ] Network isolation verification (no external access)
- [ ] Remediation recommendations implementation

## Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Check what's using the ports
netstat -tulpn | grep :3307
netstat -tulpn | grep :8080

# Kill processes if needed (be careful!)
sudo kill -9 <PID>
```

#### Database Connection Failed
```bash
# Check if MySQL container is healthy
docker compose ps

# Check MySQL logs
docker compose logs db

# Wait for initialization
docker compose logs db | grep "ready for connections"
```

#### Web Application Not Loading
```bash
# Check web container logs
docker compose logs web

# Verify database connectivity
docker exec ca_lab_web python -c "
import mysql.connector
try:
    conn = mysql.connector.connect(host='db', user='vuln_user', password='vuln_pass123', database='ca_vuln_db')
    print('Database connection successful')
    conn.close()
except Exception as e:
    print(f'Database connection failed: {e}')
"
```

#### Permission Denied Errors
```bash
# Fix file permissions
chmod +x app/app.py
chmod 644 init_db.sql
```

### Reset Everything
```bash
# Nuclear option - remove everything and start fresh
docker compose down -v --rmi all
docker system prune -f
docker compose up --build -d
```

## Package as ZIP

To create a distributable ZIP file:

```bash
# Create ZIP package (run from parent directory)
zip -r ca_lab_db.zip ca_lab_db/ -x "ca_lab_db/.git/*" "ca_lab_db/__pycache__/*" "ca_lab_db/*.log"
```

## Final Reminders

- **NEVER** deploy this in production
- **ONLY** run in isolated environments
- **ALWAYS** use secure practices in real applications
- **DOCUMENT** your findings for the CA report
- **TEST** both vulnerable and safe endpoints thoroughly

Happy learning! 🎓
