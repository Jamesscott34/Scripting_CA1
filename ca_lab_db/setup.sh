#!/bin/bash

# CA Lab Setup Script
# This script helps you get started with the SQL Injection Lab Environment

echo "🔒 CA Lab - SQL Injection Demonstration Environment Setup"
echo "=========================================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    echo "Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Check if ports are available
echo "🔍 Checking port availability..."
if netstat -tulpn 2>/dev/null | grep -q ":3307"; then
    echo "⚠️  Port 3307 is already in use. You may need to stop the conflicting service."
fi

if netstat -tulpn 2>/dev/null | grep -q ":8080"; then
    echo "⚠️  Port 8080 is already in use. You may need to stop the conflicting service."
fi

echo ""
echo "🚀 Starting the lab environment..."
echo ""

# Build and start the containers
docker compose up --build -d

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Lab environment started successfully!"
    echo ""
    echo "📋 Next Steps:"
    echo "1. Wait 30-60 seconds for database initialization"
    echo "2. Open http://localhost:8080 in your browser"
    echo "3. Test the vulnerable and safe endpoints"
    echo ""
    echo "📊 Useful Commands:"
    echo "  View logs:        docker compose logs -f"
    echo "  Stop lab:         docker compose down"
    echo "  Reset database:   docker compose down -v && docker compose up -d"
    echo "  Access database:  docker exec -it ca_lab_mysql mysql -u vuln_user -pvuln_pass123 ca_vuln_db"
    echo ""
    echo "⚠️  SECURITY REMINDER:"
    echo "   This lab contains intentionally vulnerable code for educational purposes only."
    echo "   Only run in isolated VMs with no external network access."
    echo ""
else
    echo "❌ Failed to start the lab environment. Check the logs:"
    echo "   docker compose logs"
    exit 1
fi
