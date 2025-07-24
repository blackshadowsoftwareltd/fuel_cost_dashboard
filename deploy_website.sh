#!/bin/bash

# Multi-Server Fuel Cost Dashboard Deployment Script
# VPS IP: 159.198.32.51
# Dashboard URL: fuelcost_dashboard.blackshadow.software
# API URL: fuelcost.blackshadow.software

set -e

echo "🚀 Starting Multi-Server Fuel Cost deployment..."

# Configuration
VPS_IP="159.198.32.51"
DASHBOARD_URL="fuelcost_dashboard.blackshadow.software"
API_URL="fuelcost.blackshadow.software"

# Check and fix conflicting services
print_status "Checking for conflicting services..."

# Stop conflicting Node.js service if running
if systemctl is-active --quiet fuel_cost_dashboard.service 2>/dev/null; then
    print_warning "Stopping conflicting fuel_cost_dashboard.service..."
    sudo systemctl stop fuel_cost_dashboard.service
    sudo systemctl disable fuel_cost_dashboard.service
    print_status "Conflicting service stopped"
fi

# Check port 8890 usage
port_usage=$(sudo netstat -tlnp | grep :8890 || echo "")
if [ ! -z "$port_usage" ]; then
    print_warning "Port 8890 is still in use:"
    echo "$port_usage"
else
    print_status "Port 8890 is free"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[DEPLOY]${NC} $1"
}

# Check if required files exist
print_status "Checking required files..."
required_files=("index.html" "Dockerfile.nginx" "nginx.conf" "nginx-proxy.conf" "docker-compose.multi-server.yml")

for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        print_error "Required file $file not found!"
        exit 1
    fi
done

print_status "All required files found ✓"

# Show current running containers
print_info "Current running containers:"
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"

echo ""
print_warning "This will deploy all servers using a reverse proxy setup:"
echo "  📊 Dashboard: http://${DASHBOARD_URL}"
echo "  🔌 API:       http://${API_URL}"
echo "  🌐 Both accessible on port 80 simultaneously"
echo "  ✅ Your existing servers will continue running"
echo ""

read -p "Continue with deployment? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_error "Deployment cancelled by user"
    exit 1
fi

# Stop any existing deployment
print_status "Stopping existing fuel cost services..."
docker-compose -f docker-compose.multi-server.yml down 2>/dev/null || true
docker-compose -f docker-compose.dashboard.yml down 2>/dev/null || true

# Create docker network if it doesn't exist
print_status "Setting up Docker network..."
docker network create fuel-network 2>/dev/null || print_warning "Network fuel-network already exists"

# Build and start all services
print_status "Building Docker images..."
docker-compose -f docker-compose.multi-server.yml build --no-cache

print_status "Starting all services..."
docker-compose -f docker-compose.multi-server.yml up -d

# Wait for containers to be ready
print_status "Waiting for services to be ready..."
sleep 10

# Check if all containers are running
print_status "Checking service status..."
running_containers=$(docker-compose -f docker-compose.multi-server.yml ps --services --filter "status=running" | wc -l)
total_services=2

if [ "$running_containers" -eq "$total_services" ]; then
    print_status "✅ All services deployed successfully!"
    echo ""
    echo "🌐 Your applications are now accessible:"
    echo "  📊 Dashboard: http://${DASHBOARD_URL}"
    echo "  🔌 API:       http://${API_URL}"
    echo "  🖥️  Local:     http://localhost (will route based on domain)"
    echo ""
    print_info "Service containers:"
    docker-compose -f docker-compose.multi-server.yml ps
    echo ""
    print_status "Useful commands:"
    echo "  📋 View logs:      docker-compose -f docker-compose.multi-server.yml logs -f"
    echo "  🔄 Restart:        docker-compose -f docker-compose.multi-server.yml restart"
    echo "  🛑 Stop all:       docker-compose -f docker-compose.multi-server.yml down"
    echo "  📊 View status:    docker-compose -f docker-compose.multi-server.yml ps"
else
    print_error "❌ Some services failed to start!"
    print_error "Running containers: $running_containers/$total_services"
    echo ""
    print_error "Check logs for issues:"
    docker-compose -f docker-compose.multi-server.yml logs
    exit 1
fi

print_status "🎉 Multi-server deployment completed successfully!"
print_info "Both your dashboard and API are now running simultaneously on port 80!"