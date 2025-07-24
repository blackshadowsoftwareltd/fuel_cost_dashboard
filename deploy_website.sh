#!/bin/bash

# Fuel Cost Dashboard Deployment Script
# VPS IP: 159.198.32.51
# Site URL: fuelcost_dashboard.blackshadow.software

set -e

echo "🚀 Starting Fuel Cost Dashboard deployment..."

# Configuration
VPS_IP="159.198.32.51"
PROJECT_NAME="fuel_cost_dashboard"
SITE_URL="fuelcost_dashboard.blackshadow.software"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Check if required files exist
print_status "Checking required files..."
required_files=("index.html" "Dockerfile.nginx" "nginx.conf" "docker-compose.dashboard.yml")

for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        print_error "Required file $file not found!"
        exit 1
    fi
done

print_status "All required files found ✓"

# Create docker network if it doesn't exist
print_status "Creating Docker network..."
docker network create fuel-network 2>/dev/null || print_warning "Network fuel-network already exists"

# Stop existing container if running
print_status "Stopping existing containers..."
docker-compose -f docker-compose.dashboard.yml down 2>/dev/null || true

# Build and start the dashboard
print_status "Building Docker image..."
docker-compose -f docker-compose.dashboard.yml build --no-cache

print_status "Starting the dashboard..."
docker-compose -f docker-compose.dashboard.yml up -d

# Wait for container to be ready
print_status "Waiting for container to be ready..."
sleep 5

# Check if container is running
if docker ps | grep -q fuel_cost_dashboard; then
    print_status "✅ Dashboard deployed successfully!"
    echo ""
    echo "🌐 Dashboard URL: http://${SITE_URL}"
    echo "🌐 Local access: http://localhost"
    echo "🐳 Container: fuel_cost_dashboard"
    echo ""
    print_status "Container status:"
    docker ps | grep fuel_cost_dashboard
    echo ""
    print_status "To view logs: docker logs fuel_cost_dashboard"
    print_status "To stop: docker-compose -f docker-compose.dashboard.yml down"
else
    print_error "❌ Deployment failed! Container is not running."
    print_error "Check logs with: docker logs fuel_cost_dashboard"
    exit 1
fi

print_status "🎉 Deployment completed successfully!"