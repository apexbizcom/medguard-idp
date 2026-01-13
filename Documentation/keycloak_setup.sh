#!/bin/bash
# ============================================================================
# Keycloak Local Development Setup for ComplianceVault IDP
# ============================================================================
# This script sets up Keycloak as a local SAML Identity Provider
# for testing federated authentication with your IDP schema.
#
# Prerequisites:
#   - Docker Desktop installed and running
#   - Ports 8180 available (Keycloak)
#   - Your APEX/ORDS running on port 8080
#
# Usage:
#   chmod +x keycloak_setup.sh
#   ./keycloak_setup.sh
# ============================================================================

echo "=============================================="
echo "Keycloak Local Development Setup"
echo "=============================================="
echo ""

# Configuration
KEYCLOAK_PORT=8180
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin
REALM_NAME=compliancevault

echo "Starting Keycloak on port ${KEYCLOAK_PORT}..."
echo "Admin credentials: ${KEYCLOAK_ADMIN} / ${KEYCLOAK_ADMIN_PASSWORD}"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker is not running. Please start Docker Desktop first."
    exit 1
fi

# Stop existing Keycloak container if running
docker stop keycloak-dev 2>/dev/null
docker rm keycloak-dev 2>/dev/null

# Start Keycloak
docker run -d \
    --name keycloak-dev \
    -p ${KEYCLOAK_PORT}:8080 \
    -e KEYCLOAK_ADMIN=${KEYCLOAK_ADMIN} \
    -e KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD} \
    quay.io/keycloak/keycloak:latest \
    start-dev

echo ""
echo "Waiting for Keycloak to start (this takes about 30-60 seconds)..."
echo ""

# Wait for Keycloak to be ready
for i in {1..60}; do
    if curl -s http://localhost:${KEYCLOAK_PORT}/health/ready > /dev/null 2>&1; then
        echo "Keycloak is ready!"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "Timeout waiting for Keycloak. Check: docker logs keycloak-dev"
        exit 1
    fi
    sleep 2
    echo -n "."
done

echo ""
echo "=============================================="
echo "Keycloak is running!"
echo "=============================================="
echo ""
echo "Admin Console: http://localhost:${KEYCLOAK_PORT}/admin"
echo "Username: ${KEYCLOAK_ADMIN}"
echo "Password: ${KEYCLOAK_ADMIN_PASSWORD}"
echo ""
echo "Next steps:"
echo "1. Open the Admin Console URL above"
echo "2. Log in with admin credentials"
echo "3. Follow the setup guide to create realm and SAML client"
echo ""
echo "To stop Keycloak:  docker stop keycloak-dev"
echo "To start again:    docker start keycloak-dev"
echo "To view logs:      docker logs -f keycloak-dev"
echo "=============================================="
