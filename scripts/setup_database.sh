#!/bin/bash
# ============================================================
# SPAZE — Database Setup Script
# Creates the PostgreSQL database and user for the SPAZE server.
#
# Run once: sudo bash scripts/setup_database.sh
# ============================================================

set -e

DB_NAME="spaze"
DB_USER="spaze_user"
DB_PASS="spaze_pass"

echo "============================================"
echo "  SPAZE Database Setup"
echo "============================================"
echo ""

# Must be run as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run with sudo:"
    echo "   sudo bash scripts/setup_database.sh"
    exit 1
fi

echo "[1/3] Creating PostgreSQL database..."
if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    echo "  ⚠️  Database '$DB_NAME' already exists, skipping"
else
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;"
    echo "  ✅ Database '$DB_NAME' created"
fi

echo ""
echo "[2/3] Creating database user..."
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
    echo "  ⚠️  User '$DB_USER' already exists, updating password"
    sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASS';"
else
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
    echo "  ✅ User '$DB_USER' created"
fi

echo ""
echo "[3/3] Granting privileges..."
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL ON SCHEMA public TO $DB_USER;"
echo "  ✅ Privileges granted"

echo ""
echo "============================================"
echo "  ✅ Database Setup Complete!"
echo "============================================"
echo ""
echo "Database:  $DB_NAME"
echo "User:      $DB_USER"
echo "Password:  $DB_PASS"
echo "URL:       postgresql+asyncpg://$DB_USER:$DB_PASS@localhost:5432/$DB_NAME"
echo ""
echo "Start the server:"
echo "  cd ~/Documents/MajorProject"
echo "  source venv/bin/activate"
echo "  uvicorn server.main:app --reload"
echo ""
