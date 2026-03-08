#!/usr/bin/env bash
set -euo pipefail

# Vigil v1.0 — Quick Install Script
# Usage: curl -fsSL https://raw.githubusercontent.com/vigil-agency/vigil/main/install.sh | bash

REPO="https://github.com/vigil-agency/vigil.git"
DIR="vigil"
PORT="${VIGIL_PORT:-4100}"

echo ""
echo "  ╦  ╦╦╔═╗╦╦  "
echo "  ╚╗╔╝║║ ╦║║  "
echo "   ╚╝ ╩╚═╝╩╩═╝"
echo "  The Security Agency That Never Sleeps"
echo ""

# ── Check prerequisites ──────────────────────────────────────────
command -v node >/dev/null 2>&1 || {
  echo "Error: Node.js is required. Install from https://nodejs.org"
  exit 1
}

NODE_MAJOR=$(node -v | cut -d'.' -f1 | tr -d 'v')
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "Error: Node.js 18+ required (found $(node -v))"
  exit 1
fi

command -v npm >/dev/null 2>&1 || {
  echo "Error: npm is required"
  exit 1
}

command -v git >/dev/null 2>&1 || {
  echo "Error: git is required"
  exit 1
}

# ── Clone ─────────────────────────────────────────────────────────
if [ -d "$DIR" ]; then
  echo "Directory '$DIR' already exists. Pulling latest..."
  cd "$DIR"
  git pull --ff-only
else
  echo "Cloning Vigil..."
  git clone "$REPO" "$DIR"
  cd "$DIR"
fi

# ── Setup ─────────────────────────────────────────────────────────
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example"

  # Generate random admin password
  ADMIN_PASS=$(head -c 16 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 16)
  sed -i "s/VIGIL_PASS=admin/VIGIL_PASS=$ADMIN_PASS/" .env
  echo ""
  echo "  Generated admin password: $ADMIN_PASS"
  echo "  (saved in .env — change if desired)"
  echo ""
fi

# ── Install ───────────────────────────────────────────────────────
echo "Installing dependencies..."
npm install --production

# ── Check optional scanners ───────────────────────────────────────
echo ""
echo "Scanner availability:"
for tool in nmap nuclei trivy nikto openssl dig whois; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  ✓ $tool"
  else
    echo "  ✗ $tool (optional — install for full functionality)"
  fi
done

# ── Start ─────────────────────────────────────────────────────────
echo ""
echo "Starting Vigil on port $PORT..."
echo "  URL:  http://localhost:$PORT"
echo "  User: admin"
echo "  Pass: (see .env file)"
echo ""
echo "  Stop with Ctrl+C"
echo ""

node server.js
