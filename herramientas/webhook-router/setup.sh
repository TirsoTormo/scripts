#!/usr/bin/env bash
# ======================================================================
# WEBHOOK GATEWAY - UNIX SETUP BOOTSTRAPPER (setup.sh)
# ======================================================================
# This script automates Python detection, venv creation, installing
# requirements, provisioning a secure .env with cryptography keys,
# and booting up the FastAPI ASGI server with 1 single command.
# ======================================================================

# Clear screen and format header
clear
echo -e "\033[33m======================================================================\033[0m"
echo -e "\033[33m 🛡️  WEBHOOK GATEWAY - AUTOMATED ALL-IN-ONE UNIX INSTALLER\033[0m"
echo -e "\033[33m======================================================================\033[0m"

# 1. Detect Python Interpreter
PYTHON_EXE=""
for cmd in python3 python py; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PYTHON_EXE="$cmd"
        break
    fi
done

if [ -z "$PYTHON_EXE" ]; then
    echo -e "\033[31m✖ Error: Python 3 was not found. Please install Python 3.10+ before running this script.\033[0m"
    exit 1
fi

echo -e "\033[32m✔ Found Python interpreter: $PYTHON_EXE\033[0m"

# 2. Setup Virtual Environment (venv)
if [ ! -d "venv" ]; then
    echo -e "\033[36m⌛ Creating Python virtual environment (venv)...\033[0m"
    $PYTHON_EXE -m venv venv
fi
echo -e "\033[32m✔ Virtual environment ready.\033[0m"

# 3. Upgrade Pip & Install Requirements
echo -e "\033[36m⌛ Upgrading pip and installing requirements...\033[0m"
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt
echo -e "\033[32m✔ All dependencies installed successfully.\033[0m"

# 4. Auto-Provision secure .env file
if [ ! -f ".env" ]; then
    echo -e "\033[36m⌛ Auto-provisioning secure .env configuration file...\033[0m"
    cp .env.example .env
    
    # Generate secure random token key (hexadecimal)
    if command -v openssl >/dev/null 2>&1; then
        TOKEN=$(openssl rand -hex 16)
    else
        TOKEN=$(date +%s | sha256sum | base64 | head -c 32)
    fi
    
    # Inject token directly into .env
    sed -i "s/GATEWAY_TOKEN=my_super_secure_secret_token/GATEWAY_TOKEN=$TOKEN/g" .env
    
    echo -e "\033[32m✔ Created .env with secure key: $TOKEN\033[0m"
else
    echo -e "\033[32m✔ Active .env configuration found. Retaining.\033[0m"
fi

# 5. Initialize hosts.yaml if missing
if [ ! -f "hosts.yaml" ]; then
    echo -e "\033[36m⌛ Creating default hosts.yaml registry...\033[0m"
    cat <<EOT > hosts.yaml
hosts:
  prod-db-01:
    host: "127.0.0.1"
    port: 22
    username: "admin"
EOT
    echo -e "\033[32m✔ Created hosts.yaml default registry.\033[0m"
fi

echo -e "\033[33m======================================================================\033[0m"
echo -e "\033[32m 🎉 UNIX SETUP COMPLETED SUCCESSFULLY!\033[0m"
echo -e "\033[33m======================================================================\033[0m"
echo -e "\033[36mWould you like to start the Webhook Gateway ASGI server now? (y/n)\033[0m"
read -r run_now

if [ "$run_now" = "y" ] || [ "$run_now" = "yes" ]; then
    echo -e "\033[32m🚀 Launching Webhook Gateway ASGI Server on http://localhost:8000...\033[0m"
    echo -e "\033[90mPress [Ctrl+C] inside terminal to shut down the server safely.\033[0m"
    ./venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --reload
else
    echo -e "\033[90mTo start the server manually, execute:\033[0m"
    echo -e "   ./venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
fi
