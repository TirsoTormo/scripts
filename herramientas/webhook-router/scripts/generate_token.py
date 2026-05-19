#!/usr/bin/env python3
import secrets

def generate_secure_token():
    # Generate cryptographically secure hex token of 32 bytes (64 characters)
    token = secrets.token_hex(32)
    
    print("======================================================================")
    print(" 🔑 WEBHOOK GATEWAY - CRYPTOGRAPHIC TOKEN GENERATOR")
    print("======================================================================")
    print("You have successfully generated a secure cryptographic access key.")
    print("This key is used to authenticate client scripts, cron-jobs, and monitors.")
    print("----------------------------------------------------------------------")
    print(f"👉 NEW GATEWAY TOKEN:\n\n   \033[92m{token}\033[0m\n")
    print("----------------------------------------------------------------------")
    print("💻 HOW TO CONFIGURE AND IMPLEMENT:")
    print("1. Open your local '.env' file and configure the GATEWAY_TOKEN:")
    print(f"   GATEWAY_TOKEN={token}")
    print("\n2. Supply this token inside your client webhook JSON payloads:")
    print("   {")
    print(f'     "token": "{token}",')
    print('     "source": "prod-node-01",')
    print('     "service": "my-app-service",')
    print('     "severity": "CRITICAL",')
    print('     "message": "Connection connection failure reported."')
    print("   }")
    print("\n3. OR, send it inside the 'X-Gateway-Token' standard HTTP Header (Highly Recommended!):")
    print("   curl -X POST http://localhost:8000/webhook \\")
    print(f"        -H 'X-Gateway-Token: {token}' \\")
    print("        -H 'Content-Type: application/json' \\")
    print("        -d '{\"source\": \"prod-node-01\", \"service\": \"docker-nginx\", \"severity\": \"CRITICAL\", \"message\": \"Container crash!\"}'")
    print("======================================================================")

if __name__ == "__main__":
    generate_secure_token()
