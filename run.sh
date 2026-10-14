#!/usr/bin/env bash
set -e

echo "================================================================="
echo "   Google Cloud Security & SOC Alignment Assessment Runner       "
echo "================================================================="

# 1. Verify gcloud authentication
CURRENT_ACCOUNT=$(gcloud config get-value account 2>/dev/null || true)
if [ -z "$CURRENT_ACCOUNT" ]; then
    echo "[!] Error: No active gcloud session detected."
    echo "    Please run 'gcloud auth login' and try again."
    exit 1
fi
echo "[+] Authenticated as: $CURRENT_ACCOUNT"

# 2. Auto-detect or prompt for Project ID
CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null || true)
read -p "Enter Target Quota/Billing Project ID [$CURRENT_PROJECT]: " INPUT_PROJECT
PROJECT_ID=${INPUT_PROJECT:-$CURRENT_PROJECT}

if [ -z "$PROJECT_ID" ]; then
    echo "[!] Error: Project ID is required."
    exit 1
fi

# 3. Auto-detect or prompt for Organization ID
DETECTED_ORG=$(gcloud organizations list --format="value(ID)" 2>/dev/null | head -n 1 || true)
read -p "Enter Target GCP Organization ID [$DETECTED_ORG]: " INPUT_ORG
ORG_ID=${INPUT_ORG:-$DETECTED_ORG}

if [ -z "$ORG_ID" ]; then
    echo "[!] Error: Organization ID is required."
    exit 1
fi

# 4. Optional Branding
read -p "Enter Customer / Client Name [Target Enterprise]: " CLIENT_NAME
CLIENT_NAME=${CLIENT_NAME:-"Target Enterprise"}

# 5. Virtual Environment Setup
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d ".venv" ]; then
    echo "[+] Creating local virtual environment (.venv)..."
    python3 -m venv .venv
fi

source .venv/bin/activate
echo "[+] Installing assessment dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# 6. Execute Audit
echo "[+] Running security posture scan..."
python3 audit.py \
    --org-id="$ORG_ID" \
    --project-id="$PROJECT_ID" \
    --client-name="$CLIENT_NAME" \
    --assessor-name="Cloud Security Practice"

echo ""
echo "[✓] Scan complete. Download the generated HTML file and print to PDF via your browser."