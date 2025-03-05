#!/bin/bash
# LEGION Signature Auto-Update
# using a git signature pool 

SIGNATURE_DIR="/etc/legion/signatures"
# GIT_REPO="https://github.com/legion-malware/signatures.git"

echo "[*] Updating signatures..."
if [ -d "$SIGNATURE_DIR" ]; then
    cd "$SIGNATURE_DIR" && git pull
else
    git clone "$GIT_REPO" "$SIGNATURE_DIR" # clone
fi

echo "[*] Update complete."