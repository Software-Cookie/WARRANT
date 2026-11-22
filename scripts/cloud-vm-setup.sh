#!/usr/bin/env bash
# Run once on a fresh Ubuntu 24.04 Google Compute Engine VM: installs Docker (with Compose and BuildKit) and Java 21.
set -euo pipefail
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sudo sh
fi
sudo usermod -aG docker "$USER"
sudo apt-get update -y
sudo apt-get install -y openjdk-21-jdk-headless unzip curl
sudo systemctl enable --now docker
echo
echo "Setup finished. Now type:  exit"
echo "then reconnect with the same ssh command, and run:  cd ~/WARRANT && ./scripts/cloud-demo-up.sh"
