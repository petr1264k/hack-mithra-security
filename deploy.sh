#!/usr/bin/env bash
# Copy the app to the Linode and restart it.
# Usage: ./deploy.sh   (reads SERVER_IP from .env)
set -euo pipefail
cd "$(dirname "$0")"

IP="$(grep -E '^SERVER_IP=' .env | cut -d= -f2-)"
if [ -z "$IP" ]; then echo "Set SERVER_IP=<your Linode IPv4> in .env"; exit 1; fi

# The server gets .env without account-level secrets. It never needs them,
# and it is the machine that faces the internet.
grep -v -E '^(LINODE_TOKEN|LINODE_ROOT_PASS)=|API token' .env > .env.server
chmod 600 .env.server

scp -q .env.server "root@$IP:.env"
scp -q app.py index.html app.service "root@$IP:"
ssh "root@$IP" 'cp app.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable -q app && systemctl restart app'

echo "Deployed. Waiting for the app..."
for _ in $(seq 1 30); do
  if curl -s -m 3 "http://$IP/health"; then echo; echo "Live at http://$IP"; exit 0; fi
  sleep 2
done
echo "The app did not answer. Read its log with: ssh root@$IP 'journalctl -u app -n 30'"
exit 1
