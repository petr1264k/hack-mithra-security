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
scp -q app.py index.html app.service rescan.service rescan.timer "root@$IP:"
ssh "root@$IP" 'mkdir -p data .cache'
scp -q data/xz_replay.json "root@$IP:data/"
# The cache holds public GitHub data and model results, so the server does not spend the shared AI key again.
if [ -d .cache ]; then COPYFILE_DISABLE=1 tar --no-xattrs -czf - .cache | ssh "root@$IP" 'tar -xzf -'; fi
ssh "root@$IP" 'cp app.service rescan.service rescan.timer /etc/systemd/system/ && systemctl daemon-reload && systemctl enable -q app && systemctl enable -q --now rescan.timer && systemctl restart app'

echo "Deployed. Waiting for the app..."
for _ in $(seq 1 60); do
  if curl -s -m 3 "http://$IP/health"; then echo; echo "Live at http://$IP"; exit 0; fi
  sleep 2
done
echo "The app did not answer. Read its log with: ssh root@$IP 'journalctl -u app -n 30'"
exit 1
