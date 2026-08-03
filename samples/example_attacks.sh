#!/usr/bin/env bash
#
# example_attacks.sh
#
# Generates safe test activity against the lab to trigger custom detections.
# Run from kali-zrahman (the attacker host) so alerts carry a real source IP
# rather than ::1 — same_srcip grouping does not work meaningfully against
# localhost.
#
# Requires: the manager VM running, ubuntu-zrahman reachable on the tailnet.
# Verify first:  ping -c2 ubuntu-zrahman && curl -I http://ubuntu-zrahman/
#
# Watch alerts land, on the manager, in another window:
#   sudo tail -f /var/ossec/logs/alerts/alerts.json | \
#     jq -c '{time:.timestamp, rule:.rule.id, desc:.rule.description, src:.data.srcip}'

set -u

TARGET="ubuntu-zrahman"
PAUSE=90          # seconds between tests, so frequency windows do not overlap

banner() {
  echo
  echo "=============================================================="
  echo "  $1"
  echo "=============================================================="
}

# --------------------------------------------------------------------------
# Pre-flight
# --------------------------------------------------------------------------
banner "Pre-flight checks"

if ! ping -c2 -W2 "$TARGET" > /dev/null 2>&1; then
  echo "FAIL: cannot reach $TARGET. Is Tailscale up on both ends?"
  exit 1
fi
echo "OK: $TARGET reachable"

if ! curl -s -I --max-time 5 "http://$TARGET/" > /dev/null 2>&1; then
  echo "WARN: Apache not responding on $TARGET — web tests will produce nothing."
  echo "      Check 'sudo ufw status' and 'sudo ss -tlnp | grep :80' on the agent."
fi
echo "Source IP for these alerts: $(tailscale ip -4 2>/dev/null || echo 'unknown')"

# --------------------------------------------------------------------------
# 100103 — scanner user-agent (fires on a single request)
# --------------------------------------------------------------------------
banner "100103 — known scanning tool user-agent"

for ua in "sqlmap/1.0" "Nikto/2.5.0" "gobuster/3.6"; do
  echo "  -> $ua"
  curl -s -A "$ua" "http://$TARGET/" > /dev/null
  sleep 1
done
echo "Expect: 3x rule 100103, level 7"

sleep "$PAUSE"

# --------------------------------------------------------------------------
# 100101 — 404 burst (needs 13+ within 60s from one source IP)
# --------------------------------------------------------------------------
banner "100101 — web 404 burst / path enumeration"

# Distinct paths, spread over ~25s. Firing 20 requests in under a second can
# get collapsed before the rule counter sees them as separate events.
PATHS=(admin wp-login.php .env .git/config phpmyadmin backup.sql config.php
       .aws/credentials server-status shell.php admin/login xmlrpc.php
       vendor/phpunit .ssh/id_rsa wp-admin api/v1/users .DS_Store
       robots.txt.bak dump.sql old/)

for p in "${PATHS[@]}"; do
  echo "  -> GET /$p"
  curl -s "http://$TARGET/$p" > /dev/null
  sleep 1
done
echo "Expect: many x rule 31101 (stock), then 1x rule 100101, level 8"

sleep "$PAUSE"

# --------------------------------------------------------------------------
# 100100 — SSH brute force against non-existent users (7+ within 120s)
# --------------------------------------------------------------------------
banner "100100 — SSH brute force, non-existent users"

# NumberOfPasswordPrompts=0 makes ssh fail immediately instead of prompting,
# so this runs unattended. The server still logs the failed attempt.
for i in $(seq 1 20); do
  echo "  -> ssh baduser$i@$TARGET"
  ssh -o StrictHostKeyChecking=no \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=0 \
      -o ConnectTimeout=3 \
      "baduser$i@$TARGET" exit 2>/dev/null
  sleep 1
done
echo "Expect: many x rule 5710 (stock), then 1x rule 100100, level 10"

sleep "$PAUSE"

# --------------------------------------------------------------------------
# 100102 — SSH brute force against a VALID account (6+ within 120s)
# --------------------------------------------------------------------------
banner "100102 — SSH brute force, valid account"

# Targets a real user, so sshd logs an authentication failure for an existing
# account rather than an unknown-user attempt. This is the more serious case:
# the attacker has a valid username.
VALID_USER="zrahman"

for i in $(seq 1 15); do
  echo "  -> ssh $VALID_USER@$TARGET (attempt $i)"
  ssh -o StrictHostKeyChecking=no \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=0 \
      -o ConnectTimeout=3 \
      "$VALID_USER@$TARGET" exit 2>/dev/null
  sleep 1
done
echo "Expect: rule 100102, level 12"
echo
echo "NOTE: if 100102 does not fire, check which stock rule these produce."
echo "      Run on the manager:  sudo tail -50 /var/ossec/logs/alerts/alerts.json |"
echo "      jq -c '{rule:.rule.id, desc:.rule.description}'"
echo "      100102 is built on 5716; some sshd versions log 5760 or 5503"
echo "      instead for this pattern. Adjust if_matched_sid to match."

# --------------------------------------------------------------------------
banner "Done"
cat <<'EOF'

Verify on the manager:

  sudo tail -100 /var/ossec/logs/alerts/alerts.json | \
    jq -r 'select(.rule.id | tonumber >= 100100) |
           "\(.timestamp) [\(.rule.id)] \(.rule.description)"'

Count what fired:

  sudo grep -o '"id":"1001[0-9][0-9]"' /var/ossec/logs/alerts/alerts.json | \
    sort | uniq -c

Then check the dashboard: Threat Hunting, last 1 hour,
  rule.id: (100100 or 100101 or 100102 or 100103)

If alerts.json has them but the dashboard does not, Filebeat is the gap:
  sudo filebeat test output

EOF