#!/usr/bin/env bash
#
# example_attacks.sh
#
# Generates safe test activity against the lab to trigger custom detections.
# Run from kali-zrahman (the attacker host) so alerts carry a real source IP
# rather than ::1 — same_srcip grouping does not work meaningfully against
# localhost.
#
# USAGE
#   ./example_attacks.sh                 run every test, with pauses between them
#   ./example_attacks.sh 100102          run only the test for rule 100102
#   ./example_attacks.sh 100100 100101   run several, in the order given
#   ./example_attacks.sh --list          show available tests
#   ./example_attacks.sh --help          this help
#
# When one rule is named, the inter-test pause is skipped — you get the burst
# and nothing else. Good for the demo, or for iterating on a single rule.
#
# Requires: the manager VM running, ubuntu-zrahman reachable on the tailnet.
#
# Watch alerts land, on the manager, in another window:
#   sudo tail -f /var/ossec/logs/alerts/alerts.json | \
#     jq -c '{time:.timestamp, rule:.rule.id, desc:.rule.description, src:.data.srcip}'

set -u

TARGET="ubuntu-zrahman"
VALID_USER="testuser-zrahman"
PAUSE=90          # seconds between tests in a full run, so windows do not overlap

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
banner() {
  echo
  echo "=============================================================="
  echo "  $1"
  echo "=============================================================="
}

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

list_tests() {
  cat <<'EOF'
Available tests:

  100100   SSH brute force, non-existent users   -> level 10
  100101   Web 404 burst / path enumeration      -> level 8
  100102   SSH brute force, valid account         -> level 12
  100103   Known scanning tool user-agent         -> level 7

Usage:
  ./example_attacks.sh 100102          one test, no pause
  ./example_attacks.sh 100100 100101   several, in order
  ./example_attacks.sh                 all of them, with pauses
EOF
  exit 0
}

preflight() {
  banner "Pre-flight checks"
  if ! ping -c2 -W2 "$TARGET" > /dev/null 2>&1; then
    echo "FAIL: cannot reach $TARGET. Is Tailscale up on both ends?"
    exit 1
  fi
  echo "OK: $TARGET reachable"

  if ! curl -s -I --max-time 5 "http://$TARGET/" > /dev/null 2>&1; then
    echo "WARN: Apache not responding — web tests (100101, 100103) will do nothing."
    echo "      On the agent: sudo ufw status ; sudo ss -tlnp | grep :80"
  fi
  echo "Source IP for these alerts: $(tailscale ip -4 2>/dev/null || echo unknown)"
}

# --------------------------------------------------------------------------
# Individual tests. Each is a function named test_<ruleid>.
# --------------------------------------------------------------------------

test_100103() {
  banner "100103 — known scanning tool user-agent (single-request rule)"
  for ua in "sqlmap/1.0" "Nikto/2.5.0" "gobuster/3.6"; do
    echo "  -> $ua"
    curl -s -A "$ua" "http://$TARGET/" > /dev/null
    sleep 1
  done
  echo "Expect: 3x rule 100103, level 7"
}

test_100101() {
  banner "100101 — web 404 burst / path enumeration"
  # Distinct paths, spread ~1s apart. 20 requests in under a second can be
  # collapsed before the frequency counter sees them as separate events.
  local paths=(admin wp-login.php .env .git/config phpmyadmin backup.sql
    config.php .aws/credentials server-status shell.php admin/login xmlrpc.php
    vendor/phpunit .ssh/id_rsa wp-admin api/v1/users .DS_Store robots.txt.bak
    dump.sql old/)
  for p in "${paths[@]}"; do
    echo "  -> GET /$p"
    curl -s "http://$TARGET/$p" > /dev/null
    sleep 1
  done
  echo "Expect: many x rule 31101 (stock), then 1x rule 100101, level 8"
}

test_100100() {
  banner "100100 — SSH brute force, non-existent users"
  # NumberOfPasswordPrompts=0 makes ssh fail immediately instead of prompting,
  # so this runs unattended. The server still logs each failed attempt.
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
}

test_100102() {
  banner "100102 — SSH brute force, valid account"
  # Targets a real user, so sshd logs an auth failure for an EXISTING account
  # rather than an unknown-user attempt. The more serious case: attacker has a
  # valid username.
  for i in $(seq 1 15); do
    echo "  -> ssh $VALID_USER@$TARGET (attempt $i)"
    sshpass -p "wrongpass$i" \
      ssh -o StrictHostKeyChecking=no \
          -o PreferredAuthentications=password \
          -o PubkeyAuthentication=no \
          -o ConnectTimeout=3 \
          "$VALID_USER@$TARGET" exit 2>/dev/null
    sleep 1
  done
  echo "Expect: rule 100102, level 12"
  echo
  echo "  If it does not fire: this rule is built on stock rule 5716. Some sshd"
  echo "  versions log 5760 or 5503 for this pattern instead. Check what actually"
  echo "  fired and adjust if_matched_sid in linux_rules.xml:"
  echo "    sudo tail -30 /var/ossec/logs/alerts/alerts.json | jq -c '{rule:.rule.id, desc:.rule.description}'"
}

verify_note() {
  banner "Done — verify on the manager"
  cat <<'EOF'
  sudo tail -100 /var/ossec/logs/alerts/alerts.json | \
    jq -r 'select(.rule.id | tonumber >= 100100) |
           "\(.timestamp) [\(.rule.id)] \(.rule.description)"'

Count what fired:
  sudo grep -o '"id":"1001[0-9][0-9]"' /var/ossec/logs/alerts/alerts.json | sort | uniq -c

Dashboard: Threat Hunting, last 1 hour,
  rule.id: (100100 or 100101 or 100102 or 100103)

alerts.json has them but dashboard does not? Filebeat is the gap:
  sudo filebeat test output
EOF
}

# --------------------------------------------------------------------------
# Argument handling
# --------------------------------------------------------------------------
ALL_TESTS=(100103 100101 100100 100102)   # order for a full run

case "${1:-}" in
  --help|-h) usage ;;
  --list|-l) list_tests ;;
esac

if [ "$#" -eq 0 ]; then
  # full run, with pauses
  requested=("${ALL_TESTS[@]}")
  full_run=1
else
  # named tests, in the order given, no pauses
  requested=("$@")
  full_run=0
fi

# validate every requested id has a matching function before running anything
for id in "${requested[@]}"; do
  if ! declare -f "test_$id" > /dev/null; then
    echo "Unknown test: $id"
    echo "Run  ./example_attacks.sh --list  to see valid ids."
    exit 1
  fi
done

preflight

count=0
total=${#requested[@]}
for id in "${requested[@]}"; do
  count=$((count + 1))
  "test_$id"
  # pause between tests only on a full run, and not after the last one
  if [ "$full_run" -eq 1 ] && [ "$count" -lt "$total" ]; then
    echo
    echo "  ... waiting ${PAUSE}s so the next frequency window is clean ..."
    sleep "$PAUSE"
  fi
done

verify_note