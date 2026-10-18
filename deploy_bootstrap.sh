#!/bin/sh
set -eu
# BLACKBOX public deployment is a READ-ONLY gallery. Seed only an empty
# isolated data directory, never replace user-submitted evidence.
if [ "${BLACKBOX_DEPLOY_MODE:-local}" = public-demo ] && [ ! -e "${BLACKBOX_DATA_DIR:-/var/lib/blackbox}/blackbox.sqlite3" ]; then
  BLACKBOX_DEPLOY_MODE=local python seed_public_demo.py
fi
exec python serve.py
