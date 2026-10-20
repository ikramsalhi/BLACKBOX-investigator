#!/bin/sh
set -eu
# BLACKBOX public deployment is a READ-ONLY gallery. Seed only an empty
# isolated data directory, never replace user-submitted evidence.
if { [ "${BLACKBOX_DEPLOY_MODE:-local}" = public-demo ] || [ "${BLACKBOX_DEPLOY_MODE:-local}" = hybrid ]; } && [ ! -e "${BLACKBOX_DATA_DIR:-/var/lib/blackbox}/blackbox.sqlite3" ]; then
  BLACKBOX_DEPLOY_MODE=local python seed_public_demo.py
fi
# Provision the first owner on Railway via private environment variables.
# On restart an existing account is never overwritten.
if [ -n "${BLACKBOX_BOOTSTRAP_USER:-}" ] && [ -n "${BLACKBOX_BOOTSTRAP_PASSWORD:-}" ]; then
  python -c 'import os; from blackbox import accounts,storage;storage.init_db();u=os.environ["BLACKBOX_BOOTSTRAP_USER"];accounts.add(u,os.environ["BLACKBOX_BOOTSTRAP_PASSWORD"]) if u not in accounts.accounts() else None'
fi
exec python serve.py
