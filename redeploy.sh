#!/usr/bin/env bash
#
# Re-applies ownership, permissions and SELinux labels to the Sigma Sync checkout.
# Run after EVERY git pull or edit on the server:
#
#   cd /data/AAP_Storage/apps/sigmasync && sudo ./redeploy.sh
#
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS="/data/AAP_Storage/secrets/sigmasync.env"
WEB_GROUP="apache"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo ./redeploy.sh" >&2
    exit 1
fi

cd "$APP_DIR"
# Keep files owned by whoever maintains the checkout, so `git pull` keeps working.
OWNER="$(stat -c %U "$APP_DIR/.git" 2>/dev/null || stat -c %U "$APP_DIR")"

echo "==> Ownership ${OWNER}:${WEB_GROUP} and permissions (skipping .git)"
find . -path ./.git -prune -o -exec chown "${OWNER}:${WEB_GROUP}" {} +
find . -path ./.git -prune -o -type d -exec chmod 2750 {} +
find . -path ./.git -prune -o -type f -exec chmod 0640 {} +
chmod 0750 api.pl redeploy.sh tools/*.py 2>/dev/null || true

echo "==> Line endings (a CRLF shebang breaks CGI)"
if grep -l $'\r' api.pl ./*.pm redeploy.sh >/dev/null 2>&1; then
    echo "!! CRLF line endings found - convert with: sed -i 's/\r\$//' api.pl *.pm redeploy.sh" >&2
    exit 1
fi

echo "==> SELinux labels"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -R "$APP_DIR"
    [[ -f "$SECRETS" ]] && restorecon "$SECRETS"

    label() { ls -Z "$1" | awk '{print $1}' | cut -d: -f3; }
    status=0
    if [[ "$(label api.pl)" != "httpd_sys_script_exec_t" ]]; then
        echo "!! api.pl is labelled '$(label api.pl)', expected httpd_sys_script_exec_t." >&2
        status=1
    fi
    if [[ "$(label index.html)" != "httpd_sys_content_t" ]]; then
        echo "!! index.html is labelled '$(label index.html)', expected httpd_sys_content_t." >&2
        status=1
    fi
    if [[ $status -ne 0 ]]; then
        echo "!! The one-time 'semanage fcontext' rules are missing (DEPLOY.md, step 6)." >&2
        echo "!! restorecon cannot fix labels without them. httpd WILL return 403/500." >&2
        exit 1
    fi
else
    echo "   restorecon not found - skipping (not an SELinux host?)"
fi

echo "==> Syntax check"
APP_ENV_FILE=/dev/null perl -I"$APP_DIR" -c api.pl

echo "Done. api.pl: $(ls -Z api.pl | awk '{print $1}')"
