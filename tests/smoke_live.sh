#!/usr/bin/env bash
# Optional live check against the NAS in your config: every read-only command with --json must
# exit 0 (alert/incident: 0 or 1) and print valid JSON. Sends no writes; `incident fix` only as
# --dry-run. One DSM sign-in per command unless `nas login` cached a session.
# SMOKE_SLOW=1 also runs ransom-scan (minutes).
set -u
cd "$(dirname "$0")/.."
NAS=./bin/nas
fail=0
err=$(mktemp)
trap 'rm -f "$err"' EXIT

run() {  # run NAME MAXRC ARGS...
  local name="$1" max="$2"; shift 2
  local out rc
  out=$("$NAS" --json "$@" 2>"$err"); rc=$?
  if [ $rc -gt "$max" ]; then
    echo "FAIL $name (exit $rc): $(tail -1 "$err")"; fail=1
  elif ! printf '%s' "$out" | python3 -m json.tool >/dev/null 2>&1; then
    echo "FAIL $name: not JSON"; fail=1
  else
    echo "ok   $name (exit $rc)"
  fi
}

# stop at the first failed sign-in: repeating a wrong password feeds AutoBlock
if ! "$NAS" whoami >/dev/null 2>"$err"; then
  echo "FAIL whoami: $(tail -1 "$err")"; exit 1
fi
echo "ok   whoami"
run status 0 status
run net 0 net
run services 0 services
run inventory 0 inventory
run health 0 health
run logs 0 logs --limit 2000
run api 0 api SYNO.Core.System info --version 1
run upgrade 0 upgrade --dry-run
run pkg 0 pkg list
run volume 0 volume list
run alert 1 alert --no-update
run incident 1 incident
run incident-fix-dry-run 1 incident fix --dry-run
if [ "${SMOKE_SLOW:-0}" = 1 ]; then run ransom-scan 0 ransom-scan; fi
if "$NAS" api SYNO.Core.Package.Control stop --version 1 id=none >/dev/null 2>&1; then
  echo "FAIL api write guard"; fail=1
else
  echo "ok   api write guard"
fi
exit $fail
