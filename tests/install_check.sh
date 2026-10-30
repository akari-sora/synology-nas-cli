#!/usr/bin/env bash
# Offline check of skills/install.sh against a throwaway HOME.
set -eu
cd "$(dirname "$0")/.."
REPO="$(pwd -P)"
H=$(mktemp -d)
trap 'rm -rf "$H"' EXIT
mkdir -p "$H/.claude/skills" "$H/.config/opencode/skills" "$H/.codex/skills"
mkdir -p "$H/.codex/skills/synology-nas"            # someone else's skill with the same name
run() { HOME="$H" skills/install.sh "$@"; }
fail() { echo "FAIL install_check: $*"; exit 1; }

out=$(run --dry-run)
[ -z "$(ls "$H/.claude/skills")" ] || fail "dry run changed something"
echo "$out" | grep -q "(dry run) linked $H/.claude/skills/synology-nas" || fail "dry run output: $out"
run >/dev/null
[ "$(readlink "$H/.claude/skills/synology-nas")" = "$REPO/skills/synology-nas" ] || fail "no link in .claude"
[ -L "$H/.config/opencode/skills/synology-ransomware-response" ] || fail "no link in opencode"
[ -d "$H/.codex/skills/synology-nas" ] && [ ! -L "$H/.codex/skills/synology-nas" ] || fail "foreign skill replaced"
[ -L "$H/.codex/skills/synology-ransomware-response" ] || fail "no link in codex"
[ ! -e "$H/.cursor" ] || fail "created a directory that did not exist"
run >/dev/null                                        # idempotent
run --copy >/dev/null
[ -f "$H/.claude/skills/synology-nas/SKILL.md" ] && [ ! -L "$H/.claude/skills/synology-nas" ] || fail "copy mode"
[ -f "$H/.claude/skills/synology-nas/.installed-by-synology-nas-cli" ] || fail "copy marker"
run --uninstall >/dev/null
[ -z "$(ls "$H/.claude/skills")" ] || fail "uninstall left files in .claude"
[ -d "$H/.codex/skills/synology-nas" ] || fail "uninstall removed a foreign skill"
echo "install checks ok"
