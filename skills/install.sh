#!/usr/bin/env bash
# Install the skills in this folder into every agent skill directory that already exists:
#   ~/.claude/skills ~/.cursor/skills ~/.codex/skills ~/.agents/skills ~/.grok/skills ~/.gemini/skills
#   ~/.config/opencode/skills ~/.hermes/shared-skills
# Default: a symlink per skill (updates with `git pull`). --copy: copies (marked with .installed-by-synology-nas-cli).
# --dry-run: print what would change. --uninstall: remove what this script installed (nothing else).
# Existing entries it did not create are left alone.
set -eu
SRC="$(cd "$(dirname "$0")" && pwd -P)"
MARK=".installed-by-synology-nas-cli"
mode=link dry=0 uninstall=0
for a in "$@"; do
  case "$a" in
    --copy) mode=copy ;;
    --dry-run) dry=1 ;;
    --uninstall) uninstall=1 ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
TARGETS="$HOME/.claude/skills $HOME/.cursor/skills $HOME/.codex/skills $HOME/.agents/skills $HOME/.grok/skills
$HOME/.gemini/skills $HOME/.config/opencode/skills $HOME/.hermes/shared-skills"
pre=""; [ $dry = 1 ] && pre="(dry run) "

ours() {  # ours DEST NAME: true when DEST is a link to this repo's skill or a copy this script made
  if [ -L "$1" ]; then [ "$(readlink "$1")" = "$SRC/$2" ]; return; fi
  [ -d "$1" ] && [ -f "$1/$MARK" ]
}
act() { [ $dry = 1 ] || "$@"; }

found=0
for t in $TARGETS; do
  [ -d "$t" ] || continue
  found=1
  for d in "$SRC"/*/; do
    name=$(basename "$d")
    [ -f "$SRC/$name/SKILL.md" ] || continue
    dest="$t/$name"
    if [ $uninstall = 1 ]; then
      if ours "$dest" "$name"; then act rm -rf "$dest"; echo "${pre}removed $dest"
      elif [ -e "$dest" ] || [ -L "$dest" ]; then echo "${pre}kept $dest (not installed by this script)"; fi
      continue
    fi
    if [ -e "$dest" ] || [ -L "$dest" ]; then
      if ours "$dest" "$name"; then act rm -rf "$dest"
      else echo "${pre}skipped $dest (exists, not installed by this script)"; continue; fi
    fi
    if [ $mode = copy ]; then
      act cp -R "$SRC/$name" "$dest"; act touch "$dest/$MARK"; echo "${pre}copied $name -> $dest"
    else
      act ln -s "$SRC/$name" "$dest"; echo "${pre}linked $dest -> $SRC/$name"
    fi
  done
done
[ $found = 1 ] || echo "no agent skill directory found (looked for: $(echo $TARGETS))"
exit 0
