# Sourced by demo.tape: a fresh simulated NAS, `demo/nas` first on PATH, a short prompt.
export DEMO_HOME="$(mktemp -d)"
export DEMO_STATE="$DEMO_HOME/state.pickle" NAS_CONFIG="$DEMO_HOME/config.json" PATH="$PWD/demo:$PATH"
echo '{"allowed_networks": ["192.0.2.0/24"]}' > "$NAS_CONFIG"
export PS1='\[\e[1;35m\]$\[\e[0m\] '
clear
