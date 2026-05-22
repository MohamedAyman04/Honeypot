#!/usr/bin/env bash
# hplog.sh — ICS Honeypot Terminal Logger — Shell Integration
# ============================================================
# Source this file once in your terminal session.
# After sourcing, plain curl / ssh / cat / mbtget commands are
# automatically intercepted and logged as MITRE-tagged security
# events in general logs.jsonl + Grafana.
#
# Usage:
#   source attacker_node/hplog.sh
#
# Then just run commands normally — no prefix needed:
#   curl -s http://localhost:5002/api/debug | python3 -m json.tool
#   ssh engineer@localhost -p 2222
#   cat /var/log/scada_maintenance.log
#   ssh operator@localhost -p 2222
#   mbtget -r3 -a 100 localhost
#   mbtget -w6 300 -a 100 localhost
#
# To bypass logging for a one-off command use the real binary:
#   command curl -s http://example.com
#   command ssh user@host

# ── Resolve the path to terminal_logger.py (bash + zsh safe) ─────────────────
if [ -n "${ZSH_VERSION}" ]; then
    # zsh: ${(%):-%x} expands to the path of the currently sourced file
    _HPLOG_SCRIPT="$(cd "$(dirname "${(%):-%x}")" 2>/dev/null && pwd)/terminal_logger.py"
else
    # bash: BASH_SOURCE[0] is the sourced file
    _HPLOG_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)/terminal_logger.py"
fi

# ── Shared journey ID — all commands in this session share one kill chain ─────
export STORY_RUN_ID="${STORY_RUN_ID:-$(python3 -c \
    "import datetime,secrets; \
     print(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+secrets.token_hex(2))" \
)}"

# ── Internal dispatcher ────────────────────────────────────────────────────────
_hplog_run() {
    python3 "${_HPLOG_SCRIPT}" "$@"
}

# ── Transparent command overrides (no prefix needed) ─────────────────────────
# These shadow the real binaries. Use `command curl` to bypass logging.
curl()   { _hplog_run curl   "$@"; }
ssh()    { _hplog_run ssh    "$@"; }
cat()    { _hplog_run cat    "$@"; }
mbtget() { _hplog_run mbtget "$@"; }

# ── Generic hplog wrapper (for any other command) ─────────────────────────────
hplog() { _hplog_run "$@"; }

# ── Legacy hp-prefixed aliases (backwards compat) ────────────────────────────
hpcurl()   { _hplog_run curl   "$@"; }
hpssh()    { _hplog_run ssh    "$@"; }
hpcat()    { _hplog_run cat    "$@"; }
hpmbtget() { _hplog_run mbtget "$@"; }

# ── Export so subshells inherit them ─────────────────────────────────────────
export -f _hplog_run curl ssh cat mbtget hplog hpcurl hpssh hpcat hpmbtget 2>/dev/null || true

# ── Activation banner ─────────────────────────────────────────────────────────
echo ""
echo "  \033[36m[honeypot-log]\033[0m Terminal logging \033[32mACTIVATED\033[0m"
echo "  Script      : ${_HPLOG_SCRIPT}"
echo "  Journey ID  : \033[1m${STORY_RUN_ID}\033[0m"
echo ""
echo "  Commands now logged automatically (no hp prefix needed):"
echo "    \033[33mcurl\033[0m    \033[33mssh\033[0m    \033[33mcat\033[0m    \033[33mmbtget\033[0m"
echo ""
echo "  To bypass logging for a single call:"
echo "    \033[90mcommand curl ...\033[0m  /  \033[90mcommand ssh ...\033[0m"
echo ""
echo "  Attack sequence:"
echo "    curl -s http://localhost:5002/api/debug | python3 -m json.tool"
echo "    ssh engineer@localhost -p 2222"
echo "    cat /var/log/scada_maintenance.log"
echo "    ssh operator@localhost -p 2222"
echo "    mbtget -r3 -a 100 localhost"
echo "    mbtget -w6 300 -a 100 localhost"
echo ""
