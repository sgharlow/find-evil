#!/usr/bin/env bash
# Smoke test the find-evil Docker MCP stdio transport.
# Verifies: (1) server advertises 15 tools, (2) parse_evtx runs live-mode,
# (3) hostname redaction is active when the env var is passed.
#
# Exit 0 on full pass, 1 on any failure.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

pass=0
fail=0

check() {
    local label="$1" status="$2" detail="${3:-}"
    if [ "$status" = "PASS" ]; then
        echo "  [PASS] $label"
        pass=$((pass + 1))
    else
        echo "  [FAIL] $label ${detail}"
        fail=$((fail + 1))
    fi
}

echo "=== find-evil live MCP smoke test ==="
echo

# Build a minimal MCP client payload: initialize + initialized + tools/list +
# parse_evtx call against the committed fixture.
payload=$(cat <<'JSON'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"parse_evtx","arguments":{"evtx_path":"/evidence/Application_small.evtx","max_events":3}}}
JSON
)

# Feed the payload through stdio. Sleep a beat after so the third response has
# time to flush before the container exits.
output=$({ echo "$payload"; sleep 3; } | MSYS_NO_PATHCONV=1 docker run --rm -i -e FIND_EVIL_COMPUTER_REDACT_MAP="TDC-5690-SH.Opus.OpusInspection.com=VICTUS" -v "$REPO_ROOT/evidence:/evidence:ro" -v "$REPO_ROOT/output:/output" find-evil-sift:latest 2>/dev/null)

[ "${DEBUG_SMOKE:-0}" = "1" ] && { echo "--- DEBUG ---"; echo "REPO_ROOT=$REPO_ROOT"; echo "payload bytes=${#payload}"; echo "output bytes=${#output}"; echo "output lines=$(echo "$output" | wc -l)"; echo "--- /DEBUG ---"; }

if [ -z "$output" ]; then
    echo "  [FAIL] docker stdio returned nothing (is Docker Desktop running?)"
    echo
    echo "=== Summary: 0 passed, 3 failed ==="
    exit 1
fi

# Write the parser script to a temp file so we can pipe $output into it
# without clashing with the heredoc (heredocs hijack stdin).
parser_py=$(mktemp --suffix=.py)
trap 'rm -f "$parser_py"' EXIT

cat >"$parser_py" <<'PY'
import json, sys

init_ok = False
tool_count = 0
evtx_mode = None
evtx_computers = []

for line in sys.stdin:
    line = line.strip()
    if not line.startswith('{'):
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg.get('id') == 1 and 'result' in msg:
        if 'serverInfo' in msg['result']:
            init_ok = True
    elif msg.get('id') == 2 and 'result' in msg:
        tools = msg['result'].get('tools', [])
        tool_count = len(tools)
    elif msg.get('id') == 3 and 'result' in msg:
        text = msg['result']['content'][0]['text']
        data = json.loads(text)
        evtx_mode = data.get('mode')
        evtx_computers = sorted({e.get('Computer', '') for e in data.get('data', [])})

results = [
    ('initialize handshake', init_ok, ''),
    ('tool registry (15 tools)', tool_count == 15, f'got {tool_count}'),
    ('parse_evtx live + redacted',
     evtx_mode == 'live' and evtx_computers == ['VICTUS'],
     f'mode={evtx_mode} computers={evtx_computers}'),
]

any_fail = False
for label, ok, detail in results:
    print(f'  [{"PASS" if ok else "FAIL"}] {label}' + (f' - {detail}' if not ok else ''))
    if not ok: any_fail = True

sys.exit(1 if any_fail else 0)
PY

echo "$output" | python "$parser_py"
rc=$?
if [ $rc -eq 0 ]; then
    pass=3; fail=0
else
    # Python printed per-check results already
    pass=0; fail=1  # summary shows at least one failure
fi

echo
echo "=== Summary: $pass passed, $fail failed ==="
[ $fail -eq 0 ] && exit 0 || exit 1
