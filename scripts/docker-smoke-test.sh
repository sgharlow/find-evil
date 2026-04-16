#!/usr/bin/env bash
#
# Docker Smoke Test for Evidence Integrity Enforcer (find-evil)
#
# Builds the Docker image, starts the container, verifies tool registration,
# runs the test suite, and checks the demo script — then reports PASS/FAIL
# for each step.
#
# Usage:
#   ./scripts/docker-smoke-test.sh          # test dev image (Dockerfile)
#   ./scripts/docker-smoke-test.sh --sift   # test SIFT image (Dockerfile.sift)
#
# Exit code: 0 = all checks passed, 1 = one or more checks failed

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

EXPECTED_TOOL_COUNT=15
COMPOSE_FILE="docker-compose.yml"
IMAGE_LABEL="dev"

if [[ "${1:-}" == "--sift" ]]; then
    COMPOSE_FILE="docker-compose.sift.yml"
    IMAGE_LABEL="sift"
fi

COMPOSE_CMD="docker-compose -f ${PROJECT_ROOT}/${COMPOSE_FILE}"

# Track results
PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

record_pass() {
    local label="$1"
    RESULTS+=("  PASS  $label")
    ((PASS_COUNT++)) || true
}

record_fail() {
    local label="$1"
    local detail="${2:-}"
    if [[ -n "$detail" ]]; then
        RESULTS+=("  FAIL  $label -- $detail")
    else
        RESULTS+=("  FAIL  $label")
    fi
    ((FAIL_COUNT++)) || true
}

# ---------------------------------------------------------------------------
# Cleanup trap — always tear down containers
# ---------------------------------------------------------------------------

cleanup() {
    echo ""
    echo "--- Cleaning up containers ---"
    $COMPOSE_CMD down --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Check 1: Docker files exist
# ---------------------------------------------------------------------------

echo "=== Evidence Integrity Enforcer — Docker Smoke Test (${IMAGE_LABEL}) ==="
echo ""

if [[ -f "${PROJECT_ROOT}/Dockerfile" && -f "${PROJECT_ROOT}/${COMPOSE_FILE}" ]]; then
    record_pass "Docker files exist (Dockerfile + ${COMPOSE_FILE})"
else
    record_fail "Docker files exist" "Missing Dockerfile or ${COMPOSE_FILE}"
fi

# ---------------------------------------------------------------------------
# Check 2: Build the image
# ---------------------------------------------------------------------------

echo "--- Building Docker image (${IMAGE_LABEL}) ---"
if $COMPOSE_CMD build --no-cache 2>&1; then
    record_pass "Docker image builds successfully"
else
    record_fail "Docker image builds successfully" "docker-compose build failed"
    # Cannot continue without a built image
    echo ""
    echo "=== SUMMARY ==="
    printf '%s\n' "${RESULTS[@]}"
    echo ""
    echo "FAIL — image build failed, cannot proceed with remaining checks."
    exit 1
fi

# ---------------------------------------------------------------------------
# Check 3: Verify MCP tool registration (15 tools)
# ---------------------------------------------------------------------------

echo ""
echo "--- Verifying MCP tool registration ---"
TOOL_OUTPUT=$($COMPOSE_CMD run --rm --no-deps mcp-server python -c "
from find_evil.server import mcp
tools = mcp._tool_manager.list_tools()
names = sorted(t.name for t in tools)
print(f'TOOL_COUNT={len(tools)}')
for n in names:
    print(f'  {n}')
bad = set(names) & {'execute_shell_cmd','write_file','rm','dd','shell','bash'}
if bad:
    print(f'SECURITY_VIOLATION={bad}')
else:
    print('SECURITY=CLEAN')
" 2>&1) || true

TOOL_COUNT=$(echo "$TOOL_OUTPUT" | grep -oP 'TOOL_COUNT=\K[0-9]+' || echo "0")

if [[ "$TOOL_COUNT" -eq "$EXPECTED_TOOL_COUNT" ]]; then
    record_pass "Tool registration: ${TOOL_COUNT}/${EXPECTED_TOOL_COUNT} tools"
else
    record_fail "Tool registration" "Expected ${EXPECTED_TOOL_COUNT}, got ${TOOL_COUNT}"
fi

# Check no destructive tools leaked in
if echo "$TOOL_OUTPUT" | grep -q "SECURITY=CLEAN"; then
    record_pass "Security: no destructive tools registered"
else
    record_fail "Security" "Destructive tools detected or check failed"
fi

# ---------------------------------------------------------------------------
# Check 4: Run the test suite inside the container
# ---------------------------------------------------------------------------

echo ""
echo "--- Running test suite inside container ---"
if TEST_OUTPUT=$($COMPOSE_CMD run --rm --no-deps mcp-server python -m pytest tests/ --tb=short -q 2>&1); then
    # Extract pass count from pytest output (e.g., "497 passed")
    PASSED=$(echo "$TEST_OUTPUT" | grep -oP '\d+ passed' | grep -oP '\d+' || echo "0")
    record_pass "Test suite: ${PASSED} tests passed"
else
    # Tests ran but some may have failed
    FAILED_TESTS=$(echo "$TEST_OUTPUT" | grep -oP '\d+ failed' | grep -oP '\d+' || echo "?")
    PASSED=$(echo "$TEST_OUTPUT" | grep -oP '\d+ passed' | grep -oP '\d+' || echo "0")
    record_fail "Test suite" "${FAILED_TESTS} failed, ${PASSED} passed"
fi

# ---------------------------------------------------------------------------
# Check 5: Verify demo scripts are present and importable
# ---------------------------------------------------------------------------

echo ""
echo "--- Checking demo scripts ---"
DEMO_CHECK=$($COMPOSE_CMD run --rm --no-deps mcp-server python -c "
import os, sys
demos = ['demo/tamper_demo.py', 'demo/run_investigation.py', 'demo/validate_submission.py']
found = []
missing = []
for d in demos:
    if os.path.isfile(d):
        found.append(d)
    else:
        missing.append(d)
print(f'FOUND={len(found)}')
print(f'MISSING={len(missing)}')
for m in missing:
    print(f'  MISSING: {m}')
" 2>&1) || true

DEMO_FOUND=$(echo "$DEMO_CHECK" | grep -oP 'FOUND=\K[0-9]+' || echo "0")
DEMO_MISSING=$(echo "$DEMO_CHECK" | grep -oP 'MISSING=\K[0-9]+' || echo "?")

if [[ "$DEMO_MISSING" == "0" ]]; then
    record_pass "Demo scripts accessible: ${DEMO_FOUND} found"
else
    record_fail "Demo scripts" "${DEMO_MISSING} demo scripts not found in container"
fi

# ---------------------------------------------------------------------------
# Check 6: Verify the package is importable and server can be loaded
# ---------------------------------------------------------------------------

echo ""
echo "--- Verifying package import ---"
if $COMPOSE_CMD run --rm --no-deps mcp-server python -c "
import find_evil
from find_evil.server import mcp, main
from find_evil.session.manager import EvidenceSession
from find_evil.audit.logger import AuditLogger
print('ALL_IMPORTS=OK')
" 2>&1 | grep -q "ALL_IMPORTS=OK"; then
    record_pass "Package imports: all core modules importable"
else
    record_fail "Package imports" "One or more core modules failed to import"
fi

# ---------------------------------------------------------------------------
# Check 7: Verify evidence directories exist in container
# ---------------------------------------------------------------------------

echo ""
echo "--- Checking container directory structure ---"
DIR_CHECK=$($COMPOSE_CMD run --rm --no-deps mcp-server python -c "
import os
dirs = ['/evidence', '/output', '/app/src/find_evil']
ok = all(os.path.isdir(d) for d in dirs)
print(f'DIRS_OK={ok}')
" 2>&1) || true

if echo "$DIR_CHECK" | grep -q "DIRS_OK=True"; then
    record_pass "Container directories: /evidence, /output, /app/src present"
else
    record_fail "Container directories" "Expected directories missing"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "==========================================="
echo "  DOCKER SMOKE TEST SUMMARY (${IMAGE_LABEL})"
echo "==========================================="
printf '%s\n' "${RESULTS[@]}"
echo "-------------------------------------------"
echo "  Total: $((PASS_COUNT + FAIL_COUNT)) checks"
echo "  Passed: ${PASS_COUNT}"
echo "  Failed: ${FAIL_COUNT}"
echo "==========================================="

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo ""
    echo "RESULT: FAIL"
    exit 1
else
    echo ""
    echo "RESULT: PASS -- all checks passed"
    exit 0
fi
