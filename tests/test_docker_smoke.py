"""Docker smoke tests — fast file-level validation.

Verifies Docker configuration files exist, are well-formed, and reference
the correct services, Python version, and project structure. These tests
do NOT start Docker (no daemon required) — they parse the files directly.

The companion script ``scripts/docker-smoke-test.sh`` performs the full
end-to-end Docker build + run verification.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parent.parent
DOCKERFILE = PROJECT_ROOT / "Dockerfile"
DOCKERFILE_SIFT = PROJECT_ROOT / "Dockerfile.sift"
COMPOSE_FILE = PROJECT_ROOT / "docker-compose.yml"
COMPOSE_SIFT_FILE = PROJECT_ROOT / "docker-compose.sift.yml"
SMOKE_SCRIPT = PROJECT_ROOT / "scripts" / "docker-smoke-test.sh"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read(path: Path) -> str:
    """Read a text file."""
    return path.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# 1. File existence
# ---------------------------------------------------------------------------

class TestDockerFilesExist:
    """All Docker-related files must be present in the repository."""

    def test_dockerfile_exists(self):
        assert DOCKERFILE.exists(), "Dockerfile must exist"

    def test_dockerfile_sift_exists(self):
        assert DOCKERFILE_SIFT.exists(), "Dockerfile.sift must exist"

    def test_docker_compose_exists(self):
        assert COMPOSE_FILE.exists(), "docker-compose.yml must exist"

    def test_docker_compose_sift_exists(self):
        assert COMPOSE_SIFT_FILE.exists(), "docker-compose.sift.yml must exist"

    def test_smoke_test_script_exists(self):
        assert SMOKE_SCRIPT.exists(), "scripts/docker-smoke-test.sh must exist"


# ---------------------------------------------------------------------------
# 2. Dockerfile content validation
# ---------------------------------------------------------------------------

class TestDockerfileContent:
    """Validate the dev Dockerfile is correct."""

    def test_uses_python_312(self):
        """Dockerfile must use Python 3.12."""
        content = _read(DOCKERFILE)
        assert "python:3.12" in content, "Dockerfile must use python:3.12 base image"

    def test_workdir_is_app(self):
        content = _read(DOCKERFILE)
        assert "WORKDIR /app" in content

    def test_installs_package(self):
        content = _read(DOCKERFILE)
        assert "pip install" in content

    def test_creates_evidence_directory(self):
        content = _read(DOCKERFILE)
        assert "/evidence" in content

    def test_creates_output_directory(self):
        content = _read(DOCKERFILE)
        assert "/output" in content

    def test_sets_evidence_dir_env(self):
        content = _read(DOCKERFILE)
        assert "EVIDENCE_DIR" in content

    def test_entrypoint_runs_find_evil(self):
        content = _read(DOCKERFILE)
        assert "find_evil" in content

    def test_copies_source_code(self):
        content = _read(DOCKERFILE)
        assert "COPY src/ src/" in content

    def test_copies_pyproject(self):
        content = _read(DOCKERFILE)
        assert "COPY pyproject.toml" in content


# ---------------------------------------------------------------------------
# 3. Dockerfile.sift content validation
# ---------------------------------------------------------------------------

class TestDockerfileSiftContent:
    """Validate the SIFT Dockerfile has forensic tool dependencies."""

    def test_uses_python_312(self):
        content = _read(DOCKERFILE_SIFT)
        assert "python:3.12" in content

    def test_installs_sift_extras(self):
        """SIFT Dockerfile must install the [sift] extras."""
        content = _read(DOCKERFILE_SIFT)
        assert "[sift" in content, "Must install [sift] extras for forensic tools"

    def test_installs_yara(self):
        content = _read(DOCKERFILE_SIFT)
        assert "yara" in content.lower()

    def test_installs_libffi(self):
        content = _read(DOCKERFILE_SIFT)
        assert "libffi" in content

    def test_copies_tests(self):
        """SIFT image should include tests for in-container execution."""
        content = _read(DOCKERFILE_SIFT)
        assert "COPY tests/" in content

    def test_copies_demo(self):
        """SIFT image should include demo scripts."""
        content = _read(DOCKERFILE_SIFT)
        assert "COPY demo/" in content

    def test_verifies_tool_installation(self):
        """SIFT Dockerfile should verify tools install correctly."""
        content = _read(DOCKERFILE_SIFT)
        assert "import Evtx" in content or "import evtx" in content
        assert "import yara" in content
        assert "import volatility3" in content


# ---------------------------------------------------------------------------
# 4. docker-compose.yml validation
# ---------------------------------------------------------------------------

class TestComposeFile:
    """Validate docker-compose.yml defines the expected services."""

    def test_defines_mcp_server_service(self):
        content = _read(COMPOSE_FILE)
        assert "mcp-server:" in content, "Must define mcp-server service"

    def test_mcp_server_has_stdin_open(self):
        """MCP uses stdio transport, so stdin must be open."""
        content = _read(COMPOSE_FILE)
        assert "stdin_open: true" in content

    def test_mounts_evidence_read_only(self):
        """Evidence must be mounted read-only for forensic integrity."""
        content = _read(COMPOSE_FILE)
        assert ":ro" in content, "Evidence volume must be read-only"

    def test_mounts_output_directory(self):
        content = _read(COMPOSE_FILE)
        assert "/output" in content

    def test_mounts_tests_directory(self):
        content = _read(COMPOSE_FILE)
        assert "/app/tests" in content

    def test_sets_environment_variables(self):
        content = _read(COMPOSE_FILE)
        assert "EVIDENCE_DIR" in content
        assert "AUDIT_LOG_PATH" in content

    def test_no_privileged_mode(self):
        """Container should NOT run in privileged mode."""
        content = _read(COMPOSE_FILE)
        assert "privileged: true" not in content


# ---------------------------------------------------------------------------
# 5. docker-compose.sift.yml validation
# ---------------------------------------------------------------------------

class TestComposeSiftFile:
    """Validate docker-compose.sift.yml."""

    def test_defines_mcp_server_service(self):
        content = _read(COMPOSE_SIFT_FILE)
        assert "mcp-server:" in content

    def test_references_sift_dockerfile(self):
        content = _read(COMPOSE_SIFT_FILE)
        assert "Dockerfile.sift" in content

    def test_mounts_fixtures(self):
        """SIFT compose should mount test fixtures for real evidence parsing."""
        content = _read(COMPOSE_SIFT_FILE)
        assert "fixtures" in content

    def test_has_stdin_open(self):
        content = _read(COMPOSE_SIFT_FILE)
        assert "stdin_open: true" in content

    def test_evidence_is_read_only(self):
        content = _read(COMPOSE_SIFT_FILE)
        assert ":ro" in content


# ---------------------------------------------------------------------------
# 6. Smoke test script validation
# ---------------------------------------------------------------------------

class TestSmokeTestScript:
    """Validate the smoke test script itself is well-formed."""

    def test_has_bash_shebang(self):
        content = _read(SMOKE_SCRIPT)
        assert content.startswith("#!/usr/bin/env bash"), "Must use #!/usr/bin/env bash shebang"

    def test_has_set_euo_pipefail(self):
        content = _read(SMOKE_SCRIPT)
        assert "set -euo pipefail" in content

    def test_has_cleanup_trap(self):
        content = _read(SMOKE_SCRIPT)
        assert "trap" in content and "cleanup" in content

    def test_runs_docker_compose_down_in_cleanup(self):
        content = _read(SMOKE_SCRIPT)
        assert "down" in content, "Cleanup should run docker-compose down"

    def test_checks_tool_count(self):
        content = _read(SMOKE_SCRIPT)
        assert "EXPECTED_TOOL_COUNT=15" in content

    def test_checks_for_destructive_tools(self):
        content = _read(SMOKE_SCRIPT)
        assert "execute_shell_cmd" in content or "SECURITY" in content

    def test_runs_pytest(self):
        content = _read(SMOKE_SCRIPT)
        assert "pytest" in content

    def test_supports_sift_flag(self):
        content = _read(SMOKE_SCRIPT)
        assert "--sift" in content

    def test_exits_with_failure_code(self):
        content = _read(SMOKE_SCRIPT)
        assert "exit 1" in content

    def test_exits_with_success_code(self):
        content = _read(SMOKE_SCRIPT)
        assert "exit 0" in content

    def test_prints_summary(self):
        content = _read(SMOKE_SCRIPT)
        assert "SUMMARY" in content
