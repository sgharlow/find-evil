# Evidence Integrity Enforcer — Makefile
#
# Quick-start targets for development, testing, and demo.

.PHONY: install test demo lint clean docker docker-test

# Install in editable mode with dev dependencies
install:
	pip install -e ".[dev]"

# Run the full test suite
test:
	python -m pytest tests/ -v

# Run the tamper detection demo
demo:
	python demo/tamper_demo.py

# Run the MCP server (stdio transport)
run:
	python -m find_evil

# Run with auto-sealed evidence directory
run-evidence:
	EVIDENCE_DIR=./evidence python -m find_evil

# Verify all tools are registered and no destructive tools exist
verify:
	python -c "\
from find_evil.server import mcp; \
tools = mcp._tool_manager.list_tools(); \
names = {t.name for t in tools}; \
print(f'{len(tools)} tools registered:'); \
[print(f'  {t.name}') for t in tools]; \
bad = names & {'execute_shell_cmd','write_file','rm','dd','shell','bash'}; \
assert not bad, f'SECURITY VIOLATION: destructive tools found: {bad}'; \
print('Security check: PASSED — no destructive tools'); \
"

# Build Docker image
docker:
	docker-compose build

# Run tests in Docker
docker-test:
	docker-compose run mcp-server pytest tests/ -v

# Run demo in Docker
docker-demo:
	docker-compose run mcp-server python demo/tamper_demo.py

# Clean build artifacts
clean:
	rm -rf __pycache__ .pytest_cache src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
