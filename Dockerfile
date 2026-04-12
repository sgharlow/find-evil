FROM python:3.12-slim

LABEL maintainer="Steve Harlow <sgharlow@gmail.com>"
LABEL description="Evidence Integrity Enforcer — DFIR MCP Server for SIFT Workstation"

WORKDIR /app

# Install system dependencies for SIFT tools (when adding real tool support)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY src/ src/
COPY CLAUDE.md .
COPY README.md .
COPY LICENSE .

# Install the package
RUN pip install --no-cache-dir -e ".[dev]"

# Create evidence mount point
RUN mkdir -p /evidence /output

# Environment defaults
ENV EVIDENCE_DIR=/evidence
ENV AUDIT_LOG_PATH=/output/audit_trail.jsonl
ENV HASH_CHECK_INTERVAL=30

# MCP server uses stdio transport — no port needed
# The entrypoint runs the server; Claude Code connects via stdin/stdout
ENTRYPOINT ["python", "-m", "find_evil"]
