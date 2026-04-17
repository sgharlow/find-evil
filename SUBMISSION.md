# FIND EVIL! — SANS Hackathon Submission Index

> **Hackathon window:** Apr 15 – Jun 15, 2026 · **Project:** Evidence Integrity Enforcer · **License:** MIT

Root-level pointer for judges. Detailed answers to the 8 SANS submission questions live in [`docs/sans-submission-answers.md`](./docs/sans-submission-answers.md).

## What It Is

A purpose-built MCP server that wraps SIFT Workstation forensic tools as typed, read-only operations with **architecturally-enforced evidence integrity**. Every tool call is logged to an immutable JSONL audit trail with a UUID, and every finding links back to the tool invocations that produced it.

The server ships with 15 forensic tools, a 7-phase investigation protocol, a DRS (Decision-Relevance Scoring) confidence gate, and STIX 2.1 export for interop with threat intelligence platforms.

## 8 SANS Deliverables — Where to Find Each

| # | Deliverable | Where |
|---|---|---|
| 1 | Project description + value proposition | [`README.md`](./README.md) (top), [`docs/sans-submission-answers.md`](./docs/sans-submission-answers.md) |
| 2 | Architecture diagram | [`README.md`](./README.md) lines 23-100 (ASCII) |
| 3 | Tool inventory (15 tools, MITRE coverage) | [`README.md`](./README.md) MITRE ATT&CK Coverage + Judging Criteria Map |
| 4 | Test strategy + results (541 tests) | [`README.md`](./README.md) Test Suite section + `pytest --collect-only` |
| 5 | Demo scripts | [`demo/run_investigation.py`](./demo/run_investigation.py), [`demo/tamper_demo.py`](./demo/tamper_demo.py), [`demo/VIDEO_SCRIPT.md`](./demo/VIDEO_SCRIPT.md) |
| 6 | STIX 2.1 export format | [`README.md`](./README.md) STIX 2.1 Export Format section (sample indicator) |
| 7 | Try-it-out guide | [`docs/try_it_out.md`](./docs/try_it_out.md) |
| 8 | Accuracy / DRS methodology | [`docs/accuracy_report.md`](./docs/accuracy_report.md) |

## Run Locally

```bash
# Pip path
pip install -e ".[dev]"
python -m find_evil.server

# Docker path (SIFT Workstation image)
docker compose -f docker-compose.sift.yml up
```

Full setup in [`docs/guides/docker-sift-setup.md`](./docs/guides/docker-sift-setup.md). Runtime env vars in [`.env.example`](./.env.example).

## Tests

- **541 automated tests**, all passing (`pytest`).
- Breakdown in [`README.md`](./README.md) Test Suite section.
- CI: [`.github/workflows/`](./.github/workflows/).

## License

MIT — see [`LICENSE`](./LICENSE).
