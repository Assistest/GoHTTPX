# Public Release Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the server-side 60-second control-response cutoff and add the minimum automation and documentation needed for a public GitHub release.

**Architecture:** The Go target-request context remains the only target timeout authority, capped at 600 seconds by the v1 protocol. The control HTTP server disables its global write deadline so it cannot sever a valid long-running target request. GitHub Actions repeats the existing Windows release gate; release and operation documents describe the already-supported manual deployment model.

**Tech Stack:** Go 1.25, Python 3.10, HTTPX 0.28, GitHub Actions on Windows.

## Global Constraints

- Keep the service loopback-only by default; do not turn it into a public network proxy.
- Preserve v1 JSON envelopes and the Python/Go responsibility boundary.
- Do not add runtime logging or new production dependencies.
- Keep the server and Python SDK at version 1.0.0.
- Do not add a LICENSE until the repository owner selects its legal terms.

---

### Task 1: Remove the conflicting control write deadline

**Files:**
- Create: `main_test.go`
- Modify: `main.go:16-25`, `main.go:79-86`

**Interfaces:**
- Produces: `controlWriteTimeout time.Duration`, used by the `http.Server` created in `main`.
- Preserves: request-level `timeout_ms` validation in `api.go` (`0..600000`).

- [ ] **Step 1: Write the failing test**

```go
func TestControlWriteTimeoutDoesNotCapTargetRequestDuration(t *testing.T) {
	if controlWriteTimeout != 0 {
		t.Fatalf("control WriteTimeout=%s; valid target requests may run for up to 10m", controlWriteTimeout)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestControlWriteTimeoutDoesNotCapTargetRequestDuration -count=1`

Expected: FAIL because `controlWriteTimeout` is not defined.

- [ ] **Step 3: Write minimal implementation**

```go
const controlWriteTimeout time.Duration = 0

// In main's http.Server literal:
WriteTimeout: controlWriteTimeout,
```

`0` is the documented `net/http` value for no global write deadline; the request context retains the protocol timeout.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestControlWriteTimeoutDoesNotCapTargetRequestDuration -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```text
git add main.go main_test.go
git commit -m "fix: 移除控制连接写超时上限"
```

### Task 2: Automate the existing Windows release gate

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: Go 1.25 module and Python `unittest` suite.
- Produces: a GitHub Actions workflow for pushes and pull requests.

- [ ] **Step 1: Create the workflow**

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v6
        with:
          go-version: '1.25.x'
      - uses: actions/setup-python@v5
        with:
          python-version: '3.10'
      - run: python -m pip install 'httpx>=0.28,<0.29'
      - run: go test ./... -count=1
      - run: go test -race ./... -count=1
      - run: go vet ./...
      - run: python -B -m unittest discover -s python -p "test_*.py" -v
```

- [ ] **Step 2: Validate workflow syntax locally**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml', encoding='utf-8'))"`

Expected: exit 0. If PyYAML is unavailable, inspect the YAML with the repository's supported tooling rather than adding a dependency.

- [ ] **Step 3: Commit**

```text
git add .github/workflows/ci.yml
git commit -m "ci: 添加 Windows 发布门禁"
```

### Task 3: Document the release and manual operation contract

**Files:**
- Create: `CHANGELOG.md`, `RUNBOOK.md`
- Modify: `README.md:19-58`, `PROJECT_CONTEXT.md:370-395`

**Interfaces:**
- Consumes: the existing build command, version endpoint, health endpoint, token requirements, and loopback deployment model.
- Produces: a public change summary and a short operator procedure. Exact binary metadata belongs in the GitHub Release created from a clean revision, avoiding a self-referential tracked checksum.

- [ ] **Step 1: Add a change summary**

Include the `1.0.0` public-release scope and the write-timeout correction. Direct each published binary's revision, size, and SHA-256 to its GitHub Release.

- [ ] **Step 2: Add a runbook**

Document only the current manual process: generate/store a token, start on `127.0.0.1`, probe health/capabilities, use Ctrl+C for graceful shutdown, upgrade Go EXE and Python SDK together, and prohibit `--allow-non-loopback` outside a network-isolated environment.

- [ ] **Step 3: Link the documents from README and project context**

Add concise links; do not duplicate the runbook's content.

- [ ] **Step 4: Verify documentation references**

Run: `python -c "from pathlib import Path; assert Path('CHANGELOG.md').is_file(); assert Path('RUNBOOK.md').is_file()"`

Expected: exit 0.

- [ ] **Step 5: Commit**

```text
git add README.md PROJECT_CONTEXT.md CHANGELOG.md RUNBOOK.md
git commit -m "docs: 补充公开发布与运维说明"
```

### Task 4: Execute the release verification gate

**Files:**
- Verify only: repository root

- [ ] **Step 1: Run all release checks**

```text
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
python -B -m unittest discover -s python -p "test_*.py" -v
go build -trimpath -ldflags="-s -w" -o gohttpx-server.exe .
go version -m gohttpx-server.exe
gohttpx-server.exe --version
```

- [ ] **Step 2: Verify repository state**

Run: `git status --short --branch`

Expected: the build artifact is ignored and only intentional uncommitted release metadata, if any, remains.
