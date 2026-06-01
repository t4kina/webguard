# webguard 🔐

Lightweight CLI security scanner that combines **Trivy** and **OWASP ZAP** to audit web projects before going live.

```bash
python security_report.py --url https://staging.my-app.com --path ./my-project
```

![Python](https://img.shields.io/badge/python-3.10+-blue) ![Docker](https://img.shields.io/badge/docker-required-blue) ![License](https://img.shields.io/badge/license-MIT-green)

---

## What it does

webguard runs two scanners in sequence and produces a unified security report with a 0–100 score and a clear production verdict.

**🔍 Trivy — local project**
Scans your codebase for CVEs in dependencies (npm, pip, go, maven, composer…), exposed secrets (API keys, tokens, hardcoded credentials) and misconfigurations in Dockerfile, docker-compose, Terraform and Kubernetes files.

**🕷️ OWASP ZAP — staging URL**
Runs a passive baseline scan against your staging environment, detecting missing security headers (CSP, X-Frame-Options, HSTS…), cookies without `HttpOnly` / `Secure` / `SameSite` flags, and passive vulnerabilities like reflected XSS and info leakage.

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| Python ≥ 3.10 | |
| Docker | Required for ZAP; also used as Trivy fallback |
| `trivy` binary | Optional — Docker is used if not installed |

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Full scan — local project + staging
python security_report.py --url https://staging.my-app.com --path ./my-project

# With Basic Auth (nginx/apache level)
python security_report.py --url https://staging.my-app.com --auth user:password --skip-trivy

# Scan a Docker image instead of a local folder
python security_report.py --url https://staging.my-app.com --trivy-image my-app:latest

# Local test environment (containers on the same Docker network)
python security_report.py --url http://dvwa:80 --network security-scan --trivy-image vulnerables/web-dvwa

# Show all findings including MEDIUM, LOW and INFO
python security_report.py --url https://staging.my-app.com --path . --all
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--url` | Target URL for ZAP scan (**required**) | — |
| `--path` | Local project path for Trivy filesystem scan | `.` |
| `--trivy-image` | Scan a Docker image instead of a local folder | — |
| `--auth` | Basic Auth credentials (`user:password`) | — |
| `--network` | Docker network name (to reach containers by name) | — |
| `--all` | Show all findings including MEDIUM, LOW and INFO | false |
| `--skip-trivy` | Skip Trivy scan | false |
| `--skip-zap` | Skip ZAP scan | false |

---

## Scoring

Starts at 100 and deducts points per finding. By default only CRITICAL and HIGH findings are shown — use `--all` to see everything.

| Score | Verdict |
|-------|---------|
| 80–100 | ✅ Ready for production |
| 60–79 | ⚠️ Review before publishing |
| 40–59 | 🚨 Not recommended |
| 0–39 | 🛑 Blocked — critical risk |

Penalty per finding: **CRITICAL −25 · HIGH −10 · MEDIUM −4 · LOW −1**

---

## Local test environment

A `docker-compose.yml` is included to spin up [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web Application) for testing the scanner locally.

```bash
# Start DVWA
docker compose up -d

# Open http://localhost:8080 → login admin/password → click "Create / Reset Database"

# Run the scanner against it
python security_report.py --url http://dvwa:80 --network security-scan --trivy-image vulnerables/web-dvwa

# Tear down
docker compose down
```

---

## Docker images used

```
aquasec/trivy:latest              # Trivy fallback if binary not installed
ghcr.io/zaproxy/zaproxy:stable    # OWASP ZAP
```

Both are pulled automatically on first use.
