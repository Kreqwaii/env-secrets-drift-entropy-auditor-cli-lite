# env-secrets-drift-entropy-auditor-cli-lite

Zero-dependency Python 3.9+ CLI tool that audits `.env` files across environments (`dev`, `staging`, `prod`) for:
- **Secret leaks**: AWS keys, Stripe keys, GitHub tokens, JWTs, PEM private keys, DB URLs with embedded credentials, and high-entropy generic strings (with safe redacted output).
- **Cross-environment drift**: missing keys, empty values, and malformed/duplicate `.env` entries.
- **Unsafe production flags**: `DEBUG=true`, `NODE_ENV=development`, `ALLOW_ALL_CORS=true`, `SSL_VERIFY=false`, `LOG_LEVEL=debug`.
- **Safe `.env.example` generation**: strips all real values and emits `<CHANGE_ME>` placeholders.

## Installation

No external packages required — 100% Python 3.9+ standard library.

```bash
git clone https://github.com/Kreqwaii/env-secrets-drift-entropy-auditor-cli-lite.git
cd env-secrets-drift-entropy-auditor-cli-lite
```

## Usage

Audit multiple environments:

```bash
python -m env_drift_auditor audit dev=examples/.env.dev staging=examples/.env.staging prod=examples/.env.prod
```

Output JSON for CI pipelines:

```bash
python -m env_drift_auditor audit dev=examples/.env.dev prod=examples/.env.prod --format json
```

Generate a safe `.env.example` template:

```bash
python -m env_drift_auditor template examples/.env.dev examples/.env.prod --output .env.example
```

## Sample Diff & Audit Output

```markdown
# Env Drift & Secrets Audit: `SECRET_LEAKS_DETECTED`

- **Exit Code**: `2`
- **Environments**: dev, staging, prod
- **Total Unique Keys**: 7

## Secret & High-Entropy Findings (4)
| Env | Key | Reason | Entropy | Redacted |
| --- | --- | --- | --- | --- |
| dev | `DATABASE_URL` | `pattern:db_url_with_creds` | 4.65 | `post****_dev` |
| prod | `AWS_ACCESS_KEY_ID` | `pattern:aws_access_key` | 3.72 | `AKIA****2345` |
| prod | `GITHUB_TOKEN` | `pattern:github_token` | 2.66 | `ghp_****0000` |

## Missing Keys by Environment
- **staging**: `AWS_ACCESS_KEY_ID`, `FEATURE_EXPORT`, `GITHUB_TOKEN`
- **prod**: `DATABASE_URL`, `FEATURE_EXPORT`, `STRIPE_KEY`

## Unsafe Production Flags
- **prod**: `DEBUG=true`
```

## CI Exit-Code Table

| Exit Code | Status | Meaning |
| --- | --- | --- |
| `0` | `CLEAN` | No secret leaks, no drift, no unsafe prod flags |
| `1` | `DRIFT_WARNINGS` | Missing/empty keys, parse warnings, or unsafe prod flags |
| `2` | `SECRET_LEAKS_DETECTED` | Known secret pattern or high-entropy token detected |

## Running Tests

```bash
py -m unittest discover -s tests -v
```

---

## Need Self-Hosted Web Studio UI, Historical Baseline SQLite Diffs & Multi-Repo Config Guard?

For teams needing a **Self-Hosted Web Studio UI**, **Historical Baseline SQLite Diffs**, **Multi-Repo Config Guard**, and custom CI/CD policy packs, reach out directly:

👉 **[https://funpay.com/users/20096179/](https://funpay.com/users/20096179/)**
